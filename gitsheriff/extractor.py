"""
GitSheriff - .git repository recovery module.

Recovers source files from dumped .git directories by traversing
all commits, trees, and blobs. Mirrors DotGit's extractor.sh behavior:
iterates ALL objects in .git/objects/, identifies commits, traverses
each commit, and outputs files into numbered folders per commit.
"""

import os
import sys
import subprocess
import time
from collections import defaultdict

from .utils import (
    Colors, print_info, print_success, print_warning, print_error,
    print_section, ProgressBar, safe_makedirs,
)


def _run_git(args, git_dir, capture=True):
    """Run a git command and return the output.

    Args:
        args: List of git command arguments.
        git_dir: Path to the .git directory.
        capture: Whether to capture stdout.

    Returns:
        String output of the command, or None on failure.
    """
    env = os.environ.copy()
    env["GIT_DIR"] = git_dir
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["LC_ALL"] = "C"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["HOME"] = os.devnull

    try:
        result = subprocess.run(
            ["git"] + args,
            env=env,
            capture_output=capture,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except FileNotFoundError:
        print_error("Git is not installed or not in PATH.")
        print_info("Install git: https://git-scm.com/downloads")
        return None
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def _get_object_type(git_dir, sha1):
    """Get the type of a git object (commit, tree, blob, tag).

    Returns:
        String type name, or None on failure.
    """
    output = _run_git(["cat-file", "-t", sha1], git_dir)
    if output:
        return output.strip()
    return None


def _get_object_content(git_dir, sha1):
    """Get the content of a git object.

    Returns:
        String content, or None on failure.
    """
    return _run_git(["cat-file", "-p", sha1], git_dir)


def _get_tree_entries(git_dir, sha1):
    """Get entries in a tree object.

    Returns:
        List of (mode, type, hash, name) tuples, or empty list.
    """
    content = _get_object_content(git_dir, sha1)
    if not content:
        return []

    entries = []
    for line in content.strip().splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2:
            meta = parts[0].split(" ", 2)
            if len(meta) == 3:
                entries.append((meta[0], meta[1], meta[2], parts[1]))
    return entries


def _resolve_commit_tree(git_dir, commit_hash):
    """Get the tree hash for a commit.

    Returns:
        Tree hash string, or None on failure.
    """
    content = _get_object_content(git_dir, commit_hash)
    if not content:
        return None
    for line in content.splitlines():
        if line.startswith("tree "):
            return line.split(" ", 1)[1].strip()
    return None


def _traverse_tree(git_dir, tree_hash, path_prefix=""):
    """Recursively traverse a tree and yield (mode, hash, filepath) for all blobs.

    Yields:
        Tuple of (mode, blob_hash, relative_filepath).
    """
    entries = _get_tree_entries(git_dir, tree_hash)
    for mode, obj_type, obj_hash, name in entries:
        full_path = os.path.join(path_prefix, name) if path_prefix else name
        if obj_type == "blob":
            yield (mode, obj_hash, full_path)
        elif obj_type == "tree":
            yield from _traverse_tree(git_dir, obj_hash, full_path)


def _write_blob(git_dir, blob_hash, output_path):
    """Write a blob object to a file.

    Returns:
        True on success, False on failure.
    """
    content = _get_object_content(git_dir, blob_hash)
    if content is None:
        return False
    try:
        dir_name = os.path.dirname(output_path)
        if dir_name:
            safe_makedirs(dir_name)
        with open(output_path, "wb") as f:
            f.write(content.encode("utf-8", errors="replace"))
        return True
    except Exception:
        return False


def _get_commit_info(git_dir, commit_hash):
    """Get commit metadata (author, date, message).

    Returns:
        Dict with keys: hash, author, date, message, parents.
    """
    content = _get_object_content(git_dir, commit_hash)
    if not content:
        return None

    info = {
        "hash": commit_hash,
        "author": "",
        "date": "",
        "message": "",
        "parents": [],
    }

    lines = content.splitlines()
    message_started = False
    message_lines = []

    for line in lines:
        if line.startswith("author "):
            info["author"] = line[7:]
        elif line.startswith("committer "):
            # Extract date from committer line
            parts = line.split(">", 1)
            if len(parts) > 1:
                date_part = parts[1].strip()
                info["date"] = date_part.split(" ")[0] if date_part else ""
        elif line.startswith("parent "):
            info["parents"].append(line.split(" ", 1)[1].strip())
        elif message_started:
            message_lines.append(line)
        elif line == "":
            message_started = True

    info["message"] = "\n".join(message_lines).strip()
    return info


class GitExtractor:
    """Recovers source files from a dumped .git directory.

    Mirrors DotGit's extractor.sh behavior:
    - Iterates ALL files in .git/objects/
    - Identifies all commit objects
    - Traverses each commit's tree
    - Outputs files into numbered folders: <N>-<commit_hash>/
    """

    def __init__(self, git_dir, output_dir=None, keep_unreachable=False):
        """
        Args:
            git_dir: Path to the .git directory.
            output_dir: Directory to write recovered files. Defaults to 'recovered'.
            keep_unreachable: Include unreachable objects.
        """
        self.git_dir = os.path.abspath(git_dir)
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(self.git_dir), "recovered"
        )
        self.keep_unreachable = keep_unreachable

        # Tracking
        self.commits_found = []
        self.files_recovered = 0
        self.errors = []

    def _find_all_objects(self):
        """Iterate ALL files in .git/objects/ and find all object hashes.

        Mirrors DotGit's extractor.sh approach:
        for file in $(find .git/objects/ -type f -not -name pack-*); do
            hash = <2-char-prefix>/<rest-of-filename>

        Returns:
            List of 40-character hex hashes.
        """
        objects_dir = os.path.join(self.git_dir, "objects")
        hashes = []

        if not os.path.isdir(objects_dir):
            return hashes

        for prefix_dir in sorted(os.listdir(objects_dir)):
            prefix_path = os.path.join(objects_dir, prefix_dir)
            if not os.path.isdir(prefix_path):
                continue
            if len(prefix_dir) != 2:
                continue

            for obj_file in sorted(os.listdir(prefix_path)):
                # Skip pack directories and other non-object entries
                if len(obj_file) != 38:
                    continue
                obj_hash = prefix_dir + obj_file
                if all(c in "0123456789abcdef" for c in obj_hash):
                    hashes.append(obj_hash)

        return hashes

    def _find_all_commits(self):
        """Find all commit objects by iterating ALL objects.

        Mirrors DotGit's extractor.sh:
        hash=<prefix>/<rest>
        if git cat-file -t $hash >/dev/null 2>&1; then
            type=$(git cat-file -t $hash)
            if [ "$type" = "commit" ]; then
                traverse_commit $hash

        Returns:
            List of commit info dicts.
        """
        print_info("Scanning all objects for commits...")
        all_objects = self._find_all_objects()
        print_info(f"Found {len(all_objects)} object(s) in .git/objects/")

        commits = []
        progress = ProgressBar(len(all_objects), desc="Objects")

        for obj_hash in all_objects:
            obj_type = _get_object_type(self.git_dir, obj_hash)
            if obj_type == "commit":
                info = _get_commit_info(self.git_dir, obj_hash)
                if info:
                    commits.append(info)
            progress.update()

        progress.finish()
        return commits

    def _find_commits_via_refs(self):
        """Find commits by following all refs and packed-refs.

        Fallback method when .git/objects/ might be incomplete.

        Returns:
            List of commit hashes.
        """
        commits = set()

        # Try common branch refs
        for ref_path in [
            "refs/heads/master", "refs/heads/main", "refs/heads/develop",
            "refs/heads/dev", "refs/heads/HEAD",
            "refs/remotes/origin/HEAD", "refs/remotes/origin/master",
            "refs/remotes/origin/main",
        ]:
            full = os.path.join(self.git_dir, ref_path)
            if os.path.exists(full):
                with open(full, "r", errors="replace") as f:
                    sha = f.read().strip()
                    if len(sha) == 40:
                        commits.add(sha)

        # Try HEAD
        head_file = os.path.join(self.git_dir, "HEAD")
        if os.path.exists(head_file):
            with open(head_file, "r", errors="replace") as f:
                content = f.read().strip()
                if content.startswith("ref: "):
                    ref_name = content[5:]
                    ref_file = os.path.join(self.git_dir, ref_name)
                    if os.path.exists(ref_file):
                        with open(ref_file, "r", errors="replace") as rf:
                            sha = rf.read().strip()
                            if len(sha) == 40:
                                commits.add(sha)
                elif len(content) == 40:
                    commits.add(content)

        # Try packed-refs
        packed = os.path.join(self.git_dir, "packed-refs")
        if os.path.exists(packed):
            with open(packed, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if len(parts) >= 2 and len(parts[0]) == 40:
                            commits.add(parts[0])

        return list(commits)

    def _recover_commit(self, commit_info, index):
        """Recover all files from a single commit.

        Creates output directory: <N>-<commit_hash>/

        Args:
            commit_info: Dict with hash, author, date, message, parents.
            index: Numeric index for the output folder.

        Returns:
            Number of files recovered.
        """
        commit_hash = commit_info["hash"][:12]
        folder_name = f"{index}-{commit_hash}"
        commit_dir = os.path.join(self.output_dir, folder_name)

        safe_makedirs(commit_dir)

        # Get the tree for this commit
        tree_hash = _resolve_commit_tree(self.git_dir, commit_info["hash"])
        if not tree_hash:
            print_warning(f"  Could not resolve tree for {commit_hash}")
            return 0

        # Write commit metadata
        meta_path = os.path.join(commit_dir, ".commit_info.txt")
        try:
            with open(meta_path, "w", encoding="utf-8", errors="replace") as f:
                f.write(f"Hash: {commit_info['hash']}\n")
                f.write(f"Author: {commit_info['author']}\n")
                f.write(f"Date: {commit_info['date']}\n")
                f.write(f"Message: {commit_info['message']}\n")
                f.write(f"Parents: {', '.join(commit_info['parents'])}\n")
        except Exception:
            pass

        # Traverse the tree and write files
        count = 0
        for mode, blob_hash, rel_path in _traverse_tree(self.git_dir, tree_hash):
            out_path = os.path.join(commit_dir, rel_path)
            if _write_blob(self.git_dir, blob_hash, out_path):
                count += 1
                # Set executable permission if needed
                if mode and mode.startswith("100755"):
                    try:
                        os.chmod(out_path, 0o755)
                    except Exception:
                        pass

        return count

    def extract(self):
        """Execute full extraction from a dumped .git directory.

        Mirrors DotGit's extractor.sh workflow:
        1. Find ALL objects in .git/objects/
        2. Identify ALL commit objects
        3. For each commit, traverse its tree
        4. Output files into <N>-<commit_hash>/ folders

        Returns:
            Tuple of (success_bool, output_dir_string).
        """
        print_section("Git Repository Recovery")
        print_info(f"Git directory: {self.git_dir}")
        print_info(f"Output: {self.output_dir}")
        print()

        if not os.path.isdir(self.git_dir):
            print_error(f"Git directory not found: {self.git_dir}")
            return False, self.output_dir

        start_time = time.time()

        try:
            safe_makedirs(self.output_dir)

            # Step 1: Find all commits via objects scan (primary method)
            self.commits_found = self._find_all_commits()

            # Step 2: Fallback - find commits via refs if no commits found via objects
            if not self.commits_found:
                print_info("No commits found via objects, trying refs...")
                ref_hashes = self._find_commits_via_refs()
                for h in ref_hashes:
                    info = _get_commit_info(self.git_dir, h)
                    if info:
                        self.commits_found.append(info)

            if not self.commits_found:
                print_warning("No commits found.")
                print_info("Trying to recover files from HEAD...")
                head_file = os.path.join(self.git_dir, "HEAD")
                if os.path.exists(head_file):
                    with open(head_file, "r", errors="replace") as f:
                        head_content = f.read().strip()
                    print_info(f"HEAD points to: {head_content}")
                return True, self.output_dir

            print_success(f"Found {len(self.commits_found)} commit(s)")
            print()

            # Step 3: Recover each commit
            total_files = 0
            for i, commit_info in enumerate(self.commits_found, 1):
                hash_short = commit_info["hash"][:12]
                msg_preview = commit_info["message"][:60] if commit_info["message"] else "(no message)"
                print_info(
                    f"Commit {i}/{len(self.commits_found)}: "
                    f"{hash_short} - {msg_preview}"
                )

                files = self._recover_commit(commit_info, i)
                total_files += files
                print_success(f"  Recovered {files} file(s)")

            self.files_recovered = total_files

            # Summary
            elapsed = time.time() - start_time
            print_section("Recovery Summary")
            print_success(f"Commits processed: {len(self.commits_found)}")
            print_success(f"Total files recovered: {self.files_recovered}")
            print_success(f"Output directory: {self.output_dir}")
            print_success(f"Time elapsed: {elapsed:.1f}s")

            if self.errors:
                print_warning(f"Errors: {len(self.errors)}")

            return True, self.output_dir

        except KeyboardInterrupt:
            print_warning("\nExtraction interrupted by user.")
            return False, self.output_dir
        except Exception as e:
            print_error(f"Extraction failed: {e}")
            return False, self.output_dir
