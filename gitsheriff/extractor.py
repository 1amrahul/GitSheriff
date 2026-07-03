"""
GitSheriff - Git repository extractor/recovers module.

Recovers source code from a dumped .git directory by parsing
commits, trees, and blobs.
"""

import os
import re
import sys
import time
import zlib
import stat
import subprocess
from datetime import datetime

from .utils import (
    Colors, print_info, print_success, print_warning, print_error,
    print_section, ProgressBar, safe_makedirs, safe_write,
)


class GitExtractor:
    """Recovers source code from a dumped .git directory."""

    # Git object types
    OBJ_COMMIT = 1
    OBJ_TREE = 2
    OBJ_BLOB = 3
    OBJ_TAG = 4

    def __init__(self, git_dir, output_dir=None):
        """
        Initialize the GitExtractor.

        Args:
            git_dir: Path to the dumped .git directory.
            output_dir: Directory to extract files to. Defaults to parent of git_dir.
        """
        self.git_dir = os.path.abspath(git_dir)
        self.output_dir = output_dir or os.path.dirname(self.git_dir)
        self.objects = {}
        self.errors = []
        self.extracted_files = 0

    def _get_object_path(self, sha1):
        """Get the file path for a loose git object.

        Args:
            sha1: 40-character hex SHA1 hash.

        Returns:
            Path to the object file, or None if not found.
        """
        prefix = sha1[:2]
        suffix = sha1[2:]
        loose_path = os.path.join(self.git_dir, "objects", prefix, suffix)
        if os.path.exists(loose_path):
            return loose_path
        return None

    def _read_object(self, sha1):
        """Read and decompress a git object.

        Args:
            sha1: 40-character hex SHA1 hash.

        Returns:
            Tuple of (object_type, content_bytes) or (None, None) on failure.
        """
        if sha1 in self.objects:
            return self.objects[sha1]

        obj_path = self._get_object_path(sha1)
        if not obj_path:
            # Try pack files
            return self._read_from_pack(sha1)

        try:
            with open(obj_path, "rb") as f:
                compressed = f.read()

            decompressed = zlib.decompress(compressed)

            # Parse git object header: "type size\0content"
            null_idx = decompressed.index(b"\x00")
            header = decompressed[:null_idx].decode("utf-8")
            content = decompressed[null_idx + 1:]

            obj_type_str = header.split()[0]
            type_map = {
                "commit": self.OBJ_COMMIT,
                "tree": self.OBJ_TREE,
                "blob": self.OBJ_BLOB,
                "tag": self.OBJ_TAG,
            }
            obj_type = type_map.get(obj_type_str, None)

            if obj_type is not None:
                self.objects[sha1] = (obj_type, content)
                return (obj_type, content)

        except zlib.error:
            pass
        except FileNotFoundError:
            pass
        except PermissionError:
            self.errors.append(f"Permission denied: {obj_path}")
        except Exception as e:
            self.errors.append(f"Error reading object {sha1}: {e}")

        return (None, None)

    def _read_from_pack(self, sha1):
        """Try to read an object from pack files.

        Args:
            sha1: 40-character hex SHA1 hash.

        Returns:
            Tuple of (object_type, content_bytes) or (None, None).
        """
        pack_dir = os.path.join(self.git_dir, "objects", "pack")
        if not os.path.exists(pack_dir):
            return (None, None)

        try:
            for fname in os.listdir(pack_dir):
                if fname.endswith(".pack"):
                    pack_path = os.path.join(pack_dir, fname)
                    try:
                        result = self._extract_from_pack(pack_path, sha1)
                        if result[0] is not None:
                            return result
                    except Exception:
                        continue
        except OSError:
            pass

        return (None, None)

    def _extract_from_pack(self, pack_path, sha1):
        """Extract an object from a pack file.

        This is a simplified implementation that handles basic pack files.
        For complex pack files, use git's native tools.

        Args:
            pack_path: Path to the .pack file.
            sha1: 40-character hex SHA1 hash.

        Returns:
            Tuple of (object_type, content_bytes) or (None, None).
        """
        try:
            # Try using git verify-pack to find the object offset
            idx_path = pack_path.replace(".pack", ".idx")
            if not os.path.exists(idx_path):
                return (None, None)

            # Use git cat-file if available
            result = subprocess.run(
                ["git", "cat-file", "-t", sha1],
                capture_output=True,
                text=True,
                cwd=os.path.dirname(self.git_dir),
                timeout=10,
            )

            if result.returncode == 0:
                obj_type_str = result.stdout.strip()
                type_map = {
                    "commit": self.OBJ_COMMIT,
                    "tree": self.OBJ_TREE,
                    "blob": self.OBJ_BLOB,
                    "tag": self.OBJ_TAG,
                }
                obj_type = type_map.get(obj_type_str)
                if obj_type is None:
                    return (None, None)

                result = subprocess.run(
                    ["git", "cat-file", sha1],
                    capture_output=True,
                    cwd=os.path.dirname(self.git_dir),
                    timeout=10,
                )

                if result.returncode == 0:
                    self.objects[sha1] = (obj_type, result.stdout)
                    return (obj_type, result.stdout)

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return (None, None)

    def _parse_tree(self, content):
        """Parse a git tree object.

        Args:
            content: Raw tree content bytes.

        Returns:
            List of (mode, name, sha1) tuples.
        """
        entries = []
        idx = 0
        while idx < len(content):
            try:
                # Parse mode (decimal string followed by space)
                space_idx = content.index(b" ", idx)
                mode = content[idx:space_idx].decode("utf-8")

                # Parse name (null-terminated string)
                idx = space_idx + 1
                null_idx = content.index(b"\x00", idx)
                name = content[idx:null_idx].decode("utf-8")

                # Parse SHA1 (20 bytes binary)
                idx = null_idx + 1
                sha1_binary = content[idx:idx + 20]
                sha1 = sha1_binary.hex()

                entries.append((mode, name, sha1))
                idx = idx + 20

            except (ValueError, UnicodeDecodeError):
                break

        return entries

    def _extract_tree(self, tree_sha1, target_dir, depth=0):
        """Recursively extract a git tree.

        Args:
            tree_sha1: SHA1 of the tree object.
            target_dir: Directory to extract files to.
            depth: Current recursion depth (for protection against infinite loops).
        """
        if depth > 50:
            self.errors.append(f"Max recursion depth exceeded for tree {tree_sha1}")
            return

        obj_type, content = self._read_object(tree_sha1)
        if obj_type != self.OBJ_TREE or content is None:
            return

        entries = self._parse_tree(content)

        for mode, name, sha1 in entries:
            # Sanitize path to prevent directory traversal
            safe_name = os.path.basename(name)
            if safe_name != name:
                self.errors.append(f"Path traversal attempt blocked: {name}")

            entry_path = os.path.join(target_dir, safe_name)

            if mode.startswith("10"):  # Regular file
                obj_type, blob_content = self._read_object(sha1)
                if obj_type == self.OBJ_BLOB and blob_content is not None:
                    try:
                        safe_makedirs(os.path.dirname(entry_path))
                        with open(entry_path, "wb") as f:
                            f.write(blob_content)

                        # Set executable bit if needed
                        if mode in ("100755",):
                            os.chmod(entry_path, os.stat(entry_path).st_mode | stat.S_IEXEC)

                        self.extracted_files += 1
                    except Exception as e:
                        self.errors.append(f"Failed to write {entry_path}: {e}")

            elif mode.startswith("04"):  # Directory
                safe_makedirs(entry_path)
                self._extract_tree(sha1, entry_path, depth + 1)

            elif mode == "120000":  # Symlink
                obj_type, blob_content = self._read_object(sha1)
                if obj_type == self.OBJ_BLOB and blob_content is not None:
                    try:
                        link_target = blob_content.decode("utf-8").strip()
                        if os.path.exists(entry_path):
                            os.remove(entry_path)
                        os.symlink(link_target, entry_path)
                        self.extracted_files += 1
                    except Exception as e:
                        self.errors.append(f"Failed to create symlink {entry_path}: {e}")

    def _get_commit_tree(self, commit_sha1):
        """Extract the tree SHA1 from a commit object.

        Args:
            commit_sha1: SHA1 of the commit object.

        Returns:
            Tree SHA1 string, or None on failure.
        """
        obj_type, content = self._read_object(commit_sha1)
        if obj_type != self.OBJ_COMMIT or content is None:
            return None

        try:
            text = content.decode("utf-8", errors="replace")
            for line in text.split("\n"):
                if line.startswith("tree "):
                    return line.split()[1]
        except Exception:
            pass

        return None

    def _resolve_head(self):
        """Resolve HEAD to a commit SHA1.

        Returns:
            SHA1 of the HEAD commit, or None.
        """
        head_path = os.path.join(self.git_dir, "HEAD")
        if not os.path.exists(head_path):
            return None

        try:
            with open(head_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read().strip()

            if content.startswith("ref:"):
                # Symbolic reference
                ref_path = content.split(" ")[1].strip()
                ref_file = os.path.join(self.git_dir, ref_path)
                if os.path.exists(ref_file):
                    with open(ref_file, "r", encoding="utf-8", errors="replace") as rf:
                        sha = rf.read().strip()
                        if len(sha) == 40:
                            return sha
            elif len(content) == 40:
                # Detached HEAD
                return content

        except Exception as e:
            self.errors.append(f"Failed to resolve HEAD: {e}")

        return None

    def _find_commits_from_refs(self):
        """Find commit SHA1s from all available references.

        Returns:
            List of (ref_name, commit_sha1) tuples.
        """
        commits = []
        refs_dir = os.path.join(self.git_dir, "refs")

        if not os.path.exists(refs_dir):
            return commits

        for root, dirs, files in os.walk(refs_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.git_dir)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        sha = f.read().strip()
                        if len(sha) == 40:
                            commits.append((rel_path, sha))
                except Exception:
                    continue

        # Also check packed-refs
        packed_path = os.path.join(self.git_dir, "packed-refs")
        if os.path.exists(packed_path):
            try:
                with open(packed_path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split()
                            if len(parts) >= 2:
                                sha = parts[0]
                                ref = parts[1]
                                if len(sha) == 40:
                                    commits.append((ref, sha))
            except Exception:
                pass

        return commits

    def extract(self):
        """Execute the full extraction.

        Returns:
            True on success, False on failure.
        """
        print_section("Git Repository Extraction")
        print_info(f"Git directory: {self.git_dir}")
        print_info(f"Output directory: {self.output_dir}")
        print()

        start_time = time.time()

        try:
            # Check if git_dir exists
            if not os.path.exists(self.git_dir):
                print_error(f"Git directory not found: {self.git_dir}")
                return False

            # Resolve HEAD
            head_sha = self._resolve_head()
            if head_sha:
                print_info(f"HEAD: {head_sha[:12]}...")
            else:
                print_warning("Could not resolve HEAD")

            # Find all commits from refs
            refs = self._find_commits_from_refs()
            if refs:
                print_info(f"Found {len(refs)} reference(s)")
                for ref_name, sha in refs[:5]:
                    print(f"    {ref_name}: {sha[:12]}...")
                if len(refs) > 5:
                    print(f"    ... and {len(refs) - 5} more")
            else:
                print_warning("No references found")

            # Extract from HEAD commit
            if head_sha:
                tree_sha = self._get_commit_tree(head_sha)
                if tree_sha:
                    print_info(f"Extracting from HEAD tree {tree_sha[:12]}...")
                    extract_dir = os.path.join(self.output_dir, "extracted")
                    safe_makedirs(extract_dir)
                    self._extract_tree(tree_sha, extract_dir)
                else:
                    print_warning("Could not find tree in HEAD commit")

            # Also try to extract from other refs
            for ref_name, sha in refs[:3]:
                if sha == head_sha:
                    continue
                tree_sha = self._get_commit_tree(sha)
                if tree_sha:
                    safe_ref = ref_name.replace("/", "_").replace("\\", "_")
                    extract_dir = os.path.join(self.output_dir, f"extracted_{safe_ref}")
                    safe_makedirs(extract_dir)
                    self._extract_tree(tree_sha, extract_dir)

            # Summary
            elapsed = time.time() - start_time
            print_section("Extraction Summary")
            print_success(f"Files extracted: {self.extracted_files}")
            print_success(f"Output directory: {self.output_dir}")

            if self.errors:
                print_warning(f"Errors: {len(self.errors)}")
                for err in self.errors[:5]:
                    print(f"    {Colors.RED}{err}{Colors.END}")
                if len(self.errors) > 5:
                    print(f"    ... and {len(self.errors) - 5} more")

            print_success(f"Time elapsed: {elapsed:.1f}s")
            return True

        except KeyboardInterrupt:
            print_warning("\nExtraction interrupted by user.")
            return False
        except Exception as e:
            print_error(f"Extraction failed: {e}")
            return False
