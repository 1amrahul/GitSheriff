"""
GitSheriff - .git repository dumper module.

Downloads exposed .git directories by recursively fetching objects,
packs, and reference files. Mirrors DotGit's gitdumper.sh behavior
with expanded file list, binary hash extraction, and object guessing.
"""

import os
import re
import sys
import time
import zlib
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:
    print("Error: 'requests' library is required. Install with: pip install requests")
    sys.exit(1)

from .utils import (
    Colors, print_info, print_success, print_warning, print_error,
    print_section, ProgressBar, safe_makedirs, safe_write,
)


# ---------------------------------------------------------------------------
# Initial files to fetch (mirrors DotGit's gitdumper.sh + extras)
# ---------------------------------------------------------------------------
GIT_FILES = [
    # Core
    "HEAD",
    "config",
    "description",
    "index",
    "COMMIT_EDITMSG",

    # Refs
    "packed-refs",
    "refs/heads/master",
    "refs/heads/main",
    "refs/heads/develop",
    "refs/heads/dev",
    "refs/remotes/origin/HEAD",
    "refs/remotes/origin/master",
    "refs/remotes/origin/main",
    "refs/stash",
    "refs/tags/*",

    # Logs
    "logs/HEAD",
    "logs/refs/heads/master",
    "logs/refs/heads/main",
    "logs/refs/remotes/origin/HEAD",
    "logs/refs/remotes/origin/master",

    # Info
    "info/refs",
    "info/exclude",
    "objects/info/packs",

    # Merge/rebase state
    "MERGE_HEAD",
    "ORIG_HEAD",
    "CHERRY_PICK_HEAD",
    "REBASE_HEAD",
    "rebase-apply/onto",
    "rebase-apply/head-name",
    "rebase-apply/pad",
    "rebase-apply/msg-body",

    # Magit / wip refs
    "refs/wip/index/refs/heads/master",
    "refs/wip/wtree/refs/heads/master",
    "refs/wip/index/refs/heads/main",
    "refs/wip/wtree/refs/heads/main",

    # Shallow
    "shallow",
]

# Regex patterns for extracting hashes from text and binary content
HASH_RE = re.compile(rb"[0-9a-f]{40}")
PACK_RE = re.compile(rb"pack-[0-9a-f]{40}")


class GitDumper:
    """Downloads an exposed .git directory from a web server."""

    def __init__(self, url, output_dir=None, threads=10, timeout=10,
                 verify_ssl=True, fetch_large_files=True):
        """
        Initialize the GitDumper.

        Args:
            url: Base URL where .git is exposed (e.g., http://example.com/.git/).
            output_dir: Directory to save the dumped .git. Defaults to auto-generated.
            threads: Number of concurrent download threads.
            timeout: HTTP request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
            fetch_large_files: Whether to fetch large objects and pack files.
        """
        # Normalize URL
        url = url.rstrip("/")
        if not url.endswith("/.git"):
            if url.endswith("/.git/"):
                url = url[:-1]
            else:
                url = url + "/.git"

        self.url = url
        self.output_dir = output_dir or self._default_output_dir()
        self.threads = threads
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.fetch_large_files = fetch_large_files

        # Tracking
        self.downloaded = set()
        self.errors = []
        self.git_dir = os.path.join(self.output_dir, ".git")

    def _default_output_dir(self):
        """Generate a default output directory name from the URL."""
        parsed = urlparse(self.url)
        domain = parsed.hostname or "unknown"
        domain = domain.replace(".", "_")
        return os.path.join("dumped", domain)

    def _git_url(self, path):
        """Build a full URL for a .git file."""
        return f"{self.url}/{path}"

    def _fetch_file(self, path):
        """Fetch a single file from the .git directory.

        Returns:
            Tuple of (path, content_bytes, success_bool).
        """
        url = self._git_url(path)

        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers={"User-Agent": "GitSheriff/2.0"},
            )

            if response.status_code == 200 and len(response.content) > 0:
                return (path, response.content, True)
            return (path, b"", False)

        except requests.exceptions.SSLError:
            try:
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    headers={"User-Agent": "GitSheriff/2.0"},
                )
                if response.status_code == 200 and len(response.content) > 0:
                    return (path, response.content, True)
                return (path, b"", False)
            except Exception:
                return (path, b"", False)

        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.RequestException):
            return (path, b"", False)
        except Exception:
            return (path, b"", False)

    def _fetch_object(self, sha1):
        """Fetch a git object by its SHA1 hash.

        Returns:
            Tuple of (sha1, content_bytes, success_bool).
        """
        if sha1 in self.downloaded:
            return (sha1, b"", False)

        prefix = sha1[:2]
        suffix = sha1[2:]
        loose_path = f"objects/{prefix}/{suffix}"

        path, content, success = self._fetch_file(loose_path)
        if success:
            self.downloaded.add(sha1)
            return (sha1, content, True)

        return (sha1, b"", False)

    # ------------------------------------------------------------------
    # Binary hash extraction (mirrors DotGit: strings -a | grep 40-hex)
    # ------------------------------------------------------------------

    def _extract_hashes_from_binary(self, data):
        """Extract all 40-char hex strings from raw binary content.

        This mirrors DotGit's approach of running 'strings -a' then
        grepping for 40-char hex patterns on every downloaded file.
        """
        if not data:
            return set()
        return {m.decode("ascii") for m in HASH_RE.findall(data)}

    def _extract_hashes_from_text(self, text):
        """Extract all 40-char hex strings from text content."""
        if not text:
            return set()
        return set(re.findall(r"[0-9a-f]{40}", text))

    def _extract_packs_from_binary(self, data):
        """Extract pack file references from binary content."""
        if not data:
            return set()
        return {m.decode("ascii") for m in PACK_RE.findall(data)}

    def _decompress_object(self, raw_bytes):
        """Decompress a loose git object and extract its type and content.

        Returns:
            Tuple of (type_str, content_bytes) or (None, None) on failure.
        """
        try:
            decompressed = zlib.decompress(raw_bytes)
            null_idx = decompressed.find(b"\x00")
            if null_idx == -1:
                return None, None
            header = decompressed[:null_idx].decode("utf-8", errors="replace")
            obj_type = header.split(" ")[0]
            content = decompressed[null_idx + 1:]
            return obj_type, content
        except (zlib.error, ValueError, IndexError):
            return None, None

    def _extract_hashes_from_object(self, obj_type, content):
        """Extract referenced object hashes from a parsed git object.

        Returns:
            Set of 40-character hex hash strings.
        """
        hashes = set()

        if obj_type == "commit":
            for line in content.decode("utf-8", errors="replace").splitlines():
                parts = line.split(" ")
                if len(parts) >= 2 and parts[0] in ("tree", "parent"):
                    h = parts[1].strip()
                    if len(h) == 40 and all(c in "0123456789abcdef" for c in h):
                        hashes.add(h)

        elif obj_type == "tree":
            i = 0
            while i < len(content):
                space_idx = content.find(b" ", i)
                null_idx = content.find(b"\x00", i)
                if space_idx == -1 or null_idx == -1:
                    break
                sha_start = null_idx + 1
                if sha_start + 20 <= len(content):
                    sha_hex = content[sha_start:sha_start + 20].hex()
                    if len(sha_hex) == 40:
                        hashes.add(sha_hex)
                    i = sha_start + 20
                else:
                    break

        elif obj_type == "tag":
            for line in content.decode("utf-8", errors="replace").splitlines():
                parts = line.split(" ")
                if len(parts) >= 2 and parts[0] == "object":
                    h = parts[1].strip()
                    if len(h) == 40 and all(c in "0123456789abcdef" for c in h):
                        hashes.add(h)

        return hashes

    # ------------------------------------------------------------------
    # Reference-based object discovery
    # ------------------------------------------------------------------

    def _discover_objects_from_refs(self):
        """Discover object hashes from all downloaded reference files.

        Returns:
            Set of 40-character hex hashes.
        """
        objects = set()

        # Scan all files in .git for hashes and pack references
        packs_found = set()
        for root, dirs, files in os.walk(self.git_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "rb") as f:
                        data = f.read()
                    # Extract 40-char hex hashes (from both text and binary)
                    objects.update(self._extract_hashes_from_binary(data))
                    # Extract pack file references
                    packs_found.update(self._extract_packs_from_binary(data))
                except Exception:
                    pass

        # Download any discovered pack files
        for pack_ref in packs_found:
            self._fetch_pack_by_ref(pack_ref)

        return objects

    def _fetch_pack_by_ref(self, pack_ref):
        """Download a pack file and its index by reference name.

        Args:
            pack_ref: Pack reference like 'pack-abc123...'
        """
        pack_path = f"objects/pack/{pack_ref}.pack"
        idx_path = f"objects/pack/{pack_ref}.idx"

        # Check if already downloaded
        local_pack = os.path.join(self.git_dir, pack_path)
        if os.path.exists(local_pack):
            return

        path1, content1, ok1 = self._fetch_file(pack_path)
        if ok1 and content1:
            safe_makedirs(os.path.dirname(local_pack))
            try:
                with open(local_pack, "wb") as f:
                    f.write(content1)
                print_success(f"Downloaded pack: {pack_ref}.pack")
            except Exception as e:
                self.errors.append(f"Failed to write pack {pack_ref}: {e}")

        path2, content2, ok2 = self._fetch_file(idx_path)
        if ok2 and content2:
            local_idx = os.path.join(self.git_dir, idx_path)
            try:
                with open(local_idx, "wb") as f:
                    f.write(content2)
            except Exception as e:
                self.errors.append(f"Failed to write pack index {pack_ref}: {e}")

    def _discover_referenced_objects(self, initial_objects):
        """Recursively discover all objects referenced from initial objects.

        Starts with initial objects (commit hashes from refs), downloads them,
        decompresses to find referenced tree/blob hashes, and repeats until
        no new objects are found.

        Returns:
            Set of all discovered object hashes.
        """
        all_objects = set(initial_objects)
        to_process = list(initial_objects)
        processed = set()

        max_depth = 20
        depth = 0

        while to_process and depth < max_depth:
            batch = list(to_process)
            to_process = []
            depth += 1

            print_info(f"  Resolving objects (depth {depth}, {len(batch)} to inspect)...")

            for sha1 in batch:
                if sha1 in processed:
                    continue
                processed.add(sha1)

                # Read the local object file if we have it
                prefix = sha1[:2]
                suffix = sha1[2:]
                obj_path = os.path.join(self.git_dir, "objects", prefix, suffix)

                raw_bytes = None
                if os.path.exists(obj_path):
                    try:
                        with open(obj_path, "rb") as f:
                            raw_bytes = f.read()
                    except Exception:
                        pass

                if raw_bytes is None:
                    # Need to download it first
                    _, content, success = self._fetch_object(sha1)
                    if success and content:
                        obj_dir = os.path.join(self.git_dir, "objects", prefix)
                        safe_makedirs(obj_dir)
                        try:
                            with open(obj_path, "wb") as f:
                                f.write(content)
                            raw_bytes = content
                        except Exception:
                            continue
                    else:
                        continue

                # Decompress and find referenced hashes
                obj_type, obj_content = self._decompress_object(raw_bytes)
                if obj_type is None:
                    continue

                referenced = self._extract_hashes_from_object(obj_type, obj_content)
                for h in referenced:
                    if h not in all_objects:
                        all_objects.add(h)
                        to_process.append(h)

        return all_objects

    # ------------------------------------------------------------------
    # Object guessing (brute-force common patterns)
    # ------------------------------------------------------------------

    def _guess_objects(self):
        """Try to download objects by guessing common hash patterns.

        This attempts to find objects that might not be referenced by
        any downloaded file but exist on the server (e.g., orphaned
        objects, objects referenced by pack indices we couldn't parse).

        Returns:
            Set of hashes that were successfully downloaded.
        """
        found = set()

        # Known special git hashes
        special_hashes = [
            # Empty tree (used in initial commits)
            "4b825dc642cb6eb9a060e54bf899d91f6b682d1",
            # Empty blob
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
        ]

        # Try all known commit hashes we already have - their parents' hashes
        # by flipping bits in known hashes (a heuristic)
        known = list(self.downloaded)

        candidates = list(special_hashes)

        # For each known hash, try small perturbations (common offset patterns)
        for h in known[:50]:  # Limit to avoid excessive requests
            # Try adjacent hashes (off-by-one in the last nibble)
            for delta in [-1, 1, -2, 2]:
                try:
                    val = int(h, 16) + delta
                    candidates.append(format(val, "040x"))
                except ValueError:
                    pass

        # Try short-prefix brute force for objects/00/ through objects/ff/
        # by trying 6-digit hex suffixes (small sample)
        for prefix_byte in range(256):
            prefix = f"{prefix_byte:02x}"
            for suffix_sample in ["000000", "111111", "aaaaaa", "ffffff",
                                   "012345", "abcdef", "123456", "fedcba",
                                   "000001", "ffffff"]:
                candidates.append(prefix + suffix_sample)

        print_info(f"Guessing: trying {len(candidates)} candidate object hashes...")

        for sha1 in candidates:
            if len(sha1) != 40:
                continue
            if sha1 in self.downloaded:
                continue

            path, content, success = self._fetch_object(sha1)
            if success and content:
                found.add(sha1)
                # Save it
                prefix = sha1[:2]
                suffix = sha1[2:]
                obj_dir = os.path.join(self.git_dir, "objects", prefix)
                safe_makedirs(obj_dir)
                obj_path = os.path.join(obj_dir, suffix)
                try:
                    with open(obj_path, "wb") as f:
                        f.write(content)
                except Exception:
                    pass

        return found

    # ------------------------------------------------------------------
    # Download objects
    # ------------------------------------------------------------------

    def _download_objects(self, objects):
        """Download a set of git objects."""
        if not objects:
            return

        print_info(f"Downloading {len(objects)} object(s)...")
        progress = ProgressBar(len(objects), desc="Objects")

        for sha1 in objects:
            if sha1 in self.downloaded:
                progress.update()
                continue

            path, content, success = self._fetch_object(sha1)
            if success and content:
                prefix = sha1[:2]
                suffix = sha1[2:]
                obj_dir = os.path.join(self.git_dir, "objects", prefix)
                safe_makedirs(obj_dir)
                obj_path = os.path.join(obj_dir, suffix)
                try:
                    with open(obj_path, "wb") as f:
                        f.write(content)
                except Exception as e:
                    self.errors.append(f"Failed to write object {sha1}: {e}")

            progress.update()
            time.sleep(0.01)  # Rate limiting

        progress.finish()

    # ------------------------------------------------------------------
    # Main dump
    # ------------------------------------------------------------------

    def dump(self):
        """Execute the full .git dump.

        Returns:
            Tuple of (success_bool, output_dir_string).
        """
        print_section("Git Repository Dump")
        print_info(f"Target: {self.url}")
        print_info(f"Output: {self.output_dir}")
        print()

        start_time = time.time()

        try:
            # Create output directory
            safe_makedirs(self.git_dir)

            # Step 1: Fetch known git files
            # Filter out wildcard patterns
            static_files = [f for f in GIT_FILES if "*" not in f]
            print_info(f"Fetching {len(static_files)} standard git file(s)...")
            progress = ProgressBar(len(static_files), desc="Files")

            for git_file in static_files:
                path, content, success = self._fetch_file(git_file)
                if success and content:
                    local_path = os.path.join(self.git_dir, path)
                    local_dir = os.path.dirname(local_path)
                    safe_makedirs(local_dir)
                    try:
                        with open(local_path, "wb") as f:
                            f.write(content)
                    except Exception as e:
                        self.errors.append(f"Failed to write {path}: {e}")

                progress.update()
                time.sleep(0.01)

            progress.finish()

            # Step 2: Check for pack files from packs file
            print_info("Checking for pack files...")
            packs_path = os.path.join(self.git_dir, "objects", "info", "packs")
            if os.path.exists(packs_path):
                try:
                    with open(packs_path, "rb") as f:
                        pack_content = f.read()
                    pack_hashes = self._extract_hashes_from_binary(pack_content)
                    if pack_hashes:
                        print_info(f"Found {len(pack_hashes)} pack file(s)")
                        for pack_hash in pack_hashes:
                            self._fetch_pack_by_ref(f"pack-{pack_hash}")
                except Exception as e:
                    print_warning(f"Failed to parse packs file: {e}")
            else:
                print_info("No packs file found")

            # Step 3: Discover and download objects
            if self.fetch_large_files:
                print_info("Discovering objects from references...")
                initial_objects = self._discover_objects_from_refs()
                if initial_objects:
                    print_info(f"Found {len(initial_objects)} initial object(s) from refs")
                    # Recursively discover all referenced objects
                    print_info("Recursively resolving object references...")
                    all_objects = self._discover_referenced_objects(initial_objects)
                    new_objects = all_objects - initial_objects
                    if new_objects:
                        print_success(
                            f"Discovered {len(new_objects)} additional object(s) "
                            f"from tree/blob references"
                        )
                    self._download_objects(all_objects)
                else:
                    print_info("No objects discovered from refs, trying object guesser...")
                    guessed = self._guess_objects()
                    if guessed:
                        print_success(f"Guessed {len(guessed)} object(s) successfully")
                    else:
                        print_info("No objects found via guessing")

            # Step 4: Summary
            elapsed = time.time() - start_time
            print_section("Dump Summary")
            print_success(f"Output directory: {self.output_dir}")
            print_success(f"Objects downloaded: {len(self.downloaded)}")
            print_success(f"Time elapsed: {elapsed:.1f}s")

            if self.errors:
                print_warning(f"Errors encountered: {len(self.errors)}")
                for err in self.errors[:5]:
                    print(f"    {Colors.RED}{err}{Colors.END}")
                if len(self.errors) > 5:
                    print(f"    ... and {len(self.errors) - 5} more")

            return True, self.output_dir

        except KeyboardInterrupt:
            print_warning("\nDump interrupted by user.")
            return False, self.output_dir
        except Exception as e:
            print_error(f"Dump failed: {e}")
            return False, self.output_dir
