"""
GitSheriff - .git repository dumper module.

Downloads exposed .git directories by recursively fetching objects,
packs, and reference files.
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


# Files to fetch from the .git directory
GIT_FILES = [
    "HEAD",
    "config",
    "description",
    "index",
    "packed-refs",
    "refs/heads/master",
    "refs/heads/main",
    "refs/heads/develop",
    "refs/heads/dev",
    "refs/heads/feature/*",
    "refs/heads/release/*",
    "refs/heads/hotfix/*",
    "refs/remotes/origin/HEAD",
    "refs/remotes/origin/master",
    "refs/remotes/origin/main",
    "refs/stash",
    "info/exclude",
    "objects/info/packs",
    "COMMIT_EDITMSG",
    "FETCH_HEAD",
    "MERGE_HEAD",
    "ORIG_HEAD",
    "rebase-apply/pad",
    "rebase-apply/onto",
    "rebase-apply/head-name",
    "rebase-apply/msg-body",
]

# Regex to find object hashes in git files
OBJECT_HASH_RE = re.compile(r"[0-9a-f]{40}")
PACK_HASH_RE = re.compile(r"[0-9a-f]{40}")


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
        """Build a full URL for a .git file.

        Args:
            path: Relative path within .git directory.

        Returns:
            Full URL string.
        """
        return f"{self.url}/{path}"

    def _fetch_file(self, path):
        """Fetch a single file from the .git directory.

        Args:
            path: Relative path within .git directory.

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
            elif response.status_code == 404:
                return (path, b"", False)
            else:
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

        except requests.exceptions.ConnectionError:
            return (path, b"", False)
        except requests.exceptions.Timeout:
            return (path, b"", False)
        except requests.exceptions.RequestException:
            return (path, b"", False)
        except Exception as e:
            return (path, b"", False)

    def _fetch_object(self, sha1):
        """Fetch a git object by its SHA1 hash.

        Args:
            sha1: 40-character hex SHA1 hash.

        Returns:
            Tuple of (sha1, content_bytes, success_bool).
        """
        if sha1 in self.downloaded:
            return (sha1, b"", False)

        # Try loose object first
        prefix = sha1[:2]
        suffix = sha1[2:]
        loose_path = f"objects/{prefix}/{suffix}"

        path, content, success = self._fetch_file(loose_path)
        if success:
            self.downloaded.add(sha1)
            # Try to decompress to get the object type
            try:
                decompressed = zlib.decompress(content)
                return (sha1, content, True)
            except zlib.error:
                # Not a valid zlib object, might be raw
                return (sha1, content, True)

        return (sha1, b"", False)

    def _discover_objects_from_refs(self):
        """Discover object hashes from reference files.

        Returns:
            Set of 40-character hex hashes.
        """
        objects = set()
        ref_patterns = [
            "refs/heads/*",
            "refs/remotes/origin/*",
            "refs/tags/*",
        ]

        # Try to read HEAD first
        head_path = os.path.join(self.git_dir, "HEAD")
        if os.path.exists(head_path):
            try:
                with open(head_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read().strip()
                    if content.startswith("ref:"):
                        ref_path = content.split(" ")[1].strip()
                        ref_file = os.path.join(self.git_dir, ref_path)
                        if os.path.exists(ref_file):
                            with open(ref_file, "r", encoding="utf-8", errors="replace") as rf:
                                sha = rf.read().strip()
                                if len(sha) == 40:
                                    objects.add(sha)
            except Exception:
                pass

        # Scan all files in .git for object hashes
        for root, dirs, files in os.walk(self.git_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                        for match in OBJECT_HASH_RE.finditer(content):
                            objects.add(match.group())
                except Exception:
                    pass

        return objects

    def _download_objects(self, objects):
        """Download a set of git objects.

        Args:
            objects: Set of 40-character hex hashes to download.
        """
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
                # Save the loose object
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

    def dump(self):
        """Execute the full .git dump.

        Returns:
            True on success, False on failure. Also returns the output_dir.
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
            print_info("Fetching standard git files...")
            progress = ProgressBar(len(GIT_FILES), desc="Files")

            for git_file in GIT_FILES:
                if "*" in git_file:
                    # Skip wildcard patterns for now
                    progress.update()
                    continue

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
                time.sleep(0.01)  # Rate limiting

            progress.finish()

            # Step 2: Check for pack files
            print_info("Checking for pack files...")
            packs_path = os.path.join(self.git_dir, "objects", "info", "packs")
            if os.path.exists(packs_path):
                try:
                    with open(packs_path, "r", encoding="utf-8", errors="replace") as f:
                        pack_content = f.read()
                    pack_hashes = PACK_HASH_RE.findall(pack_content)
                    if pack_hashes:
                        print_info(f"Found {len(pack_hashes)} pack file(s)")
                        for pack_hash in pack_hashes:
                            pack_path = f"objects/pack/pack-{pack_hash}.pack"
                            idx_path = f"objects/pack/pack-{pack_hash}.idx"
                            path1, content1, success1 = self._fetch_file(pack_path)
                            if success1 and content1:
                                local_path = os.path.join(self.git_dir, pack_path)
                                safe_makedirs(os.path.dirname(local_path))
                                try:
                                    with open(local_path, "wb") as f:
                                        f.write(content1)
                                    print_success(f"Downloaded: pack-{pack_hash}.pack")
                                except Exception as e:
                                    self.errors.append(f"Failed to write pack: {e}")

                            path2, content2, success2 = self._fetch_file(idx_path)
                            if success2 and content2:
                                local_path = os.path.join(self.git_dir, idx_path)
                                try:
                                    with open(local_path, "wb") as f:
                                        f.write(content2)
                                except Exception as e:
                                    self.errors.append(f"Failed to write pack index: {e}")
                except Exception as e:
                    print_warning(f"Failed to parse packs file: {e}")
            else:
                print_info("No pack files found")

            # Step 3: Discover and download objects
            if self.fetch_large_files:
                print_info("Discovering objects from references...")
                objects = self._discover_objects_from_refs()
                if objects:
                    self._download_objects(objects)
                else:
                    print_info("No additional objects discovered from references")

            # Step 4: Summary
            elapsed = time.time() - start_time
            print_section("Dump Summary")
            print_success(f"Output directory: {self.output_dir}")
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
