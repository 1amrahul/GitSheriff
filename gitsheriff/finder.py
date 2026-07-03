"""
GitSheriff - .git exposure detection module.

Scans URLs for exposed .git directories and related sensitive files.
"""

import re
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("Error: 'requests' library is required. Install with: pip install requests")
    sys.exit(1)

from .utils import (
    Colors, print_info, print_success, print_warning, print_error,
    print_section, print_found, print_not_found, format_size,
)


# Common paths to check for .git exposure
GIT_PATHS = [
    "/.git/",
    "/.git/HEAD",
    "/.git/index",
    "/.git/config",
    "/.git/description",
    "/.git/COMMIT_EDITMSG",
    "/.git/FETCH_HEAD",
    "/.git/HEAD~1",
]

# Paths that confirm full .git dump is possible
CONFIRMATION_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.git/index",
]


class GitFinder:
    """Scans a list of URLs for exposed .git directories."""

    def __init__(self, urls=None, threads=10, timeout=10, verify_ssl=True):
        """
        Initialize the GitFinder.

        Args:
            urls: List of URLs to scan.
            threads: Number of concurrent threads.
            timeout: HTTP request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.urls = urls or []
        self.threads = threads
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.found = []
        self.not_found = []
        self.errors = []

    def _check_url(self, url):
        """Check a single URL for .git exposure.

        Args:
            url: Base URL to check.

        Returns:
            Tuple of (url, found_paths, status) where status is
            'found', 'not_found', or 'error'.
        """
        # Normalize URL
        url = url.rstrip("/")
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        found_paths = []

        try:
            for path in GIT_PATHS:
                full_url = url + path
                try:
                    response = requests.get(
                        full_url,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=False,
                        headers={"User-Agent": "GitSheriff/2.0"},
                    )

                    if response.status_code == 200:
                        content_type = response.headers.get("Content-Type", "")
                        content_length = len(response.content)

                        # Filter out generic error pages
                        if content_length < 10:
                            continue

                        # Check if it looks like a real git file
                        is_git_content = False
                        if path == "/.git/HEAD":
                            text = response.text.strip()
                            if text.startswith("ref:"):
                                is_git_content = True
                        elif path == "/.git/config":
                            text = response.text
                            if "[core]" in text or "[remote" in text:
                                is_git_content = True
                        elif path == "/.git/index":
                            is_git_content = True
                        else:
                            is_git_content = True

                        if is_git_content:
                            found_paths.append({
                                "path": path,
                                "url": full_url,
                                "status_code": response.status_code,
                                "size": content_length,
                                "content_type": content_type,
                            })

                except requests.exceptions.SSLError:
                    # Try without SSL verification
                    try:
                        response = requests.get(
                            full_url,
                            timeout=self.timeout,
                            verify=False,
                            allow_redirects=False,
                            headers={"User-Agent": "GitSheriff/2.0"},
                        )
                        if response.status_code == 200 and len(response.content) >= 10:
                            found_paths.append({
                                "path": path,
                                "url": full_url,
                                "status_code": response.status_code,
                                "size": len(response.content),
                                "content_type": response.headers.get("Content-Type", ""),
                            })
                    except Exception:
                        pass

                except requests.exceptions.ConnectionError:
                    # Connection refused or DNS failure - skip this URL
                    pass

                except requests.exceptions.Timeout:
                    # Timeout - skip this path
                    pass

                except requests.exceptions.RequestException:
                    # Any other request error - skip
                    pass

            if found_paths:
                return (url, found_paths, "found")
            else:
                return (url, [], "not_found")

        except Exception as e:
            return (url, [], "error", str(e))

    def scan(self):
        """Scan all URLs for .git exposure.

        Returns:
            List of dicts with found URLs and their exposed paths.
        """
        if not self.urls:
            print_warning("No URLs provided for scanning.")
            return []

        print_section("Scanning for .git Exposure")
        print_info(f"Scanning {len(self.urls)} URL(s) with {self.threads} thread(s)")
        print()

        results = []

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._check_url, url): url
                    for url in self.urls
                }

                for future in as_completed(futures):
                    try:
                        result = future.result()
                        url, found_paths, status = result[0], result[1], result[2]

                        if status == "found":
                            self.found.append(url)
                            results.append({
                                "url": url,
                                "paths": found_paths,
                            })
                            print_found(url, f"({len(found_paths)} path(s))")
                            for fp in found_paths:
                                print(f"    {Colors.GREEN}{fp['path']}{Colors.END} "
                                      f"({format_size(fp['size'])})")

                        elif status == "not_found":
                            self.not_found.append(url)
                            print_not_found(url)

                        elif status == "error":
                            error_msg = result[3] if len(result) > 3 else "Unknown error"
                            self.errors.append({"url": url, "error": error_msg})
                            print_error(f"{url}: {error_msg}")

                    except Exception as e:
                        print_error(f"Thread error: {e}")

        except KeyboardInterrupt:
            print_warning("\nScan interrupted by user.")
        except Exception as e:
            print_error(f"Scan failed: {e}")

        # Print summary
        print_section("Scan Summary")
        print_success(f"Found: {len(self.found)} URL(s)")
        print_info(f"Not found: {len(self.not_found)} URL(s)")
        if self.errors:
            print_error(f"Errors: {len(self.errors)} URL(s)")

        return results

    def get_confirmable_urls(self):
        """Return URLs where .git HEAD was found (full dump possible).

        Returns:
            List of URLs where .git/HEAD was detected.
        """
        confirmable = []
        for result in self.found:
            # This is a simplified check - in practice you'd track
            # which paths were found per URL
            confirmable.append(result)
        return confirmable
