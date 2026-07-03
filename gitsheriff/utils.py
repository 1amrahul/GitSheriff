"""
GitSheriff - Utility functions for UI, colors, progress bars, and common helpers.

All printed characters are ASCII-safe for Windows cp1252 compatibility.
"""

import os
import sys
import time
import threading


class Colors:
    """ANSI color codes for terminal output."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"

    @classmethod
    def disable(cls):
        """Disable colors (e.g., for non-TTY output)."""
        for attr in ["RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN", "BOLD", "UNDERLINE", "END"]:
            setattr(cls, attr, "")


def supports_color():
    """Check if the terminal supports ANSI colors."""
    if os.getenv("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return True


if not supports_color():
    Colors.disable()


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_banner():
    """Print the GitSheriff banner."""
    banner = r"""
       _____ _ _   _____                                  
      / ____(_) | |  __ \                                 
     | |  __ _| |_| |  | |_   _ _ __ ___  _ __   ___ _ __
     | | |_ | | __| |  | | | | | '_ ` _ \| '_ \ / _ \ '__|
     | |__| | | |_| |__| | |_| | | | | | | |_) |  __/ |  
      \_____|_|\__|_____/ \__,_|_| |_| |_| .__/ \___|_|  
                                          | |              
                                          |_|  v2.0.0     
    """
    try:
        print(Colors.CYAN + Colors.BOLD + banner + Colors.END)
    except UnicodeEncodeError:
        print(banner)


def print_info(message):
    """Print an informational message."""
    try:
        print(f"  {Colors.BLUE}[*]{Colors.END} {message}")
    except UnicodeEncodeError:
        print(f"  [*] {message}")


def print_success(message):
    """Print a success message."""
    try:
        print(f"  {Colors.GREEN}[+]{Colors.END} {message}")
    except UnicodeEncodeError:
        print(f"  [+] {message}")


def print_warning(message):
    """Print a warning message."""
    try:
        print(f"  {Colors.YELLOW}[!]{Colors.END} {message}")
    except UnicodeEncodeError:
        print(f"  [!] {message}")


def print_error(message):
    """Print an error message."""
    try:
        print(f"  {Colors.RED}[-]{Colors.END} {message}")
    except UnicodeEncodeError:
        print(f"  [-] {message}")


def print_section(title):
    """Print a section header."""
    try:
        print(f"\n  {Colors.CYAN}{Colors.BOLD}--- {title} ---{Colors.END}")
    except UnicodeEncodeError:
        print(f"\n  --- {title} ---")


def print_found(url, message=""):
    """Print a found result."""
    try:
        print(f"  {Colors.GREEN}[+]{Colors.END} {Colors.GREEN}{url}{Colors.END} {message}")
    except UnicodeEncodeError:
        print(f"  [+] {url} {message}")


def print_not_found(url):
    """Print a not-found result."""
    try:
        print(f"  {Colors.RED}[-]{Colors.END} {url}")
    except UnicodeEncodeError:
        print(f"  [-] {url}")


# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------

class ProgressBar:
    """A simple progress bar for downloads and operations."""

    def __init__(self, total, desc="Progress", width=40):
        self.total = total
        self.desc = desc
        self.width = width
        self.current = 0
        self.start_time = time.time()
        self._lock = threading.Lock()

    def update(self, n=1):
        """Update the progress bar by n units."""
        with self._lock:
            self.current += n
            self._draw()

    def _draw(self):
        """Draw the progress bar."""
        if self.total <= 0:
            return
        pct = min(self.current / self.total, 1.0)
        filled = int(self.width * pct)
        bar = "#" * filled + "-" * (self.width - filled)
        elapsed = time.time() - self.start_time
        rate = self.current / elapsed if elapsed > 0 else 0
        eta = (self.total - self.current) / rate if rate > 0 else 0

        try:
            sys.stdout.write(
                f"\r  {self.desc}: [{bar}] "
                f"{self.current}/{self.total} "
                f"({pct*100:.0f}%) "
                f"ETA: {eta:.0f}s "
            )
            sys.stdout.flush()
        except UnicodeEncodeError:
            sys.stdout.write(
                f"\r  {self.desc}: [{bar}] "
                f"{self.current}/{self.total} "
                f"({pct*100:.0f}%) "
                f"ETA: {eta:.0f}s "
            )
            sys.stdout.flush()

    def finish(self):
        """Mark the progress bar as complete."""
        try:
            sys.stdout.write("\n")
            sys.stdout.flush()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Spinner
# ---------------------------------------------------------------------------

class Spinner:
    """A simple ASCII spinner for long-running operations."""

    FRAMES = ["|", "/", "-", "\\"]
    INTERVAL = 0.1

    def __init__(self, message="Working"):
        self.message = message
        self._running = False
        self._thread = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()

    def start(self):
        """Start the spinner."""
        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the spinner."""
        self._running = False
        if self._thread:
            self._thread.join()
        try:
            sys.stdout.write("\r" + " " * (len(self.message) + 10) + "\r")
            sys.stdout.flush()
        except Exception:
            pass

    def _spin(self):
        """Spin animation loop."""
        idx = 0
        while self._running:
            try:
                sys.stdout.write(f"\r  {self.FRAMES[idx % len(self.FRAMES)]} {self.message}...")
                sys.stdout.flush()
            except Exception:
                pass
            time.sleep(self.INTERVAL)
            idx += 1


# ---------------------------------------------------------------------------
# Confirmation prompt
# ---------------------------------------------------------------------------

def confirm(message, default=True):
    """Ask the user for confirmation.

    Args:
        message: The prompt message to display.
        default: Default answer if user just presses Enter.

    Returns:
        True if confirmed, False otherwise.
    """
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        answer = input(f"  {Colors.YELLOW}?{Colors.END} {message} {suffix}: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False

    if not answer:
        return default
    return answer in ("y", "yes")


def prompt_input(message, default=""):
    """Prompt the user for input with an optional default.

    Args:
        message: The prompt message.
        default: Default value if user presses Enter.

    Returns:
        The user's input or the default value.
    """
    try:
        suffix = f" [{default}]" if default else ""
        answer = input(f"  {Colors.YELLOW}?{Colors.END} {message}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return answer if answer else default


# ---------------------------------------------------------------------------
# File size formatting
# ---------------------------------------------------------------------------

def format_size(size_bytes):
    """Format a byte count into a human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


# ---------------------------------------------------------------------------
# Safe file writing
# ---------------------------------------------------------------------------

def safe_write(filepath, content, mode="w", encoding="utf-8"):
    """Write content to a file with proper error handling.

    Args:
        filepath: Path to write to.
        content: Content to write.
        mode: File open mode.
        encoding: File encoding.

    Returns:
        True on success, False on failure.
    """
    try:
        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
        with open(filepath, mode, encoding=encoding, errors="replace") as f:
            f.write(content)
        return True
    except PermissionError:
        print_error(f"Permission denied: {filepath}")
        return False
    except OSError as e:
        print_error(f"Failed to write {filepath}: {e}")
        return False
    except Exception as e:
        print_error(f"Unexpected error writing {filepath}: {e}")
        return False


def safe_read(filepath, mode="r", encoding="utf-8"):
    """Read content from a file with proper error handling.

    Args:
        filepath: Path to read from.
        mode: File open mode.
        encoding: File encoding.

    Returns:
        File content as string, or None on failure.
    """
    try:
        with open(filepath, mode, encoding=encoding, errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        print_error(f"File not found: {filepath}")
        return None
    except PermissionError:
        print_error(f"Permission denied: {filepath}")
        return None
    except OSError as e:
        print_error(f"Failed to read {filepath}: {e}")
        return None
    except Exception as e:
        print_error(f"Unexpected error reading {filepath}: {e}")
        return None


def safe_makedirs(path):
    """Create directories with proper error handling."""
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except PermissionError:
        print_error(f"Permission denied creating directory: {path}")
        return False
    except OSError as e:
        print_error(f"Failed to create directory {path}: {e}")
        return False
    except Exception as e:
        print_error(f"Unexpected error creating directory {path}: {e}")
        return False
