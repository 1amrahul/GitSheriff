"""
GitSheriff - Unified CLI with integrated dump and extract workflow.

Usage:
    python -m gitsheriff find <urls>     - Scan for .git exposure
    python -m gitsheriff dump <url>      - Dump an exposed .git repo
    python -m gitsheriff extract <dir>   - Recover files from a dumped .git
"""

import os
import sys
import argparse

from . import __version__, __author__, __url__, __website__
from .utils import (
    Colors, print_banner, print_info, print_success, print_warning,
    print_error, print_section, confirm,
)


def cmd_find(args):
    """Execute the find command - scan URLs for .git exposure."""
    from .finder import GitFinder

    # Parse URLs from args or stdin
    urls = []
    if args.urls:
        urls = args.urls
    elif not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip()]
    else:
        print_error("No URLs provided. Use --urls or pipe from stdin.")
        return 1

    try:
        finder = GitFinder(
            urls=urls,
            threads=args.threads,
            timeout=args.timeout,
            verify_ssl=args.verify_ssl,
        )
        results = finder.scan()

        if results:
            # Save results if requested
            if args.output:
                try:
                    with open(args.output, "w") as f:
                        for r in results:
                            f.write(f"{r['url']}\n")
                    print_success(f"Results saved to {args.output}")
                except Exception as e:
                    print_error(f"Failed to save results: {e}")

            return 0
        else:
            print_info("No exposed .git directories found.")
            return 1

    except KeyboardInterrupt:
        print_warning("\nScan interrupted by user.")
        return 130
    except Exception as e:
        print_error(f"Find failed: {e}")
        return 1


def cmd_dump(args):
    """Execute the dump command - download an exposed .git repo.

    After successful dump, prompts user to extract/recover files.
    """
    from .dumper import GitDumper
    from .extractor import GitExtractor

    try:
        # Determine output directory
        output_dir = args.output
        if not output_dir:
            from urllib.parse import urlparse
            parsed = urlparse(args.url)
            domain = (parsed.hostname or "unknown").replace(".", "_")
            output_dir = os.path.join("dumped", domain)

        # Create and run dumper
        dumper = GitDumper(
            url=args.url,
            output_dir=output_dir,
            threads=args.threads,
            timeout=args.timeout,
            verify_ssl=args.verify_ssl,
            fetch_large_files=not args.skip_objects,
        )

        success, git_dir = dumper.dump()

        if not success:
            print_error("Dump failed.")
            return 1

        # Integrated flow: prompt to extract
        print()
        if args.yes or confirm("Do you want to extract/recover files from the dumped .git?", default=True):
            print()
            extractor = GitExtractor(
                git_dir=os.path.join(git_dir, ".git"),
                output_dir=git_dir,
            )
            extract_success = extractor.extract()
            if extract_success:
                print()
                print_success("Complete! Your extracted files are in the 'extracted' subdirectory.")
            else:
                print_warning("Extraction completed with errors. Check the output above.")
        else:
            print_info("Skipping extraction. You can run it manually later:")
            print_info(f"  python -m gitsheriff extract {os.path.join(git_dir, '.git')}")

        return 0

    except KeyboardInterrupt:
        print_warning("\nDump interrupted by user.")
        return 130
    except Exception as e:
        print_error(f"Dump failed: {e}")
        return 1


def cmd_extract(args):
    """Execute the extract command - recover files from a dumped .git."""
    from .extractor import GitExtractor

    try:
        git_dir = args.git_dir
        output_dir = args.output

        extractor = GitExtractor(
            git_dir=git_dir,
            output_dir=output_dir,
        )
        success = extractor.extract()

        if success:
            return 0
        else:
            return 1

    except KeyboardInterrupt:
        print_warning("\nExtraction interrupted by user.")
        return 130
    except Exception as e:
        print_error(f"Extract failed: {e}")
        return 1


def build_parser():
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="gitsheriff",
        description="GitSheriff - .git exposure detection, dumping, and recovery toolkit",
        epilog=f"Author: {__author__} | Website: {__website__}",
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- Find command ---
    find_parser = subparsers.add_parser(
        "find",
        help="Scan URLs for exposed .git directories",
        description="Scan one or more URLs for exposed .git directories and sensitive files.",
    )
    find_parser.add_argument(
        "--urls", "-u",
        nargs="+",
        help="URL(s) to scan",
    )
    find_parser.add_argument(
        "--output", "-o",
        help="Save found URLs to a file",
    )
    find_parser.add_argument(
        "--threads", "-t",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)",
    )
    find_parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: 10)",
    )
    find_parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification",
    )

    # --- Dump command ---
    dump_parser = subparsers.add_parser(
        "dump",
        help="Download an exposed .git repository",
        description="Download an exposed .git directory from a web server. "
                    "After download, optionally extract/recover source files.",
    )
    dump_parser.add_argument(
        "url",
        help="URL of the exposed .git directory",
    )
    dump_parser.add_argument(
        "--output", "-o",
        help="Output directory (default: dumped/<domain>)",
    )
    dump_parser.add_argument(
        "--threads", "-t",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)",
    )
    dump_parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: 10)",
    )
    dump_parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification",
    )
    dump_parser.add_argument(
        "--skip-objects",
        action="store_true",
        help="Skip downloading individual objects (faster but less complete)",
    )
    dump_parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip confirmation prompts",
    )

    # --- Extract command ---
    extract_parser = subparsers.add_parser(
        "extract",
        help="Recover source files from a dumped .git directory",
        description="Extract and recover source code files from a previously dumped .git directory.",
    )
    extract_parser.add_argument(
        "git_dir",
        help="Path to the dumped .git directory",
    )
    extract_parser.add_argument(
        "--output", "-o",
        help="Output directory (default: parent of git_dir)",
    )

    return parser


def main():
    """Main entry point for GitSheriff CLI."""
    try:
        print_banner()
    except Exception:
        pass

    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    # Dispatch to command handler
    commands = {
        "find": cmd_find,
        "dump": cmd_dump,
        "extract": cmd_extract,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)
    else:
        parser.print_help()
        return 1
