"""
GitSheriff - Sensitive data scanner module.

Scans extracted/recovered files for sensitive information using
regex-based pattern matching. Detects secrets, passwords, API keys,
private keys, tokens, connection strings, and other credentials.
"""

import os
import re
import json
import time
from collections import defaultdict

from .utils import (
    Colors, print_info, print_success, print_warning, print_error,
    print_section, ProgressBar, safe_makedirs,
)


# ---------------------------------------------------------------------------
# Pattern definitions: (name, severity, regex_pattern, description)
# ---------------------------------------------------------------------------
PATTERNS = [
    # --- High severity ---
    (
        "AWS Access Key",
        "HIGH",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "AWS IAM access key ID",
    ),
    (
        "AWS Secret Key",
        "HIGH",
        re.compile(r"(?:aws_secret_access_key|aws_secret_key|secret_key)[\s:=]+['\"]?([A-Za-z0-9/+=]{40})['\"]?", re.IGNORECASE),
        "AWS IAM secret access key",
    ),
    (
        "GitHub Token",
        "HIGH",
        re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"),
        "GitHub personal access token or fine-grained token",
    ),
    (
        "GitLab Token",
        "HIGH",
        re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
        "GitLab personal access token",
    ),
    (
        "Slack Token",
        "HIGH",
        re.compile(r"xox[bpsa]-[0-9]{10,}-[0-9a-zA-Z\-]+"),
        "Slack bot/user/app token",
    ),
    (
        "Slack Webhook",
        "HIGH",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"),
        "Slack incoming webhook URL",
    ),
    (
        "Stripe Key",
        "HIGH",
        re.compile(r"sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}"),
        "Stripe API live key",
    ),
    (
        "Stripe Secret Key",
        "HIGH",
        re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        "Stripe secret key (live mode)",
    ),
    (
        "Google API Key",
        "HIGH",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "Google API key",
    ),
    (
        "Heroku API Key",
        "HIGH",
        re.compile(r"(?:heroku_api_key|HEROKU_API_KEY)[\s:=]+['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?", re.IGNORECASE),
        "Heroku API key",
    ),
    (
        "Private Key (RSA)",
        "CRITICAL",
        re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        "RSA private key (PEM format)",
    ),
    (
        "Private Key (EC)",
        "CRITICAL",
        re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
        "Elliptic curve private key (PEM format)",
    ),
    (
        "Private Key (Generic)",
        "CRITICAL",
        re.compile(r"-----BEGIN PRIVATE KEY-----"),
        "Generic private key (PKCS#8 PEM format)",
    ),
    (
        "PGP Private Key",
        "CRITICAL",
        re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        "PGP/GPG private key block",
    ),
    (
        "DSA Private Key",
        "CRITICAL",
        re.compile(r"-----BEGIN DSA PRIVATE KEY-----"),
        "DSA private key (PEM format)",
    ),
    (
        "OpenSSH Private Key",
        "CRITICAL",
        re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        "OpenSSH private key",
    ),

    # --- Medium severity ---
    (
        "JWT Token",
        "MEDIUM",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
        "JSON Web Token (JWT)",
    ),
    (
        "Generic API Key",
        "MEDIUM",
        re.compile(r"(?:api_key|apikey|api-key|API_KEY|APIKEY|API_KEY)[\s:=]+['\"]?([A-Za-z0-9\-_]{20,})['\"]?", re.IGNORECASE),
        "Generic API key",
    ),
    (
        "Bearer Token",
        "MEDIUM",
        re.compile(r"(?:bearer|token|auth)[\s:=]+['\"]?Bearer\s+[A-Za-z0-9\-_.]+", re.IGNORECASE),
        "Bearer authentication token",
    ),
    (
        "Basic Auth Header",
        "MEDIUM",
        re.compile(r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]+"),
        "Basic authentication header (base64 encoded)",
    ),
    (
        "Password in Code",
        "MEDIUM",
        re.compile(r"(?:password|passwd|pwd)[\s:=]+['\"]([^'\"]{6,})['\"]", re.IGNORECASE),
        "Password hardcoded in source code",
    ),
    (
        "Password Assignment",
        "MEDIUM",
        re.compile(r"(?:password|passwd|pwd)\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE),
        "Password assigned to a variable",
    ),
    (
        "Database URL",
        "MEDIUM",
        re.compile(r"(?:mysql|postgres|postgresql|mongodb|redis|sqlite|amqp|mssql)://[^\s\"']+:[^\s\"']+@[^\s\"']+"),
        "Database connection string with credentials",
    ),
    (
        "MySQL URL",
        "MEDIUM",
        re.compile(r"mysql://[^:\s]+:[^@\s]+@[^/\s]+/\S+"),
        "MySQL connection URL with credentials",
    ),
    (
        "PostgreSQL URL",
        "MEDIUM",
        re.compile(r"postgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]+/\S+"),
        "PostgreSQL connection URL with credentials",
    ),
    (
        "MongoDB URL",
        "MEDIUM",
        re.compile(r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^/\s]+/\S+"),
        "MongoDB connection URL with credentials",
    ),
    (
        "Redis URL",
        "MEDIUM",
        re.compile(r"redis://[^:\s]*:[^@\s]+@[^\s]+"),
        "Redis connection URL with credentials",
    ),
    (
        "FTP URL",
        "MEDIUM",
        re.compile(r"ftp://[^:\s]+:[^@\s]+@[^\s]+"),
        "FTP URL with credentials",
    ),
    (
        "SSH Connection String",
        "MEDIUM",
        re.compile(r"ssh://[^:\s]+:[^@\s]+@[^\s]+"),
        "SSH connection string with password",
    ),
    (
        "SMTP Credentials",
        "MEDIUM",
        re.compile(r"(?:smtp|mail)[\s:=]+[^\s]*://[^:\s]+:[^@\s]+@[^\s]+"),
        "SMTP connection with credentials",
    ),
    (
        "Twitch Token",
        "MEDIUM",
        re.compile(r"oauth:[a-z0-9]{30}"),
        "Twitch OAuth token",
    ),
    (
        "Azure Storage Account Key",
        "MEDIUM",
        re.compile(r"AccountKey=[A-Za-z0-9+/=]{44,}"),
        "Azure Storage account key",
    ),
    (
        "Azure Connection String",
        "MEDIUM",
        re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+"),
        "Azure Storage connection string",
    ),

    # --- Low severity ---
    (
        "Email Address",
        "LOW",
        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        "Email address (potential credential)",
    ),
    (
        "IP Address",
        "LOW",
        re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
        "IP address",
    ),
    (
        "AWS ARN",
        "LOW",
        re.compile(r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[a-zA-Z0-9\-_/]+"),
        "AWS Amazon Resource Name",
    ),
    (
        "Terraform API Token",
        "LOW",
        re.compile(r"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-_]{67}"),
        "Terraform Cloud API token",
    ),
]

# Severity display colors
SEVERITY_COLORS = {
    "CRITICAL": Colors.RED + Colors.BOLD,
    "HIGH": Colors.RED,
    "MEDIUM": Colors.YELLOW,
    "LOW": Colors.BLUE,
}

# Skip these file extensions (binary / media / irrelevant)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".flv",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".dat",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pyc", ".pyo", ".class",
    ".o", ".a",
    ".db", ".sqlite", ".sqlite3",
}

# Max file size to scan (10 MB)
MAX_FILE_SIZE = 10 * 1024 * 1024


class Finding:
    """A single sensitive data finding."""

    def __init__(self, file_path, line_number, pattern_name, severity,
                 matched_text, description):
        self.file_path = file_path
        self.line_number = line_number
        self.pattern_name = pattern_name
        self.severity = severity
        self.matched_text = matched_text
        self.description = description

    def to_dict(self):
        return {
            "file": self.file_path,
            "line": self.line_number,
            "pattern": self.pattern_name,
            "severity": self.severity,
            "match": self.matched_text[:200],  # Truncate long matches
            "description": self.description,
        }

    def __str__(self):
        color = SEVERITY_COLORS.get(self.severity, "")
        try:
            return (
                f"  {color}[{self.severity}]{Colors.END} "
                f"{self.pattern_name} in {self.file_path}:{self.line_number}\n"
                f"    Match: {self.matched_text[:120]}"
            )
        except UnicodeEncodeError:
            return (
                f"  [{self.severity}] "
                f"{self.pattern_name} in {self.file_path}:{self.line_number}\n"
                f"    Match: {self.matched_text[:120]}"
            )


class Scanner:
    """Scans files for sensitive data using regex patterns."""

    def __init__(self, scan_dir, output_file=None, min_severity=None):
        """
        Args:
            scan_dir: Directory to scan for sensitive data.
            output_file: File to save scan results (JSON format).
            min_severity: Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW).
        """
        self.scan_dir = os.path.abspath(scan_dir)
        self.output_file = output_file
        self.min_severity = min_severity or "LOW"

        # Severity ordering for filtering
        self._severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

        # Results
        self.findings = []
        self.files_scanned = 0
        self.files_skipped = 0

    def _should_skip_file(self, file_path):
        """Check if a file should be skipped."""
        _, ext = os.path.splitext(file_path.lower())
        if ext in SKIP_EXTENSIONS:
            return True
        # Skip hidden files (but keep .env, .htpasswd, etc.)
        basename = os.path.basename(file_path)
        if basename.startswith(".") and basename not in (
            ".env", ".htpasswd", ".htaccess", ".netrc",
            ".git-credentials", ".npmrc", ".dockerenv",
        ):
            return True
        return False

    def _is_severity_above(self, severity):
        """Check if severity meets the minimum threshold."""
        return self._severity_order.get(severity, 99) <= self._severity_order.get(
            self.min_severity, 99
        )

    def _scan_file(self, file_path):
        """Scan a single file for sensitive patterns.

        Returns:
            List of Finding objects.
        """
        findings = []

        # Get relative path for display
        try:
            rel_path = os.path.relpath(file_path, self.scan_dir)
        except ValueError:
            rel_path = file_path

        # Check file size
        try:
            file_size = os.path.getsize(file_path)
            if file_size > MAX_FILE_SIZE:
                self.files_skipped += 1
                return findings
        except OSError:
            self.files_skipped += 1
            return findings

        # Read file content
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            self.files_skipped += 1
            return findings

        if not content:
            return findings

        # Check each pattern
        lines = content.split("\n")
        for pattern_name, severity, regex, description in PATTERNS:
            if not self._is_severity_above(severity):
                continue

            for i, line in enumerate(lines, 1):
                matches = regex.findall(line)
                for match in matches:
                    match_text = match if isinstance(match, str) else str(match)
                    findings.append(Finding(
                        file_path=rel_path,
                        line_number=i,
                        pattern_name=pattern_name,
                        severity=severity,
                        matched_text=match_text.strip(),
                        description=description,
                    ))

        self.files_scanned += 1
        return findings

    def scan(self):
        """Execute the scan on all files in the target directory.

        Returns:
            Tuple of (success_bool, findings_list).
        """
        print_section("Sensitive Data Scan")
        print_info(f"Target: {self.scan_dir}")
        if self.output_file:
            print_info(f"Output: {self.output_file}")
        print()

        start_time = time.time()

        if not os.path.isdir(self.scan_dir):
            print_error(f"Directory not found: {self.scan_dir}")
            return False, []

        # Collect all files to scan
        all_files = []
        for root, dirs, files in os.walk(self.scan_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                if not self._should_skip_file(fpath):
                    all_files.append(fpath)

        print_info(f"Found {len(all_files)} file(s) to scan")
        print()

        # Scan files
        progress = ProgressBar(len(all_files), desc="Scanning")

        for fpath in all_files:
            file_findings = self._scan_file(fpath)
            self.findings.extend(file_findings)
            progress.update()

        progress.finish()

        # Sort findings by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.findings.sort(key=lambda f: severity_order.get(f.severity, 99))

        # Display results
        elapsed = time.time() - start_time

        if not self.findings:
            print_success("No sensitive data found.")
        else:
            # Group by severity
            by_severity = defaultdict(list)
            for f in self.findings:
                by_severity[f.severity].append(f)

            print_section("Scan Results")

            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if severity not in by_severity:
                    continue
                items = by_severity[severity]
                color = SEVERITY_COLORS.get(severity, "")
                try:
                    print(f"\n  {color}{Colors.BOLD}{severity} ({len(items)} finding(s)):{Colors.END}")
                except UnicodeEncodeError:
                    print(f"\n  {severity} ({len(items)} finding(s)):")

                for item in items:
                    print(str(item))
                    print()

        # Summary
        print_section("Scan Summary")
        print_success(f"Files scanned: {self.files_scanned}")
        print_success(f"Files skipped: {self.files_skipped}")

        if self.findings:
            by_severity = defaultdict(int)
            for f in self.findings:
                by_severity[f.severity] += 1
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if sev in by_severity:
                    color = SEVERITY_COLORS.get(sev, "")
                    try:
                        print(f"  {color}[{sev}]{Colors.END}: {by_severity[sev]}")
                    except UnicodeEncodeError:
                        print(f"  [{sev}]: {by_severity[sev]}")

        print_success(f"Time elapsed: {elapsed:.1f}s")

        # Save results to file
        if self.output_file:
            self._save_results()

        return True, self.findings

    def _save_results(self):
        """Save scan results to a JSON file."""
        try:
            safe_makedirs(os.path.dirname(self.output_file) or ".")

            report = {
                "tool": "GitSheriff Scanner",
                "scan_dir": self.scan_dir,
                "total_findings": len(self.findings),
                "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped,
                "findings": [f.to_dict() for f in self.findings],
            }

            with open(self.output_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            print_success(f"Results saved to {self.output_file}")

        except Exception as e:
            print_error(f"Failed to save results: {e}")
