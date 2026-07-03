# GitSheriff

A comprehensive `.git` exposure detection, dumping, recovery, and sensitive data scanning toolkit.

**Author:** [Rahul](https://github.com/1amrahul) | **Website:** [rahulms.qzz.io](https://rahulms.qzz.io)

---

## Features

- **Find** - Scan URLs for exposed `.git` directories and sensitive files
- **Dump** - Download exposed `.git` repositories with recursive object fetching
- **Extract** - Recover source code from dumped `.git` directories
- **Scan** - Scan recovered files for sensitive data (API keys, private keys, passwords, tokens, `.env` secrets, and 100+ pattern categories)
- **Integrated Workflow** - Dump, extract, and scan in a single command with interactive prompts

## Installation

```bash
git clone https://github.com/1amrahul/GitSheriff.git
cd GitSheriff
pip install .
```

### Requirements

- Python 3.8+
- `requests` library

```bash
pip install -r requirements.txt
```

---

## Quick Start - Integrated Workflow

The fastest way to use GitSheriff is the integrated dump-extract-scan workflow. Just one command:

```bash
gitsheriff dump https://example.com/.git
```

This will:
1. **Download** the exposed `.git` repository
2. **Ask** if you want to extract/recover files
3. **Extract** source code automatically
4. **Ask** if you want to scan for sensitive data
5. **Scan** all extracted files for secrets, keys, and credentials

### Full Example Output

```
$ gitsheriff dump https://example.com/.git

  --- Git Repository Dump ---
  Target: https://example.com/.git
  Output: dumped/example_com

  Files: [####################################] 27/27 (100%) ETA: 0s
  Checking for pack files...
  No pack files found
  Discovering objects from references...
  Objects: [########] 8/8 (100%) ETA: 0s

  --- Dump Summary ---
  Output directory: dumped/example_com
  Time elapsed: 2.3s

  ? Do you want to extract/recover files from the dumped .git? [Y/n]:

  --- Git Repository Extraction ---
  Git directory: dumped/example_com/.git
  Output directory: dumped/example_com
  HEAD: a1b2c3d4e5f6...
  Files extracted: 15

  --- Extraction Summary ---
  Files extracted: 15
  Output directory: dumped/example_com
  Time elapsed: 0.5s

  ? Do you want to scan for sensitive data? [Y/n]:

  --- Sensitive Data Scan ---
  Scanning: dumped/example_com
  Files scanned: 15
  Findings: 3

  CRITICAL  [line  12] config/database.yml
            Ruby DATABASE_PASSWORD: ********
  HIGH      [line   3] .env
            AWS_SECRET_ACCESS_KEY: ********
  MEDIUM    [line   5] docker-compose.yml
            Docker Hub token detected

  --- Scan Summary ---
  Total findings: 3
  CRITICAL: 1 | HIGH: 1 | MEDIUM: 1 | LOW: 0
  Results saved to: dumped/example_com/scan_results.json

  Complete! Extracted files are in the 'extracted' subdirectory.
```

### Skip Extraction and Scan (Dump Only)

```bash
gitsheriff dump https://example.com/.git --yes
```

### Extract Later (From Previous Dump)

```bash
gitsheriff extract ./dumped/example_com/.git
```

### Scan a Directory for Sensitive Data

```bash
# Scan a directory
gitsheriff scan ./dumped/example_com

# Scan with minimum severity filter
gitsheriff scan ./dumped/example_com --severity HIGH

# Save results to JSON
gitsheriff scan ./dumped/example_com --output results.json
```

---

## Individual Commands

### Find - Scan for .git Exposure

```bash
# Scan a single URL
gitsheriff find https://example.com

# Scan multiple URLs
gitsheriff find https://site1.com https://site2.com

# Scan from a file
cat urls.txt | gitsheriff find

# Save results to file
gitsheriff find https://example.com --output found.txt
```

### Dump - Download Exposed .git

```bash
# Dump with extraction and scan prompts (default)
gitsheriff dump https://example.com/.git

# Custom output directory
gitsheriff dump https://example.com/.git --output ./my_dump

# Skip object downloading (faster)
gitsheriff dump https://example.com/.git --skip-objects

# Skip all prompts (dump + extract + scan automatically)
gitsheriff dump https://example.com/.git --yes
```

### Extract - Recover Source Files

```bash
# Extract from a dumped .git directory
gitsheriff extract ./dumped/example_com/.git

# Extract to a specific directory
gitsheriff extract ./dumped/example_com/.git --output ./recovered
```

### Scan - Detect Sensitive Data

```bash
# Scan a directory (reports all severities)
gitsheriff scan ./dumped/example_com

# Only report HIGH and CRITICAL findings
gitsheriff scan ./dumped/example_com --severity HIGH

# Save results to JSON file
gitsheriff scan ./dumped/example_com --output scan_results.json
```

---

## Command Line Options

### Global Options

| Option | Description |
|--------|-------------|
| `--version`, `-v` | Show version information |
| `--help`, `-h` | Show help message |

### Find Command

| Option | Description |
|--------|-------------|
| `urls` | URL(s) to scan (positional) |
| `--urls`, `-u` | URL(s) to scan (flag) |
| `--output`, `-o` | Save found URLs to a file |
| `--threads`, `-t` | Number of concurrent threads (default: 10) |
| `--timeout` | HTTP timeout in seconds (default: 10) |
| `--no-verify-ssl` | Disable SSL verification |

### Dump Command

| Option | Description |
|--------|-------------|
| `url` | URL of the exposed .git directory |
| `--output`, `-o` | Output directory (default: `dumped/<domain>`) |
| `--threads`, `-t` | Number of concurrent threads (default: 10) |
| `--timeout` | HTTP timeout in seconds (default: 10) |
| `--no-verify-ssl` | Disable SSL verification |
| `--skip-objects` | Skip downloading individual objects |
| `--yes`, `-y` | Skip all confirmation prompts |

### Extract Command

| Option | Description |
|--------|-------------|
| `git_dir` | Path to the dumped .git directory |
| `--output`, `-o` | Output directory (default: parent of git_dir) |

### Scan Command

| Option | Description |
|--------|-------------|
| `scan_dir` | Directory to scan for sensitive data |
| `--output`, `-o` | Save scan results to a JSON file |
| `--severity`, `-s` | Minimum severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` (default: `LOW`) |

---

## What GitSheriff Detects

### .git Exposure Detection

- Exposed `.git/HEAD` files
- Exposed `.git/config` files
- Exposed `.git/index` files
- Exposed `.git/objects` directories
- Exposed `.git/refs` directories
- Exposed `.git/packed-refs` files
- Exposed `.git/FETCH_HEAD` files
- Exposed `.git/MERGE_HEAD` files

### Sensitive Data Patterns (100+ patterns)

#### CRITICAL - Private Keys & Top Secrets

| Pattern | Example |
|---------|---------|
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` |
| EC Private Key | `-----BEGIN EC PRIVATE KEY-----` |
| DSA Private Key | `-----BEGIN DSA PRIVATE KEY-----` |
| PGP Private Key | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |
| OpenSSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| Generic Private Key | `-----BEGIN PRIVATE KEY-----` |
| .env SECRET_KEY | `SECRET_KEY=django-insecure-...` |
| .env DATABASE_PASSWORD | `DATABASE_PASSWORD=mysecretpass` |
| .env API_SECRET | `API_SECRET=abc123...` |
| .env ENCRYPTION_KEY | `ENCRYPTION_KEY=a1b2c3...` |
| .env PRIVATE_KEY | `PRIVATE_KEY=-----BEGIN...` |
| .env JWT_SECRET | `JWT_SECRET=myjwtsecret...` |

#### HIGH - Cloud Credentials & Service Tokens

| Pattern | Example |
|---------|---------|
| AWS Secret Access Key | `aws_secret_access_key=wJalrXUtnFEMI...` |
| AWS Session Token | `aws_session_token=FwoGZXIvYXdz...` |
| AWS MWS Key | `amzn.mws.9ea900df-...` |
| GitHub Token | `ghp_ABCDEFGHIJKLMNOP...` |
| GitHub OAuth | `gho_ABCDEFGHIJKLMNOP...` |
| GitLab Token | `glpat-ABCDEF.GHIJKLMN...` |
| Slack Bot Token | `xoxb-0000000000-...` |
| Slack User Token | `xoxp-0000000000-...` |
| Slack Webhook | `https://hooks.slack.com/services/T...` |
| Stripe Live Key | `sk_live_ABCDEFGHI...` |
| Stripe Publishable | `pk_live_ABCDEFGHI...` |
| Google API Key | `AIzaSyA1B2C3D4...` |
| Google OAuth | `client_secret:GOCSPX-...` |
| Google Service Account | `"type": "service_account"` |
| Azure Client Secret | `AZURE_CLIENT_SECRET=abc123...` |
| Azure AD Token | `eyJhbGciOiJSUzI1NiIs...` |
| GCP Service Account Key | `GCP_SERVICE_ACCOUNT_KEY={...}` |
| DigitalOcean Token | `DO_TOKEN=dop_v1_abc...` |
| Cloudflare Token | `CLOUDFLARE_TOKEN=abc123...` |
| Fastly Token | `FASTLY_TOKEN=abc123...` |
| npm Token | `npm_ABCDEFGHIJKLMN...` |
| PyPI Token | `pypi-AgEI...` |
| RubyGems Token | `rubygems_abc123...` |
| Heroku API Key | `HEROKU_API_KEY=abc123...` |
| Twilio Account SID | `TWILIO_ACCOUNT_SID=AC...` |
| Twilio Auth Token | `TWILIO_AUTH_TOKEN=abc...` |
| SendGrid API Key | `SG.abc123...` |
| Mailgun API Key | `key-abc123...` |
| NPM Token | `NPM_TOKEN=npm_abc...` |
| npm Automation Token | `NPM_TOKEN=npm_abc123...` |
| Atlassian Token | `atlassian_abcd...` |
| Confluence Token | `CONFLUENCE_TOKEN=abc...` |
| Jira Token | `JIRA_TOKEN=abc...` |
| Zendesk Token | `ZENDESK_TOKEN=abc...` |
| Intercom Token | `INTERCOM_TOKEN=abc...` |
| Algolia Key | `ALGOLIA_API_KEY=abc...` |
| RapidAPI Key | `RAPIDAPI_KEY=abc...` |
| Cloudinary URL | `cloudinary://abc...` |
| Firebase Key | `FIREBASE_KEY=abc...` |
| Sentry DSN | `SENTRY_DSN=https://abc...` |
| Datadog Key | `DD_API_KEY=abc...` |
| New Relic Key | `NEW_RELIC_KEY=abc...` |
| PagerDuty Key | `PAGERDUTY_TOKEN=abc...` |
| Vault Token | `VAULT_TOKEN=abc...` |
| MongoDB URL | `mongodb+srv://user:pass@...` |
| MySQL URL | `mysql://user:pass@...` |
| PostgreSQL URL | `postgres://user:pass@...` |
| Redis URL | `redis://user:pass@...` |

#### HIGH - Database & Service Passwords (.env format)

| Pattern | Example |
|---------|---------|
| REDIS_PASSWORD | `REDIS_PASSWORD=abc123` |
| SMTP_PASSWORD | `SMTP_PASSWORD=abc123` |
| FTP_PASSWORD | `FTP_PASSWORD=abc123` |
| SSH_PASSWORD | `SSH_PASSWORD=abc123` |
| STORAGE_PASSWORD | `STORAGE_PASSWORD=abc123` |
| ELASTICSEARCH_PASSWORD | `ELASTICSEARCH_PASSWORD=abc123` |
| MONGODB_PASSWORD | `MONGODB_PASSWORD=abc123` |
| MYSQL_ROOT_PASSWORD | `MYSQL_ROOT_PASSWORD=abc123` |
| POSTGRES_PASSWORD | `POSTGRES_PASSWORD=abc123` |
| NGINX_PASSWORD | `NGINX_PASSWORD=abc123` |
| KAFKA_PASSWORD | `KAFKA_PASSWORD=abc123` |

#### MEDIUM - API Keys & Auth Tokens

| Pattern | Example |
|---------|---------|
| Generic API Key | `api_key = "abc123..."` |
| Generic API Secret | `api_secret: "abc123..."` |
| Access Token | `access_token = "abc123..."` |
| Bearer Token | `Authorization: Bearer abc...` |
| Basic Auth | `Authorization: Basic base64...` |
| Auth Token | `auth_token: "abc123..."` |
| Private Key (inline) | `private_key = "abc123..."` |

#### MEDIUM - .env Variable Name Patterns

| Pattern | Example |
|---------|---------|
| PASSWORD variable | `DB_PASSWORD=abc123` |
| SECRET variable | `APP_SECRET=abc123` |
| TOKEN variable | `API_TOKEN=abc123` |
| CREDENTIAL variable | `AWS_CREDENTIAL=abc123` |
| AUTH variable | `AUTH_KEY=abc123` |
| KEY variable | `ENCRYPTION_KEY=abc123` |

#### MEDIUM - Docker / CI-CD Secrets

| Pattern | Example |
|---------|---------|
| Docker Hub Token | `DOCKER_PASSWORD=abc...` |
| Docker Config | `"auth": "base64..."` |
| Jenkins Token | `JENKINS_TOKEN=abc...` |
| CircleCI Token | `CIRCLE_TOKEN=abc...` |
| Travis CI Token | `TRAVIS_TOKEN=abc...` |
| GitHub Actions Secret | `SECRET_KEY: abc...` |

#### MEDIUM - Kubernetes / Helm / IaC

| Pattern | Example |
|---------|---------|
| K8s Token | `K8S_TOKEN=abc...` |
| Kubeconfig | `password: abc123` |
| Helm Secret | `HELM_SECRET=abc...` |
| Ansible Vault | `$ANSIBLE_VAULT;1.1` |
| Terraform Cloud | `TF_TOKEN=abc...` |
| Terraform S3 Backend | `secret_key = "abc..."` |
| Pulumi Token | `PULUMI_ACCESS_TOKEN=abc...` |

#### MEDIUM - Crypto & Passphrases

| Pattern | Example |
|---------|---------|
| SSH Passphrase | `SSH_PASSPHRASE=abc...` |
| PGP Passphrase | `PGP_PASSPHRASE=abc...` |
| SSL Certificate Password | `SSL_PASSWORD=abc...` |
| Key Passphrase | `KEY_PASSPHRASE=abc...` |
| Keystore Password | `KEYSTORE_PASSWORD=abc...` |

#### MEDIUM - Social Media & Payment

| Pattern | Example |
|---------|---------|
| Facebook Token | `FB_TOKEN=abc...` |
| Twitter/X Token | `TWITTER_TOKEN=abc...` |
| Instagram Token | `INSTAGRAM_TOKEN=abc...` |
| LinkedIn Token | `LINKEDIN_TOKEN=abc...` |
| Microsoft Graph | `MS_GRAPH_TOKEN=abc...` |
| PayPal Client ID | `PAYPAL_CLIENT_ID=abc...` |
| Square Access Token | `SQUARE_ACCESS_TOKEN=abc...` |
| Braintree Token | `BRAINTREE_TOKEN=abc...` |

#### LOW - Informational

| Pattern | Example |
|---------|---------|
| Email addresses | `user@example.com` |
| Hardcoded IPs | `192.168.1.1:8080` |
| Internal hostnames | `db.internal.corp` |
| Debug mode | `DEBUG=True` |
| Default credentials | `admin:admin` |
| Base64 encoded secrets | `key="base64encoded..."` |

---

## How It Works

### Detection
GitSheriff checks for common `.git` files that should not be publicly accessible:
- `/` - Root `.git` directory
- `/HEAD` - Points to current branch
- `/config` - Repository configuration
- `/index` - Staging area index
- `/objects/` - Git object database

### Dumping
The dumper recursively downloads:
- Standard git files (HEAD, config, index, refs)
- Pack files (`.pack` and `.idx`)
- Loose objects discovered from references
- Binary file hash extraction
- Support for concurrent multi-threaded downloads

### Extraction
The extractor recovers:
- Source code from HEAD and other branches
- File permissions and executable bits
- Symlinks
- Directory structure

### Sensitive Data Scanning
The scanner:
- Recursively scans all files in the extracted directory
- Applies 100+ regex patterns organized by severity
- Skips binary files automatically
- Limits file size (1MB) and line length (2000 chars) for performance
- Outputs findings with file paths, line numbers, and matched values
- Saves results to JSON for further analysis
- Groups and counts findings by severity and pattern

---

## Project Structure

```
GitSheriff/
├── gitsheriff/
│   ├── __init__.py      # Version and metadata
│   ├── __main__.py      # Entry point
│   ├── cli.py           # Command line interface
│   ├── utils.py         # UI helpers and utilities
│   ├── finder.py        # .git exposure detection
│   ├── dumper.py        # .git repository dumper
│   ├── extractor.py     # File recovery from .git
│   └── scanner.py       # Sensitive data detection (100+ patterns)
├── setup.py             # Package setup
├── requirements.txt     # Dependencies
├── LICENSE              # MIT License
└── README.md            # This file
```

---

## Error Handling

GitSheriff includes comprehensive error handling for:
- Network timeouts and connection errors
- SSL/TLS certificate issues
- File permission errors
- Disk space issues
- Corrupted git objects
- Invalid repository structures
- Binary file detection (skipped during scanning)
- Large file handling (size limits enforced)

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The author is not responsible for any misuse of this tool. Always obtain proper authorization before scanning or dumping repositories you do not own.

---

**Author:** [Rahul](https://github.com/1amrahul) | **Website:** [rahulms.qzz.io](https://rahulms.qzz.io)
