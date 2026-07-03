# GitSheriff

A comprehensive .git exposure detection, dumping, and recovery toolkit.

**Author:** [Rahul](https://github.com/1amrahul) | **Website:** [rahulms.qzz.io](https://rahulms.qzz.io)

---

## Features

- **Find** - Scan URLs for exposed `.git` directories and sensitive files
- **Dump** - Download exposed `.git` repositories with recursive object fetching
- **Extract** - Recover source code from dumped `.git` directories
- **Integrated Workflow** - After dumping, automatically prompt to extract files in the same session

## Installation

```bash
git clone https://github.com/1amrahul/GitSheriff.git
cd GitSheriff
pip install .
```

Or install directly from PyPI (if published):

```bash
pip install gitsheriff
```

### Requirements

- Python 3.8+
- `requests` library

```bash
pip install -r requirements.txt
```

## Usage

### Scan for .git Exposure

```bash
# Scan a single URL
python -m gitsheriff find --urls https://example.com

# Scan multiple URLs
python -m gitsheriff find --urls https://site1.com https://site2.com

# Scan from a file
cat urls.txt | python -m gitsheriff find

# Save results to file
python -m gitsheriff find --urls https://example.com --output found.txt
```

### Dump an Exposed .git Repository

```bash
# Dump with automatic extraction prompt
python -m gitsheriff dump https://example.com/.git

# Dump without extraction
python -m gitsheriff dump https://example.com/.git --yes

# Custom output directory
python -m gitsheriff dump https://example.com/.git --output ./my_dump

# Skip object downloading (faster)
python -m gitsheriff dump https://example.com/.git --skip-objects
```

### Extract from a Dumped .git

```bash
# Extract files from a dumped .git directory
python -m gitsheriff extract ./dumped/example_com/.git

# Extract to a specific directory
python -m gitsheriff extract ./dumped/example_com/.git --output ./recovered
```

## Integrated Workflow

GitSheriff provides a seamless dump-and-extract workflow:

1. **Dump** an exposed `.git` repository
2. After successful dump, **automatically prompt** to extract/recover files
3. Extract source code from the dumped repository

```bash
$ python -m gitsheriff dump https://example.com/.git

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

  Complete! Your extracted files are in the 'extracted' subdirectory.
```

## Command Line Options

### Global Options

| Option | Description |
|--------|-------------|
| `--version`, `-v` | Show version information |
| `--help`, `-h` | Show help message |

### Find Command

| Option | Description |
|--------|-------------|
| `--urls`, `-u` | URL(s) to scan |
| `--output`, `-o` | Save found URLs to a file |
| `--threads`, `-t` | Number of concurrent threads (default: 10) |
| `--timeout` | HTTP timeout in seconds (default: 10) |
| `--no-verify-ssl` | Disable SSL verification |

### Dump Command

| Option | Description |
|--------|-------------|
| `url` | URL of the exposed .git directory |
| `--output`, `-o` | Output directory |
| `--threads`, `-t` | Number of concurrent threads (default: 10) |
| `--timeout` | HTTP timeout in seconds (default: 10) |
| `--no-verify-ssl` | Disable SSL verification |
| `--skip-objects` | Skip downloading individual objects |
| `--yes`, `-y` | Skip confirmation prompts |

### Extract Command

| Option | Description |
|--------|-------------|
| `git_dir` | Path to the dumped .git directory |
| `--output`, `-o` | Output directory |

## Security Considerations

This tool is designed for:
- **Authorized security assessments**
- **Penetration testing**
- **Bug bounty programs**
- **Security research**

**Do not use this tool for unauthorized access to systems you do not own or have permission to test.**

## What GitSheriff Detects

- Exposed `.git/HEAD` files
- Exposed `.git/config` files
- Exposed `.git/index` files
- Exposed `.git/objects` directories
- Exposed `.git/refs` directories
- Exposed `.git/packed-refs` files
- Exposed `.git/FETCH_HEAD` files
- Exposed `.git/MERGE_HEAD` files

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
- Support for concurrent multi-threaded downloads

### Extraction
The extractor recovers:
- Source code from HEAD and other branches
- File permissions and executable bits
- Symlinks
- Directory structure

## Error Handling

GitSheriff includes comprehensive error handling for:
- Network timeouts and connection errors
- SSL/TLS certificate issues
- File permission errors
- Disk space issues
- Corrupted git objects
- Invalid repository structures

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
│   └── extractor.py     # File recovery from .git
├── setup.py             # Package setup
├── requirements.txt     # Dependencies
├── LICENSE              # MIT License
└── README.md            # This file
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The author is not responsible for any misuse of this tool.

---

**Author:** [Rahul](https://github.com/1amrahul) | **Website:** [rahulms.qzz.io](https://rahulms.qzz.io)
