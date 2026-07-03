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

### Requirements

- Python 3.8+
- `requests` library

```bash
pip install -r requirements.txt
```

---

## Quick Start - Integrated Workflow

The fastest way to use GitSheriff is the integrated dump-and-extract workflow. Just one command:

```bash
gitsheriff dump https://example.com/.git
```

This will:
1. **Download** the exposed `.git` repository
2. **Ask** if you want to extract/recover files
3. **Extract** source code automatically

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

  Complete! Your extracted files are in the 'extracted' subdirectory.
```

### Skip Extraction (Dump Only)

```bash
gitsheriff dump https://example.com/.git --yes
```

### Extract Later (From Previous Dump)

```bash
gitsheriff extract ./dumped/example_com/.git
```

---

## Individual Commands

### Find - Scan for .git Exposure

```bash
# Scan a single URL
gitsheriff find --urls https://example.com

# Scan multiple URLs
gitsheriff find --urls https://site1.com https://site2.com

# Scan from a file
cat urls.txt | gitsheriff find

# Save results to file
gitsheriff find --urls https://example.com --output found.txt
```

### Dump - Download Exposed .git

```bash
# Dump with extraction prompt (default)
gitsheriff dump https://example.com/.git

# Custom output directory
gitsheriff dump https://example.com/.git --output ./my_dump

# Skip object downloading (faster)
gitsheriff dump https://example.com/.git --skip-objects
```

### Extract - Recover Source Files

```bash
# Extract from a dumped .git directory
gitsheriff extract ./dumped/example_com/.git

# Extract to a specific directory
gitsheriff extract ./dumped/example_com/.git --output ./recovered
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

---

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
│   └── extractor.py     # File recovery from .git
├── setup.py             # Package setup
├── requirements.txt     # Dependencies
├── LICENSE              # MIT License
└── README.md            # This file
```

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The author is not responsible for any misuse of this tool.

---

**Author:** [Rahul](https://github.com/1amrahul) | **Website:** [rahulms.qzz.io](https://rahulms.qzz.io)
