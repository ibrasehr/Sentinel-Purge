# Sentinel-Purge

> **NIST SP 800-88 Compliant Data Sanitization & Forensic Verification Engine**

Sentinel-Purge is a standalone Python framework built for secure file sanitization, directory table metadata destruction, and post-wipe forensic verification. It prevents recovery of sensitive file artifacts from underlying storage blocks, scrambles directory entries, and generates signed JSON certificates of destruction for audit compliance.

---

### Core Capabilities

* **NIST SP 800-88 Rev. 1 Alignment**: Executes logical overwrite pipelines including NIST Clear (1-Pass random/zero overwrite), DoD 5220.22-M (3-Pass), and fixed pattern passes.
* **Target Scope Guardrails**: Analyzes target paths before execution to block destructive operations against system directories (`C:\Windows`, `/bin`, `/boot`, `/etc`) and physical drive mount points.
* **Pre-Wipe Chain of Custody**: Computes SHA-256 cryptographic hashes via 4KB stream buffers prior to file mutation to establish pre-sanitization state proof.
* **Entropy-Based Verification Engine**: Samples post-wipe byte distributions across header, body, and tail offset zones, calculating Shannon Entropy ($H \ge 7.2\text{ bits/byte}$) to confirm random data transformation.
* **Directory Metadata Obfuscation**: Scrambles original filenames to random 16-character strings, truncates file sizes to zero bytes, and unlinks filesystem nodes to mitigate metadata recovery.
* **Structured Audit Certificates**: Emits JSON certificates detailing operator metadata, execution parameters, pre-wipe hashes, and post-wipe entropy scores.
* **Secret-Key Authorized Operations**: Supports authenticated Clear and Purge execution paths backed by HMAC secret-key validation and append-only audit logging.
* **CLI & REST API Interfaces**: Includes an interactive CLI (`erasure.cli`) alongside a lightweight Flask management server (`erasure.server`).

---

### Repository Layout

```text
sentinel-purge/
├── erasure/                   # Core sanitization & verification package
│   ├── __init__.py
│   ├── __main__.py            # CLI entry point (`python -m erasure`)
│   ├── audit_trail.py         # Structured audit logging & persistence
│   ├── cli.py                 # Interactive & automated CLI entrypoint
│   ├── device_detection.py    # Path inspection & system guardrails
│   ├── handler.py             # Authenticated Clear & Purge handlers
│   ├── methods.py             # Binary pattern generators & overwrite passes
│   ├── sanitizer.py           # Sanitization orchestrator & certificate generator
│   ├── server.py              # Flask REST server implementation
│   ├── static/                # Web UI static assets
│   └── verification.py        # Shannon Entropy & binary sample verification
├── tests/
│   └── erasure/               # Unit test suite (28 tests)
│       ├── test_handler.py
│       ├── test_methods.py
│       ├── test_sanitizer.py
│       └── test_verification.py
├── .gitignore
├── pytest.ini                 # Test suite configuration
├── requirements.txt           # Project dependencies
└── README.md
```

---

### Setup & Requirements

#### Prerequisites
- Python 3.10+ (Tested on Python 3.12)
- `pip` package manager

#### Dependency Installation
```bash
pip install -r requirements.txt
```

---

### Running Tests

Execute the 28-test suite across sanitization, safety guardrail, and verification routines:

```bash
# Run via pytest
pytest tests/erasure/ -v

# Run via unittest
python -m unittest discover -s tests/erasure -p "test_*.py" -v
```

---

### Usage Guide

#### 1. Command Line Interface

```bash
# Interactive mode
python -m erasure

# Direct execution commands
python -m erasure sanitize /path/to/target.dat --method NIST_800_88_CLEAR --operator "SecOps Engineer"
python -m erasure inspect /path/to/target.dat
python -m erasure validate-target /path/to/target.dat
```

#### 2. Python Programmatic API

```python
from erasure.sanitizer import sanitize_file
from erasure.methods import SanitizationAlgorithm

# Execute NIST Clear pipeline
result = sanitize_file(
    target_path="confidential_document.pdf",
    algorithm=SanitizationAlgorithm.NIST_800_88_CLEAR,
    operator_name="SecOps Engineer",
    certificates_dir="certificates",
)

if result.status == "completed":
    print(f"[+] Target sanitized: {result.original_filename}")
    print(f"    Pre-wipe SHA-256: {result.pre_wipe_sha256}")
    print(f"    Certificate generated: {result.certificate_path}")
else:
    print(f"[-] Operation failed: {result.error_message}")
```

#### 3. REST API Server

```bash
# Start management server on port 5000
python -m erasure serve --port 5000
```

---

### Operational Note

This tool implements user-space file overwriting and pattern sanitization aligned with NIST SP 800-88 Rev. 1 guidelines (Clear operations). On modern solid-state media (SSDs/NVMe), logical sector overwriting handles target cluster contents at the file-system layer. Complete physical block sanitization covering over-provisioned space requires drive-level ATA/NVMe Purge firmware commands.
