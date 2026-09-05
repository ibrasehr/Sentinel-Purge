# Sentinel-Purge 🛡️

> **NIST SP 800-88 Compliant Secure Data Sanitization & Forensic Verification Engine**

Sentinel-Purge is a standalone, forensic-grade, memory-efficient data sanitization and post-wipe verification framework. It reliably overwrites sensitive file artifacts, prevents residual data recovery from underlying storage clusters, scrambles directory table metadata, and emits tamper-evident audit certificates of destruction.

---

## 🚀 Key Features

- **NIST SP 800-88 Rev. 1 Alignment**: Implements certified logical overwrite algorithms (NIST Clear 1-Pass, DoD 5220.22-M 3-Pass, Fixed Zero-Fill).
- **Target Scope Validation & Guardrails**: Automatically inspects targets and blocks destructive operations on OS directories (`C:\Windows`, `/bin`, `/boot`, `/etc`, etc.) and physical disk raw identifiers.
- **Pre-Wipe Forensic Hashing**: Computes SHA-256 cryptographic hashes via 4KB streaming buffers before any mutation for immutable chain-of-custody proof.
- **Independent Verification Engine**: Multi-zone binary sampling (Header, Body, Tail) with Shannon entropy calculations ($H \ge 7.2\text{ bits/byte}$) to detect any residual unwiped data.
- **Directory Table Metadata Scrambling**: Renames files to cryptographically random 16-character strings, truncates to 0 bytes, and safely unlinks filesystem entries.
- **Tamper-Evident Forensic Certificates**: Emits structured JSON certificates of destruction containing operator metadata, pre-wipe hashes, and verification telemetry.
- **Secret-Key Authorized Operations**: Supports authorized Clear and Purge workflows protected by HMAC/secret-key verification and live audit trail recording.
- **CLI & REST API Server**: Provides a complete command-line interface (`erasure.cli`) and Flask orchestration server (`erasure.server`).

---

## 📁 Repository Structure

```
sentinel-purge/
├── erasure/                   # Core sanitization & verification package
│   ├── __init__.py
│   ├── __main__.py            # CLI entry point (`python -m erasure`)
│   ├── audit_trail.py         # Structured audit logging & persistence
│   ├── cli.py                 # Interactive & automated CLI tool
│   ├── device_detection.py    # Target scope validator & media guardrails
│   ├── handler.py             # Authorized Clear & Purge handlers
│   ├── methods.py             # Binary pattern generators & overwrite passes
│   ├── sanitizer.py           # End-to-end sanitization pipeline & certificates
│   ├── server.py              # Lightweight Flask REST server
│   ├── static/                # Static web UI assets
│   └── verification.py        # Shannon entropy & binary sample verification
├── tests/
│   └── erasure/               # Comprehensive unit test suite (28 tests)
│       ├── test_handler.py
│       ├── test_methods.py
│       ├── test_sanitizer.py
│       └── test_verification.py
├── .gitignore
├── pytest.ini                 # Pytest runner configuration
├── requirements.txt           # Project dependencies
└── README.md
```

---

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.10+ (Recommended: Python 3.12)
- `pip`

### Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🧪 Running Tests

Run the complete test suite across all erasure and verification components:

```bash
# Run tests with pytest
pytest tests/erasure/ -v

# Or run using Python's built-in unittest runner
python -m unittest discover -s tests/erasure -p "test_*.py" -v
```

---

## 💻 Usage

### 1. Command Line Interface (CLI)

```bash
# Run the interactive CLI
python -m erasure

# Or invoke specific subcommands
python -m erasure sanitize /path/to/target.dat --method NIST_800_88_CLEAR --operator "Investigator"
python -m erasure inspect /path/to/target.dat
python -m erasure validate-target /path/to/target.dat
```

### 2. Python API

```python
from erasure.sanitizer import sanitize_file
from erasure.methods import SanitizationAlgorithm

# Execute NIST Clear sanitization
result = sanitize_file(
    target_path="confidential_document.pdf",
    algorithm=SanitizationAlgorithm.NIST_800_88_CLEAR,
    operator_name="SecOps Engineer",
    certificates_dir="certificates",
)

if result.status == "completed":
    print(f"[+] File securely sanitized: {result.original_filename}")
    print(f"    Pre-wipe SHA-256: {result.pre_wipe_sha256}")
    print(f"    Certificate: {result.certificate_path}")
else:
    print(f"[-] Sanitization failed: {result.error_message}")
```

### 3. REST API Server

```bash
# Launch the API server
python -m erasure serve --port 5000
```

---

## 📜 Standards Disclaimer

This project implements procedural recommendations from **NIST SP 800-88 Rev. 1** (*Guidelines for Media Sanitization*). For flash storage (SSDs/NVMe), user-space file overwriting operates at the logical cluster level; full hardware-level sanitization on flash drives should utilize firmware-level ATA/NVMe Secure Erase.
