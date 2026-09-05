# Sentinel-Purge — Secure Data Sanitization Module

> **Target Specification:** NIST SP 800-88 Rev. 1 Guidelines & Forensic Chain-of-Custody Compliance

---

## 1. Overview & Architecture

The **Sentinel-Purge Module** provides a forensic-grade, memory-efficient data sanitization and post-wipe verification pipeline. It is designed to reliably overwrite sensitive file artifacts, prevent residual data recovery from underlying storage clusters, scramble directory table metadata, and emit tamper-evident audit certificates.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       Sanitization Pipeline Flow                        │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
                   [ 1. Target Scope Check ]
               (device_detection.py: Protect OS & Root)
                                   │
                                   ▼
                [ 2. Pre-Wipe Forensic Hashing ]
               (Compute SHA-256 via 4KB Chunks)
                                   │
                                   ▼
             [ 3. Chunked Binary Pattern Overwrite ]
            (methods.py: NIST Clear / DoD 3-Pass + fsync)
                                   │
                                   ▼
            [ 4. Independent Binary Verification ]
           (verification.py: Header/Body/Tail Sampling)
                                   │
                                   ▼
              [ 5. Metadata Scrambling & Deletion ]
             (16-char Random Rename + Truncate + Unlink)
                                   │
                                   ▼
              [ 6. Forensic Certificate Generation ]
             (Emit data-schema.md Compliant JSON Report)
```

---

## 2. Standards Mapping (NIST SP 800-88 Rev. 1)

This module aligns with procedural sanitization recommendations established in **NIST Special Publication 800-88 Revision 1** (*Guidelines for Media Sanitization*).

| NIST SP 800-88 Category | Implementation Status | Technical Mechanism | Scope & Limitations |
|:---|:---:|:---|:---|
| **Clear** (Logical Overwrite) | **Implemented** | 1-pass binary overwrite using cryptographically secure pseudo-random bytes (`os.urandom`) with enforced OS buffer synchronization (`os.fsync`). | Overwrites addressable logical file blocks in user-space. Mitigates basic forensic recovery tools. |
| **Purge** (Low-Level Sanitization) | **Documented / Out of Scope** | *Out of Scope for User-Space Prototype.* Real firmware Purge requires ATA Secure Erase (`hdparm`), NVMe Format Cryptographic Erase (`nvme-cli`), or degaussing. | User-space overwriting cannot bypass Flash Translation Layers (FTL), over-provisioned blocks, or wear-leveling remaps on SSDs. |
| **Destroy** (Physical Destruction) | **Documented** | Physical disintegration, incineration, shredding, or melting per NIST Table A-1 through A-10. | External physical hardware action. |
| **Verification** (Section 4.8) | **Implemented** | Independent read-back inspection sampling binary chunks across file header, body, and tail, evaluated via Shannon entropy and pattern matching. | Confirms write committed to storage medium before unlinking metadata. |
| **Documentation & Certificate** (Section 4.9) | **Implemented** | Structured, tamper-evident JSON Certificate of Destruction with pre-wipe cryptographic hashes, operator metadata, and verification telemetry. | Meets NIST audit and chain-of-custody requirements. |

> **⚠️ Standards Disclaimer:**  
> - **DoD 5220.22-M** is a legacy specification from the United States Department of Defense (superseded) and is **not** a modern NIST standard. It is included strictly for historical compatibility and multi-pass benchmark comparison.  
> - This software is an academic/prototypical implementation and does not claim accredited laboratory certification (e.g., Common Criteria or formal NIST FIPS validation).

---

## 3. Hardware & Method Selection

Sanitization efficiency depends heavily on the physical media substrate:

### Comparison Matrix: Sanitization Methods

| Parameter | NIST SP 800-88 Clear | Legacy DoD 5220.22-M | Fixed Zero Fill (Quick) |
|:---|:---:|:---:|:---:|
| **Pass Count** | **1 Pass** | **3 Passes** | **1 Pass** |
| **Pattern Sequence** | Cryptographic Random (`os.urandom`) | Pass 1: `0x00`<br>Pass 2: `0xFF`<br>Pass 3: Random | Fixed Zeros (`0x00`) |
| **Rotational HDD Suitability** | Excellent (Overwrites magnetic domain transitions) | High (Redundant overwriting) | Good (Basic clearing) |
| **SSD / NVMe Flash Suitability** | Moderate (Subject to FTL Wear-Leveling) | Not Recommended (Excessive write wear without security gain) | Moderate |
| **Execution Speed** | Fast ($\approx 1\times$ baseline I/O) | Slower ($\approx 3\times$ I/O time) | Fastest (Optimized buffer throughput) |
| **Entropy Post-Wipe** | High ($\approx 7.95 - 8.00$ bits/byte) | High ($\approx 7.95 - 8.00$ bits/byte) | $0.00$ bits/byte |

### Media Detection & Selection Logic (`device_detection.py`)

1. **Rotational Magnetic Drives (HDD):**
   - Single-pass random (NIST Clear) or multi-pass (DoD 3-Pass) is fully effective across logical sector clusters.
2. **Flash-Based Storage (SSD / NVMe / USB Flash):**
   - **FTL & Wear-Leveling Warning:** Modern SSDs distribute writes across flash NAND blocks via wear-leveling algorithms. Standard file-level overwrites write to newly allocated flash blocks while the original block may temporarily reside in unallocated over-provisioned space until garbage-collected by TRIM.
   - **Recommendation:** Use 1-Pass NIST Clear to minimize unnecessary NAND write amplification. Full device repurposing should utilize ATA/NVMe hardware-level secure erase.
3. **Safety Guardrails:**
   - Automatically inspects target paths and **rejects critical operating system directories** (`C:\Windows`, `C:\Program Files`, `/bin`, `/boot`, `/etc`, `/usr`) and physical drive devices (`\\.\PhysicalDrive0`, `/dev/sda`) before performing any destructive I/O.

---

## 4. Verification & Forensic Chain-of-Custody

### 1. Pre-Wipe Cryptographic Hashing (`compute_file_sha256`)
Prior to modifying a single byte on disk, the pipeline computes the target's original **SHA-256 hash** using streaming 4096-byte buffers. This provides immutable forensic proof that a specific piece of evidence existed prior to destruction.

### 2. Independent Binary Verification (`verification.py`)
Following pattern overwriting, the verification engine independently inspects the file across three distinct zones:
- **Header:** First 4096 bytes (offset `0`).
- **Body:** 3 evenly spaced sample regions across the file payload.
- **Tail:** Last 4096 bytes (`file_size - 4096`).

Each region is tested for:
- **Pattern Matching:** Verifies $100\%$ byte identity if a deterministic pattern (e.g. `0x00`) was written.
- **Shannon Entropy Analysis:** Computes empirical entropy $H = -\sum p(x)\log_2 p(x)$. Random sanitization passes must yield high entropy ($\ge 7.2\text{ bits/byte}$). Residual plaintext or uniform repeating structures trigger an immediate verification failure.
- **Fail-Safe Deletion Halting:** If verification fails, **file deletion is aborted** to preserve remnant evidence for forensic review.

### 3. Metadata Scrambling & Deletion
To prevent forensic file recovery tools from retrieving original filenames from directory tables ($MFT in NTFS / Directory Entries in FAT32/ext4):
1. The target file is renamed to a cryptographically random 16-character alphanumeric string (e.g. `k8F2mP9xQwL4vN1z`).
2. The file length is truncated to `0` bytes.
3. The entry is unlinked via `os.remove()`.

---

## 5. Audit Certificate Integration

Every sanitization run automatically outputs a structured JSON certificate in `certificates/certificate_<job_id>.json`. This schema provides an immutable, tamper-evident audit artifact:

### Example Generated Certificate (`certificates/certificate_san-4a9e5d50e7f3.json`)

```json
{
  "id": "san-4a9e5d50e7f3",
  "target_path": "C:\\Users\\DELL\\evidence\\confidential_case_402.docx",
  "original_filename": "confidential_case_402.docx",
  "size_bytes": 1048576,
  "pre_wipe_sha256": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
  "erasure_method": "NIST_SP_800_88_CLEAR",
  "pass_count": 1,
  "passes_total": 1,
  "status": "completed",
  "started_at": "2026-09-02T10:50:00.123456+00:00",
  "completed_at": "2026-09-02T10:50:00.456789+00:00",
  "timestamp_iso": "2026-09-02T10:50:00.456789+00:00",
  "verification_status": "passed",
  "operator_name": "Forensic Sanitization Officer",
  "device": {
    "name": "C:\\Users\\DELL\\evidence\\confidential_case_402.docx",
    "type": "Local Dummy/Test File",
    "serial": "N/A",
    "capacity_bytes": 1048576
  },
  "verification": {
    "passed": true,
    "sample_sectors_checked": 5,
    "residual_data_found": false,
    "average_entropy": 7.9812,
    "expected_pattern_type": "Cryptographic Random / High Entropy",
    "details": "High Shannon entropy confirmed across all 5 sampled regions (avg: 7.98 bits/byte)."
  },
  "certificate_path": "certificates/certificate_san-4a9e5d50e7f3.json",
  "error_message": null
}
```

---

## 6. Execution & Test Instructions

### Running Tests

All unit and acceptance tests strictly operate on local temporary dummy files.

```powershell
# Using Pytest
pytest tests/erasure/ -v

# Using Python unittest runner
python -m unittest discover -s tests/erasure -p "test_*.py" -v
```

### Programmatic Usage

```python
from erasure.sanitizer import sanitize_file
from erasure.methods import SanitizationAlgorithm

# Execute full NIST Clear sanitization workflow
result = sanitize_file(
    target_path="path/to/target_file.dat",
    algorithm=SanitizationAlgorithm.NIST_800_88_CLEAR,
    operator_name="Investigator Jane Doe",
    certificates_dir="certificates",
)

if result.status == "completed":
    print(f"[+] Successfully sanitized: {result.original_filename}")
    print(f"    Pre-wipe SHA-256: {result.pre_wipe_sha256}")
    print(f"    Certificate saved: {result.certificate_path}")
else:
    print(f"[-] Sanitization failed: {result.error_message}")
```

### Target Scope Safety Verification via CLI

```powershell
python -c "from erasure.device_detection import check_target_safety; print(check_target_safety('C:\\Windows\\System32'))"
# Output: False (Protected OS directory)
```
