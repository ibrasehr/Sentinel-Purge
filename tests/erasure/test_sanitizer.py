"""
Acceptance Criteria Test Suite for erasure.sanitizer
Tests end-to-end sanitization lifecycles, verification failure handling,
scope guardrail protections, and data-schema.md compliance.

Compatible with both unittest and pytest test runners.
Strictly operates on local temporary dummy files.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from erasure.methods import SanitizationAlgorithm, SanitizationResult
from erasure.sanitizer import (
    SanitizationJobResult,
    Sanitizer,
    compute_file_sha256,
    generate_random_filename,
    sanitize_file,
)
from erasure.verification import VerificationReport


class TestSanitizerAcceptanceSuite(unittest.TestCase):
    """Exhaustive acceptance test suite for forensic sanitization pipeline."""

    def setUp(self) -> None:
        self.test_dir = Path(tempfile.mkdtemp(prefix="sentinel_accept_"))
        self.cert_dir = self.test_dir / "certificates"
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        self.sanitizer = Sanitizer(
            certificates_dir=self.cert_dir,
            approved_roots=[self.test_dir],
        )

    def tearDown(self) -> None:
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    # =========================================================================
    # 1. Successful Sanitization Lifecycle Tests
    # =========================================================================
    def test_lifecycle_empty_0byte_file(self) -> None:
        """Acceptance: 0-byte file sanitization lifecycle."""
        empty_target = self.test_dir / "dummy_empty.bin"
        empty_target.write_bytes(b"")
        expected_hash = hashlib.sha256(b"").hexdigest()

        result = self.sanitizer.sanitize(
            target_path=empty_target,
            algorithm=SanitizationAlgorithm.NIST_800_88_CLEAR,
            operator_name="Operator 01",
        )

        # Confirm status, hash, and deletion
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.verification_status, "passed")
        self.assertEqual(result.size_bytes, 0)
        self.assertEqual(result.pre_wipe_sha256, expected_hash)
        self.assertFalse(empty_target.exists(), "Target file must be unlinked from filesystem.")

        # Confirm valid JSON certificate
        self.assertIsNotNone(result.certificate_path)
        self.assertTrue(Path(result.certificate_path).exists())

    def test_lifecycle_tiny_text_file(self) -> None:
        """Acceptance: Tiny text file (< 1KB) sanitization lifecycle."""
        tiny_target = self.test_dir / "tiny_secret.txt"
        payload = b"Top secret cryptographic passkey: 8x92-ZqL!"
        tiny_target.write_bytes(payload)
        expected_hash = hashlib.sha256(payload).hexdigest()
        expected_size = len(payload)

        result = self.sanitizer.sanitize(
            target_path=tiny_target,
            algorithm=SanitizationAlgorithm.NIST_800_88_CLEAR,
            operator_name="Forensic Investigator Smith",
        )

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.verification_status, "passed")
        self.assertEqual(result.size_bytes, expected_size)
        self.assertEqual(result.pre_wipe_sha256, expected_hash)
        self.assertEqual(result.pass_count, 1)
        self.assertFalse(tiny_target.exists(), "Original file must be deleted.")

    def test_lifecycle_large_file_chunked_processing(self) -> None:
        """Acceptance: Multi-megabyte file chunked sanitization lifecycle."""
        large_target = self.test_dir / "large_disk_image.raw"
        # Create a 2 MB dummy payload to test chunked streaming
        chunk = b"FORENSIC_SECTOR_DATA_BLOCK_2026" * 128  # 4096 bytes
        large_target.write_bytes(chunk * 512)  # 2,097,152 bytes (2 MB)
        
        expected_size = large_target.stat().st_size
        expected_hash = compute_file_sha256(large_target)

        result = self.sanitizer.sanitize(
            target_path=large_target,
            algorithm=SanitizationAlgorithm.LEGACY_DOD_5220_22_M,
            operator_name="Senior Analyst Doe",
        )

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.verification_status, "passed")
        self.assertEqual(result.size_bytes, expected_size)
        self.assertEqual(result.pre_wipe_sha256, expected_hash)
        self.assertEqual(result.pass_count, 3)
        self.assertEqual(result.passes_total, 3)
        self.assertFalse(large_target.exists(), "Large file must be safely unlinked.")

    def test_lifecycle_read_only_target(self) -> None:
        """Acceptance: Read-only targets are unlocked and wiped without permission errors."""
        ro_target = self.test_dir / "read_only_archive.tar"
        ro_target.write_bytes(b"ARCHIVED SENSITIVE DATABASE DUMP" * 200)
        os.chmod(ro_target, stat.S_IREAD)

        result = self.sanitizer.sanitize(
            target_path=ro_target,
            algorithm=SanitizationAlgorithm.NIST_800_88_CLEAR,
        )

        self.assertEqual(result.status, "completed")
        self.assertFalse(ro_target.exists())

    # =========================================================================
    # 2. Verification Failure Handling Tests
    # =========================================================================
    def test_verification_failure_halts_deletion_and_flags_status(self) -> None:
        """
        Acceptance: Simulate a post-wipe verification failure.
        Confirms pipeline flags verification_status: failed, HALTS deletion,
        logs failure details, and marks job status as failed.
        """
        failed_target = self.test_dir / "corrupt_write_target.dat"
        failed_target.write_bytes(b"DATA THAT CANNOT BE WIPED" * 100)

        # Mock the verification engine to simulate residual data detection failure
        mock_failed_report = VerificationReport(
            target_path=str(failed_target),
            passed=False,
            file_size_bytes=len(b"DATA THAT CANNOT BE WIPED" * 100),
            sample_sectors_checked=4,
            residual_data_found=True,
            average_entropy=1.85,
            expected_pattern_type="Cryptographic Random / High Entropy",
            details="SIMULATED FAILURE: Residual non-random data detected on media sectors.",
        )

        with patch.object(self.sanitizer.verification_engine, "inspect", return_value=mock_failed_report):
            result: SanitizationJobResult = self.sanitizer.sanitize(
                target_path=failed_target,
                algorithm=SanitizationAlgorithm.NIST_800_88_CLEAR,
            )

        # Confirm pipeline did NOT report success
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.verification_status, "failed")
        self.assertFalse(result.verification["passed"])
        self.assertTrue(result.verification["residual_data_found"])
        self.assertIn("Verification check failed", result.error_message or "")

        # Crucial Guardrail Check: The file must NOT be unlinked/deleted upon verification failure!
        self.assertTrue(failed_target.exists(), "File deletion MUST be halted if verification fails.")

    # =========================================================================
    # 3. Scope Guardrail Protection Tests
    # =========================================================================
    def test_scope_guardrail_rejects_windows_system_directories(self) -> None:
        """Acceptance: System paths (e.g. C:\\Windows\\System32) are safely rejected prior to I/O."""
        result = self.sanitizer.sanitize(
            target_path=r"C:\Windows\System32",
            algorithm=SanitizationAlgorithm.NIST_800_88_CLEAR,
        )

        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.verification_status, "skipped")
        self.assertIn("Safety Rejection", result.error_message or "")
        self.assertEqual(result.pre_wipe_sha256, "N/A (Scope Rejected)")

    def test_scope_guardrail_rejects_physical_drive_targets(self) -> None:
        """Acceptance: Raw physical system drives (e.g. \\\\.\\PhysicalDrive0) are safely blocked."""
        result = self.sanitizer.sanitize(
            target_path=r"\\.\PhysicalDrive0",
            algorithm=SanitizationAlgorithm.NIST_800_88_CLEAR,
        )

        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.verification_status, "skipped")
        self.assertIn("Safety Rejection", result.error_message or "")

    def test_scope_guardrail_rejects_unapproved_outside_paths(self) -> None:
        """Acceptance: Paths outside configured approved roots are rejected."""
        outside_dir = Path(tempfile.mkdtemp(prefix="outside_scope_"))
        outside_file = outside_dir / "unapproved_target.dat"
        outside_file.write_bytes(b"OUTSIDE DATA")

        try:
            # Validator configured with approved_roots strictly set to self.test_dir
            result = self.sanitizer.sanitize(
                target_path=outside_file,
                algorithm=SanitizationAlgorithm.NIST_800_88_CLEAR,
            )

            self.assertEqual(result.status, "rejected")
            self.assertEqual(result.verification_status, "skipped")
            # Confirm outside file was not touched/deleted
            self.assertTrue(outside_file.exists())
        finally:
            shutil.rmtree(outside_dir, ignore_errors=True)

    # =========================================================================
    # 4. Schema Compliance (data-schema.md) Tests
    # =========================================================================
    def test_certificate_schema_compliance(self) -> None:
        """
        Acceptance: Generated JSON certificate must strictly comply with data-schema.md.
        Validates all key names, nested objects, and strict data types.
        """
        target_file = self.test_dir / "schema_test_file.txt"
        target_file.write_bytes(b"AUDIT COMPLIANCE VERIFICATION RECORD")
        
        result = self.sanitizer.sanitize(
            target_path=target_file,
            algorithm=SanitizationAlgorithm.NIST_800_88_CLEAR,
            operator_name="Forensic Auditor Charlie",
        )

        self.assertEqual(result.status, "completed")
        cert_path = Path(result.certificate_path)
        self.assertTrue(cert_path.exists())

        raw_json = cert_path.read_text(encoding="utf-8")
        data = json.loads(raw_json)

        # 1. Root Level Schema Keys & Types
        self.assertIsInstance(data["id"], str)
        self.assertTrue(data["id"].startswith("san-"))
        self.assertIsInstance(data["target_path"], str)
        self.assertIsInstance(data["original_filename"], str)
        self.assertIsInstance(data["size_bytes"], int)
        self.assertIsInstance(data["pre_wipe_sha256"], str)
        self.assertEqual(len(data["pre_wipe_sha256"]), 64)  # Valid SHA-256 length
        self.assertIsInstance(data["erasure_method"], str)
        self.assertIsInstance(data["pass_count"], int)
        self.assertIsInstance(data["passes_total"], int)
        self.assertIsInstance(data["status"], str)
        self.assertIn(data["status"], ["completed", "failed", "rejected"])
        self.assertIsInstance(data["started_at"], str)
        self.assertIsInstance(data["completed_at"], str)
        self.assertIsInstance(data["timestamp_iso"], str)
        self.assertIsInstance(data["verification_status"], str)
        self.assertIsInstance(data["operator_name"], str)

        # 2. Nested "device" Object Schema
        self.assertIsInstance(data["device"], dict)
        self.assertIn("name", data["device"])
        self.assertIsInstance(data["device"]["name"], str)
        self.assertIn("type", data["device"])
        self.assertIsInstance(data["device"]["type"], str)
        self.assertIn("serial", data["device"])
        self.assertIsInstance(data["device"]["serial"], str)
        self.assertIn("capacity_bytes", data["device"])
        self.assertIsInstance(data["device"]["capacity_bytes"], int)

        # 3. Nested "verification" Object Schema
        self.assertIsInstance(data["verification"], dict)
        self.assertIn("passed", data["verification"])
        self.assertIsInstance(data["verification"]["passed"], bool)
        self.assertIn("sample_sectors_checked", data["verification"])
        self.assertIsInstance(data["verification"]["sample_sectors_checked"], int)
        self.assertIn("residual_data_found", data["verification"])
        self.assertIsInstance(data["verification"]["residual_data_found"], bool)


if __name__ == "__main__":
    unittest.main()
