"""
Unit tests for erasure.verification (Independent binary verification engine).
Tests both successful wipe verifications and forced verification failures.
Compatible with standard library unittest and pytest.
Strictly operates on temporary local dummy files.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from erasure.methods import (
    OverwriteEngine,
    SanitizationAlgorithm,
    overwrite_dod_3pass,
    overwrite_nist_clear,
)
from erasure.verification import (
    VerificationEngine,
    calculate_shannon_entropy,
    inspect_erasure,
    verify_erasure,
)


class TestErasureVerification(unittest.TestCase):
    """Test suite for post-wipe binary verification engine."""

    def setUp(self) -> None:
        self.test_dir = Path(tempfile.mkdtemp(prefix="sentinel_verify_"))

    def tearDown(self) -> None:
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    # =========================================================================
    # Shannon Entropy Calculations
    # =========================================================================
    def test_entropy_fixed_zeros(self) -> None:
        """Fixed repeating byte pattern must yield 0.0 entropy."""
        data = b"\x00" * 4096
        self.assertEqual(calculate_shannon_entropy(data), 0.0)

    def test_entropy_random_bytes(self) -> None:
        """Cryptographically random data must yield high entropy (> 7.5 bits/byte)."""
        data = os.urandom(8192)
        entropy = calculate_shannon_entropy(data)
        self.assertGreater(entropy, 7.5)
        self.assertLessEqual(entropy, 8.0)

    def test_entropy_structured_text(self) -> None:
        """Structured text typically yields moderate entropy (between 2.5 and 5.0)."""
        text = b"CONFIDENTIAL FINANCIAL RECORD " * 100
        entropy = calculate_shannon_entropy(text)
        self.assertGreater(entropy, 2.0)
        self.assertLess(entropy, 6.0)

    # =========================================================================
    # Successful Wipes
    # =========================================================================
    def test_verify_zero_overwrite_success(self) -> None:
        """Verify file wiped with all zeros returns True when expecting b'\\x00'."""
        dummy_file = self.test_dir / "zero_wiped.bin"
        dummy_file.write_bytes(b"\x00" * 16384)

        result = verify_erasure(dummy_file, expected_pattern=b"\x00")
        self.assertTrue(result)

        report = inspect_erasure(dummy_file, expected_pattern=b"\x00")
        self.assertTrue(report.passed)
        self.assertFalse(report.residual_data_found)
        self.assertEqual(report.average_entropy, 0.0)

    def test_verify_nist_clear_random_success(self) -> None:
        """Verify file wiped via NIST Clear (random) passes high-entropy verification."""
        dummy_file = self.test_dir / "nist_cleared.bin"
        dummy_file.write_bytes(b"INITIAL ORIGINAL SENSITIVE EVIDENCE" * 200)

        # Apply NIST Clear overwrite
        res = overwrite_nist_clear(dummy_file)
        self.assertTrue(res.success)

        # Verify erasure without explicit pattern (evaluates random entropy)
        result = verify_erasure(dummy_file, expected_pattern=None)
        self.assertTrue(result)

        report = inspect_erasure(dummy_file, expected_pattern=None)
        self.assertTrue(report.passed)
        self.assertFalse(report.residual_data_found)
        self.assertGreater(report.average_entropy, 7.2)

    def test_verify_dod_3pass_success(self) -> None:
        """Verify file sanitized via legacy DoD 3-pass (final pass random) passes verification."""
        dummy_file = self.test_dir / "dod_wiped.bin"
        dummy_file.write_bytes(b"TOP SECRET INTELLIGENCE DATA" * 300)

        res = overwrite_dod_3pass(dummy_file)
        self.assertTrue(res.success)

        result = verify_erasure(dummy_file, expected_pattern=None)
        self.assertTrue(result)

    def test_verify_empty_file_success(self) -> None:
        """0-byte file must be verified successfully without errors."""
        empty_file = self.test_dir / "empty.dat"
        empty_file.write_bytes(b"")

        self.assertTrue(verify_erasure(empty_file))
        report = inspect_erasure(empty_file)
        self.assertTrue(report.passed)
        self.assertFalse(report.residual_data_found)

    def test_verify_small_file_success(self) -> None:
        """Small file (< 4096 bytes) should be sampled in full."""
        small_file = self.test_dir / "small_zero.dat"
        small_file.write_bytes(b"\x00" * 128)

        self.assertTrue(verify_erasure(small_file, expected_pattern=b"\x00"))

    # =========================================================================
    # Forced Verification Failures (Adversarial / Residual Data Tests)
    # =========================================================================
    def test_forced_failure_residual_data_when_expecting_zeros(self) -> None:
        """File with non-zero bytes must fail when expecting zero pattern."""
        dirty_file = self.test_dir / "dirty_zero.bin"
        # 16KB of zeros, but with residual data at offset 8192
        dirty_data = bytearray(b"\x00" * 16384)
        dirty_data[8192:8210] = b"RESIDUAL_PASSWORD!"
        dirty_file.write_bytes(dirty_data)

        result = verify_erasure(dirty_file, expected_pattern=b"\x00")
        self.assertFalse(result)

        report = inspect_erasure(dirty_file, expected_pattern=b"\x00")
        self.assertFalse(report.passed)
        self.assertTrue(report.residual_data_found)
        self.assertIn("mismatch", report.details.lower())

    def test_forced_failure_low_entropy_unwiped_data(self) -> None:
        """Unwiped plaintext file must fail random overwrite verification due to low entropy."""
        plain_file = self.test_dir / "unwiped_plain.txt"
        plain_file.write_bytes(b"A" * 16384)  # Single repeating character -> entropy 0.0

        result = verify_erasure(plain_file, expected_pattern=None)
        self.assertFalse(result)

        report = inspect_erasure(plain_file, expected_pattern=None)
        self.assertFalse(report.passed)
        self.assertTrue(report.residual_data_found)

    def test_forced_failure_partial_corruption_header_tail(self) -> None:
        """File with random body but unwiped plaintext header must fail verification."""
        partial_file = self.test_dir / "partial_wiped.bin"
        # Header is plaintext, body and tail are random
        header = b"UNWIPED_ORIGINAL_HEADER_EVIDENCE" * 128  # 4096 bytes
        random_tail = os.urandom(16384)
        partial_file.write_bytes(header + random_tail)

        result = verify_erasure(partial_file, expected_pattern=None)
        self.assertFalse(result)

        report = inspect_erasure(partial_file, expected_pattern=None)
        self.assertFalse(report.passed)
        self.assertTrue(report.residual_data_found)

    def test_verify_nonexistent_file_returns_false(self) -> None:
        """Non-existent file target must return False."""
        ghost_file = self.test_dir / "does_not_exist.bin"
        self.assertFalse(verify_erasure(ghost_file))


if __name__ == "__main__":
    unittest.main()
