"""
Unit tests for erasure.methods and erasure.device_detection.
Compatible with both standard library unittest and pytest.
Ensures tests strictly run on local dummy test files.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from erasure.methods import (
    DEFAULT_CHUNK_SIZE,
    BinaryPatternGenerator,
    OverwriteEngine,
    SanitizationAlgorithm,
    overwrite_dod_3pass,
    overwrite_nist_clear,
)
from erasure.device_detection import (
    StorageMediaType,
    TargetScopeValidator,
    validate_sanitization_target,
)


class TestErasureMethodsAndDetection(unittest.TestCase):
    """Test suite for sanitization methods and target scope detection."""

    def setUp(self) -> None:
        self.test_dir = Path(tempfile.mkdtemp(prefix="sentinel_dummy_"))

    def tearDown(self) -> None:
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_chunk_size_enforced(self) -> None:
        """Ensure standard 4096-byte chunk size is enforced."""
        self.assertEqual(DEFAULT_CHUNK_SIZE, 4096)

    def test_binary_pattern_generator(self) -> None:
        """Verify binary patterns generate correct byte sequences."""
        zeros = BinaryPatternGenerator.zeros(16)
        self.assertEqual(zeros, b"\x00" * 16)

        ones = BinaryPatternGenerator.ones(16)
        self.assertEqual(ones, b"\xFF" * 16)

        rand_bytes = BinaryPatternGenerator.random(32)
        self.assertEqual(len(rand_bytes), 32)
        self.assertNotEqual(rand_bytes, b"\x00" * 32)

    def test_nist_clear_overwrite_dummy_file(self) -> None:
        """Test 1-pass NIST Clear on a local dummy file."""
        dummy_file = self.test_dir / "dummy_nist.txt"
        original_data = b"CONFIDENTIAL FORENSIC EVIDENCE" * 100
        dummy_file.write_bytes(original_data)
        original_size = len(original_data)

        res = overwrite_nist_clear(dummy_file)

        self.assertTrue(res.success)
        self.assertEqual(res.passes_completed, 1)
        self.assertEqual(res.passes_total, 1)
        self.assertEqual(res.total_bytes_sanitized, original_size)
        self.assertEqual(dummy_file.stat().st_size, original_size)

        # Verify content was overwritten and no longer matches original
        new_data = dummy_file.read_bytes()
        self.assertNotEqual(new_data, original_data)

    def test_dod_3pass_overwrite_dummy_file(self) -> None:
        """Test legacy DoD 3-pass overwrite on a local dummy file."""
        dummy_file = self.test_dir / "dummy_dod.bin"
        original_data = b"SECRET FORENSIC ARTIFACT RECORD" * 500
        dummy_file.write_bytes(original_data)
        original_size = len(original_data)

        res = overwrite_dod_3pass(dummy_file)

        self.assertTrue(res.success)
        self.assertEqual(res.passes_completed, 3)
        self.assertEqual(res.passes_total, 3)
        self.assertEqual(len(res.pass_details), 3)
        self.assertEqual(res.total_bytes_sanitized, original_size)

        # Verify final overwritten data is changed
        self.assertNotEqual(dummy_file.read_bytes(), original_data)

    def test_empty_dummy_file(self) -> None:
        """Test sanitization handles 0-byte files gracefully without crashing."""
        empty_file = self.test_dir / "empty_dummy.bin"
        empty_file.write_bytes(b"")

        res = overwrite_nist_clear(empty_file)

        self.assertTrue(res.success)
        self.assertEqual(res.total_bytes_sanitized, 0)
        self.assertEqual(empty_file.stat().st_size, 0)

    def test_device_detection_rejects_system_paths(self) -> None:
        """Verify safety validator rejects critical system directories."""
        validator = TargetScopeValidator()

        # Reject Windows system directory
        res_win = validator.evaluate_target(r"C:\Windows\System32")
        self.assertFalse(res_win.is_safe)
        self.assertTrue("REJECTED" in (res_win.rejection_reason or "") or "protected" in (res_win.rejection_reason or "").lower())

        # Reject root drive device
        res_drive = validator.evaluate_target(r"\\.\PhysicalDrive0")
        self.assertFalse(res_drive.is_safe)
        self.assertTrue(res_drive.is_block_device)

    def test_device_detection_approves_local_dummy_file(self) -> None:
        """Verify local dummy test file in approved path is marked safe."""
        dummy_file = self.test_dir / "dummy_test_sample.dat"
        dummy_file.write_bytes(b"TEST DUMMY DATA")

        validator = TargetScopeValidator(approved_roots=[self.test_dir])
        res = validator.evaluate_target(dummy_file)

        self.assertTrue(res.is_safe)
        self.assertEqual(res.media_type, StorageMediaType.DUMMY_TEST_FILE)
        self.assertEqual(res.size_bytes, len(b"TEST DUMMY DATA"))


if __name__ == "__main__":
    unittest.main()
