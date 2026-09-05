"""
Tests for erasure.handler
Sentinel-Purge Test Suite
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from erasure.audit_trail import AuditTrail
from erasure.handler import authorize, handle_clear, handle_purge


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_file():
    """Create a temporary file with known content for testing."""
    fd, path = tempfile.mkstemp(prefix="sentinel_test_", suffix=".dat")
    content = b"Sentinel-Purge test data - this content should be erased.\n" * 100
    os.write(fd, content)
    os.close(fd)
    yield path
    # Cleanup: file may already be deleted by purge
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def audit():
    """Fresh AuditTrail writing to a temp directory."""
    with tempfile.TemporaryDirectory(prefix="audit_test_") as tmpdir:
        trail = AuditTrail(log_dir=tmpdir)
        yield trail


VALID_KEY = "SentinelPurge@2026"
INVALID_KEY = "wrong-key-12345"


# ===================================================================
# Authorization Tests
# ===================================================================

class TestAuthorize:
    """Test the authorize() function."""

    def test_valid_key_returns_true(self):
        assert authorize(VALID_KEY) is True

    def test_invalid_key_returns_false(self):
        assert authorize(INVALID_KEY) is False

    def test_empty_key_returns_false(self):
        assert authorize("") is False

    def test_env_var_override(self, monkeypatch):
        """When ERASURE_SECRET_KEY env var is set, it overrides the default."""
        monkeypatch.setenv("ERASURE_SECRET_KEY", "custom-env-key-99")
        assert authorize("custom-env-key-99") is True
        assert authorize(VALID_KEY) is False  # default no longer works

    def test_timing_safe_comparison(self):
        """authorize() should not raise on unusual characters."""
        assert authorize("' OR 1=1 --") is False
        assert authorize("\x00\xff\x00") is False
        assert authorize("a" * 10_000) is False


# ===================================================================
# Clear Operation Tests
# ===================================================================

class TestHandleClear:
    """Test the handle_clear() function."""

    def test_clear_authorized_empties_file(self, temp_file, audit):
        """After a valid clear, the file should exist with 0 bytes."""
        original_size = os.path.getsize(temp_file)
        assert original_size > 0

        result = handle_clear(temp_file, VALID_KEY, audit=audit)

        assert result["success"] is True
        assert result["operation"] == "clear"
        assert os.path.exists(temp_file), "File should still exist after clear"
        assert os.path.getsize(temp_file) == 0, "File should be 0 bytes after clear"

    def test_clear_unauthorized_leaves_file_intact(self, temp_file, audit):
        """With wrong key, the file content should be unchanged."""
        original_size = os.path.getsize(temp_file)
        original_content = Path(temp_file).read_bytes()

        result = handle_clear(temp_file, INVALID_KEY, audit=audit)

        assert result["success"] is False
        assert "Authorization failed" in result["detail"]
        assert os.path.exists(temp_file)
        assert os.path.getsize(temp_file) == original_size
        assert Path(temp_file).read_bytes() == original_content

    def test_clear_missing_file(self, audit):
        """Clear on a non-existent file should fail gracefully."""
        fake_path = os.path.join(tempfile.gettempdir(), "nonexistent_erasure_test_file.dat")
        result = handle_clear(fake_path, VALID_KEY, audit=audit)

        assert result["success"] is False
        assert "File not found" in result["detail"] or "not a regular file" in result["detail"]

    def test_clear_zero_byte_file(self, audit):
        """Clear on an already-empty file should succeed."""
        fd, path = tempfile.mkstemp(prefix="erasure_empty_test_")
        os.close(fd)
        try:
            result = handle_clear(path, VALID_KEY, audit=audit)
            assert result["success"] is True
            assert os.path.getsize(path) == 0
        finally:
            if os.path.exists(path):
                os.remove(path)


# ===================================================================
# Purge Operation Tests
# ===================================================================

class TestHandlePurge:
    """Test the handle_purge() function."""

    def test_purge_authorized_deletes_file(self, temp_file, audit):
        """After a valid purge, the file should no longer exist."""
        assert os.path.exists(temp_file)

        result = handle_purge(temp_file, VALID_KEY, audit=audit)

        assert result["success"] is True
        assert result["operation"] == "purge"
        assert not os.path.exists(temp_file), "File must be deleted after purge"

    def test_purge_unauthorized_leaves_file_intact(self, temp_file, audit):
        """With wrong key, the file should remain unchanged."""
        original_content = Path(temp_file).read_bytes()

        result = handle_purge(temp_file, INVALID_KEY, audit=audit)

        assert result["success"] is False
        assert "Authorization failed" in result["detail"]
        assert os.path.exists(temp_file)
        assert Path(temp_file).read_bytes() == original_content

    def test_purge_missing_file(self, audit):
        """Purge on a non-existent file should fail gracefully."""
        fake_path = os.path.join(tempfile.gettempdir(), "nonexistent_erasure_purge_test.dat")
        result = handle_purge(fake_path, VALID_KEY, audit=audit)

        assert result["success"] is False


# ===================================================================
# Audit Trail Integration Tests
# ===================================================================

class TestAuditTrailIntegration:
    """Verify that every handler step is recorded in the audit trail."""

    def test_clear_success_records_all_steps(self, temp_file, audit):
        """A successful clear should produce AUTH_SUCCESS, CLEAR_START, CLEAR_OK."""
        handle_clear(temp_file, VALID_KEY, audit=audit)
        entries = audit.get_entries()
        actions = [e["action"] for e in entries]

        assert AuditTrail.AUTH_SUCCESS in actions
        assert AuditTrail.CLEAR_START in actions
        assert AuditTrail.CLEAR_OK in actions
        assert all(e["target_file"] for e in entries), "Every entry should have a target_file"

    def test_clear_failure_records_auth_failure(self, temp_file, audit):
        """A failed auth for clear should produce AUTH_FAILURE."""
        handle_clear(temp_file, INVALID_KEY, audit=audit)
        entries = audit.get_entries()
        actions = [e["action"] for e in entries]

        assert AuditTrail.AUTH_FAILURE in actions
        assert AuditTrail.CLEAR_START not in actions

    def test_purge_success_records_all_steps(self, temp_file, audit):
        """A successful purge should produce AUTH_SUCCESS, PURGE_START, PURGE_OK."""
        handle_purge(temp_file, VALID_KEY, audit=audit)
        entries = audit.get_entries()
        actions = [e["action"] for e in entries]

        assert AuditTrail.AUTH_SUCCESS in actions
        assert AuditTrail.PURGE_START in actions
        assert AuditTrail.PURGE_OK in actions

    def test_purge_failure_records_auth_failure(self, temp_file, audit):
        """A failed auth for purge should produce AUTH_FAILURE."""
        handle_purge(temp_file, INVALID_KEY, audit=audit)
        entries = audit.get_entries()
        actions = [e["action"] for e in entries]

        assert AuditTrail.AUTH_FAILURE in actions
        assert AuditTrail.PURGE_START not in actions

    def test_audit_entries_have_timestamps(self, temp_file, audit):
        """Every audit entry must have a non-empty ISO 8601 timestamp."""
        handle_clear(temp_file, VALID_KEY, audit=audit)
        for entry in audit.get_entries():
            assert entry["timestamp"], "Timestamp must not be empty"
            assert "T" in entry["timestamp"], "Timestamp should be ISO 8601 format"

    def test_audit_log_persisted_to_file(self, temp_file):
        """Entries should be appended to the JSONL log file."""
        with tempfile.TemporaryDirectory(prefix="audit_persist_") as tmpdir:
            trail = AuditTrail(log_dir=tmpdir)
            handle_clear(temp_file, VALID_KEY, audit=trail)

            log_path = trail.log_path
            assert log_path.exists(), "JSONL log file should be created"

            lines = log_path.read_text(encoding="utf-8").strip().split("\n")
            assert len(lines) >= 3, f"Expected >= 3 log lines, got {len(lines)}"
