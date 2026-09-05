"""
Sentinel-Purge Erasure Handler
Module: erasure.handler

Central orchestration for file-based Clear and Purge operations
with mandatory secret-key authorization gating.

Clear:  Overwrites file content with zero-bytes, truncates to 0 bytes,
        leaves the filesystem entry (inode / directory entry) intact.
Purge:  Overwrites content with random bytes, truncates, then permanently
        deletes / unlinks the file from disk.

Every step is recorded through the AuditTrail for live proof logging.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional

from erasure.audit_trail import AuditTrail


# ---------------------------------------------------------------------------
# Default secret key (override via ERASURE_SECRET_KEY environment variable)
# ---------------------------------------------------------------------------
_DEFAULT_SECRET_KEY = "SentinelPurge@2026"


def _get_valid_key() -> str:
    """Return the valid authorization key from env or the built-in default."""
    return os.environ.get("ERASURE_SECRET_KEY", _DEFAULT_SECRET_KEY)


def _hash_key(key: str) -> str:
    """Derive a deterministic SHA-256 hash of the key for safe comparison."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------

def authorize(secret_key: str) -> bool:
    """
    Verify the supplied secret key against the valid authorized key.

    Uses hmac.compare_digest to prevent timing-based side-channel attacks.

    Returns:
        True if the key matches, False otherwise.
    """
    valid_hash = _hash_key(_get_valid_key())
    supplied_hash = _hash_key(secret_key)
    return hmac.compare_digest(valid_hash, supplied_hash)


# ---------------------------------------------------------------------------
# Clear Operation
# ---------------------------------------------------------------------------

def handle_clear(
    file_path: str | Path,
    secret_key: str,
    audit: Optional[AuditTrail] = None,
) -> Dict[str, Any]:
    """
    Authorized Clear operation.

    1. Verify secret key.
    2. Overwrite file content with zero-bytes (0x00).
    3. Truncate file to 0 bytes.
    4. Flush + fsync.
    5. Leave the file entry intact on disk.

    Args:
        file_path:   Path to the target file.
        secret_key:  User-supplied authorization key.
        audit:       Optional AuditTrail instance for live logging.

    Returns:
        Result dict with keys: success, operation, file_path, detail, audit_log.
    """
    if audit is None:
        audit = AuditTrail()

    target = Path(file_path).resolve()
    target_str = str(target)

    # --- Step 1: Authorization ---
    if not authorize(secret_key):
        audit.record(
            action=AuditTrail.AUTH_FAILURE,
            target_file=target_str,
            detail="Authorization failed: invalid secret key supplied for CLEAR operation.",
            success=False,
        )
        return _result(False, "clear", target_str, "Authorization failed: invalid secret key.", audit)

    audit.record(
        action=AuditTrail.AUTH_SUCCESS,
        target_file=target_str,
        detail="Secret key verified successfully for CLEAR operation.",
        success=True,
    )

    # --- Step 2: Validate target ---
    if not target.is_file():
        audit.record(
            action=AuditTrail.ERROR,
            target_file=target_str,
            detail=f"Target path does not exist or is not a regular file: {target_str}",
            success=False,
        )
        return _result(False, "clear", target_str, f"File not found: {target_str}", audit)

    # --- Step 3: Clear contents ---
    audit.record(
        action=AuditTrail.CLEAR_START,
        target_file=target_str,
        detail=f"Beginning CLEAR operation. Original file size: {target.stat().st_size} bytes.",
        success=True,
    )

    try:
        file_size = target.stat().st_size

        # Ensure writable
        try:
            os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
        except Exception:
            pass

        # Overwrite with zeros then truncate
        with open(target, "r+b") as f:
            if file_size > 0:
                # Write zero-bytes across the entire file
                chunk_size = 4096
                remaining = file_size
                while remaining > 0:
                    write_len = min(chunk_size, remaining)
                    f.write(b"\x00" * write_len)
                    remaining -= write_len
                f.flush()
                os.fsync(f.fileno())

            # Truncate to 0 bytes
            f.seek(0)
            f.truncate(0)
            f.flush()
            os.fsync(f.fileno())

        # Verify the file is now 0 bytes
        final_size = target.stat().st_size
        if final_size != 0:
            audit.record(
                action=AuditTrail.ERROR,
                target_file=target_str,
                detail=f"Clear verification failed: file size is {final_size} bytes (expected 0).",
                success=False,
            )
            return _result(False, "clear", target_str, "Clear verification failed.", audit)

        audit.record(
            action=AuditTrail.CLEAR_OK,
            target_file=target_str,
            detail=f"CLEAR completed successfully. {file_size} bytes zeroed and truncated to 0. File entry preserved.",
            success=True,
        )
        return _result(True, "clear", target_str, f"File cleared: {file_size} bytes overwritten with zeros, truncated to 0.", audit)

    except PermissionError as e:
        audit.record(
            action=AuditTrail.ERROR,
            target_file=target_str,
            detail=f"Permission denied during CLEAR: {e}",
            success=False,
        )
        return _result(False, "clear", target_str, f"Permission denied: {e}", audit)

    except Exception as e:
        audit.record(
            action=AuditTrail.ERROR,
            target_file=target_str,
            detail=f"Unexpected error during CLEAR: {e}",
            success=False,
        )
        return _result(False, "clear", target_str, f"Error: {e}", audit)


# ---------------------------------------------------------------------------
# Purge Operation
# ---------------------------------------------------------------------------

def handle_purge(
    file_path: str | Path,
    secret_key: str,
    audit: Optional[AuditTrail] = None,
) -> Dict[str, Any]:
    """
    Authorized Purge operation.

    1. Verify secret key.
    2. Overwrite file content with cryptographic random bytes.
    3. Truncate file to 0 bytes.
    4. Delete / unlink the file from the filesystem.
    5. Confirm the path no longer exists.

    Args:
        file_path:   Path to the target file.
        secret_key:  User-supplied authorization key.
        audit:       Optional AuditTrail instance for live logging.

    Returns:
        Result dict with keys: success, operation, file_path, detail, audit_log.
    """
    if audit is None:
        audit = AuditTrail()

    target = Path(file_path).resolve()
    target_str = str(target)

    # --- Step 1: Authorization ---
    if not authorize(secret_key):
        audit.record(
            action=AuditTrail.AUTH_FAILURE,
            target_file=target_str,
            detail="Authorization failed: invalid secret key supplied for PURGE operation.",
            success=False,
        )
        return _result(False, "purge", target_str, "Authorization failed: invalid secret key.", audit)

    audit.record(
        action=AuditTrail.AUTH_SUCCESS,
        target_file=target_str,
        detail="Secret key verified successfully for PURGE operation.",
        success=True,
    )

    # --- Step 2: Validate target ---
    if not target.is_file():
        audit.record(
            action=AuditTrail.ERROR,
            target_file=target_str,
            detail=f"Target path does not exist or is not a regular file: {target_str}",
            success=False,
        )
        return _result(False, "purge", target_str, f"File not found: {target_str}", audit)

    # --- Step 3: Purge contents + delete ---
    audit.record(
        action=AuditTrail.PURGE_START,
        target_file=target_str,
        detail=f"Beginning PURGE operation. Original file size: {target.stat().st_size} bytes.",
        success=True,
    )

    try:
        file_size = target.stat().st_size

        # Ensure writable
        try:
            os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
        except Exception:
            pass

        # Overwrite with random bytes then truncate
        with open(target, "r+b") as f:
            if file_size > 0:
                chunk_size = 4096
                remaining = file_size
                while remaining > 0:
                    write_len = min(chunk_size, remaining)
                    f.write(os.urandom(write_len))
                    remaining -= write_len
                f.flush()
                os.fsync(f.fileno())

            # Truncate to 0 bytes before deletion
            f.seek(0)
            f.truncate(0)
            f.flush()
            os.fsync(f.fileno())

        # Delete the file
        os.remove(target)

        # Verify deletion
        if target.exists():
            audit.record(
                action=AuditTrail.ERROR,
                target_file=target_str,
                detail="Purge verification failed: file still exists after os.remove().",
                success=False,
            )
            return _result(False, "purge", target_str, "Purge verification failed: file still exists.", audit)

        audit.record(
            action=AuditTrail.PURGE_OK,
            target_file=target_str,
            detail=f"PURGE completed successfully. {file_size} bytes overwritten with random data, truncated, and file permanently deleted.",
            success=True,
        )
        return _result(True, "purge", target_str, f"File purged: {file_size} bytes overwritten, truncated, and permanently deleted.", audit)

    except PermissionError as e:
        audit.record(
            action=AuditTrail.ERROR,
            target_file=target_str,
            detail=f"Permission denied during PURGE: {e}",
            success=False,
        )
        return _result(False, "purge", target_str, f"Permission denied: {e}", audit)

    except Exception as e:
        audit.record(
            action=AuditTrail.ERROR,
            target_file=target_str,
            detail=f"Unexpected error during PURGE: {e}",
            success=False,
        )
        return _result(False, "purge", target_str, f"Error: {e}", audit)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _result(
    success: bool,
    operation: str,
    file_path: str,
    detail: str,
    audit: AuditTrail,
) -> Dict[str, Any]:
    """Build a standardized result dict including the full audit trail."""
    return {
        "success": success,
        "operation": operation,
        "file_path": file_path,
        "detail": detail,
        "audit_log": audit.get_entries(),
    }
