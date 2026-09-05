"""
Sentinel-Purge Sanitizer Orchestration Engine
Module: erasure.sanitizer

End-to-end sanitization workflow pipeline:
  1. Target Scope Check (device_detection.py)
  2. Pre-Wipe Cryptographic Hashing (SHA-256 via 4096-byte chunks)
  3. Chunked Binary Sanitization Overwriting (methods.py)
  4. Post-Wipe Independent Verification (verification.py)
  5. Metadata Scrambling (16-char random rename) & Unlink Deletion
  6. Forensic Audit Certificate Generation
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import secrets
import stat
import string
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from erasure.device_detection import (
    StorageMediaType,
    TargetScopeInfo,
    validate_sanitization_target,
)
from erasure.methods import (
    DEFAULT_CHUNK_SIZE,
    OverwriteEngine,
    SanitizationAlgorithm,
    SanitizationResult,
)
from erasure.verification import (
    VerificationEngine,
    VerificationReport,
    inspect_erasure,
)


@dataclass
class SanitizationJobResult:
    """Complete forensic sanitization record conforming to data-schema.md."""
    id: str
    target_path: str
    original_filename: str
    size_bytes: int
    pre_wipe_sha256: str
    erasure_method: str
    pass_count: int
    passes_total: int
    status: str  # "completed" | "failed" | "rejected"
    started_at: str  # ISO 8601
    completed_at: str  # ISO 8601
    timestamp_iso: str  # ISO 8601
    verification_status: str  # "passed" | "failed" | "skipped"
    operator_name: str
    device: Dict[str, Any]
    verification: Dict[str, Any]
    certificate_path: Optional[str] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary matching data-schema.md."""
        return asdict(self)


def compute_file_sha256(
    file_path: str | Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """
    Compute pre-wipe SHA-256 cryptographic hash of a file
    using chunked binary streaming (4096 bytes per chunk).
    """
    path = Path(file_path).resolve()
    hasher = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)

    return hasher.hexdigest()


def generate_random_filename(length: int = 16) -> str:
    """Generate a random alphanumeric string to scramble filename metadata traces."""
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


class Sanitizer:
    """
    Forensic Sanitization Orchestration Engine.
    Executes safety checks, hashing, multi-pass overwriting, verification,
    directory entry metadata scrubbing, and Certificate of Destruction generation.
    """

    def __init__(
        self,
        certificates_dir: str | Path = "certificates",
        approved_roots: Optional[List[Path | str]] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        self.certificates_dir = Path(certificates_dir)
        self.approved_roots = approved_roots
        self.chunk_size = chunk_size
        self.overwrite_engine = OverwriteEngine(chunk_size=chunk_size)
        self.verification_engine = VerificationEngine(sample_chunk_size=chunk_size)

    def sanitize(
        self,
        target_path: str | Path,
        algorithm: SanitizationAlgorithm | str = SanitizationAlgorithm.NIST_800_88_CLEAR,
        operator_name: str = "Forensic Sanitization Operator",
        progress_callback: Optional[Callable[[int, int, int, int], None]] = None,
    ) -> SanitizationJobResult:
        """
        Execute full sanitization pipeline on a target file.
        """
        job_id = f"san-{uuid.uuid4().hex[:12]}"
        start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        target_str = str(target_path)

        # Normalize algorithm parameter
        if isinstance(algorithm, str):
            try:
                algo_enum = SanitizationAlgorithm(algorithm)
            except ValueError:
                algo_enum = SanitizationAlgorithm.NIST_800_88_CLEAR
        else:
            algo_enum = algorithm

        # ---------------------------------------------------------------------
        # Step 1: Scope & Safety Validation
        # ---------------------------------------------------------------------
        scope_info = validate_sanitization_target(
            target_path, approved_roots=self.approved_roots
        )

        device_dict = {
            "name": target_str,
            "type": scope_info.media_type.value if scope_info else "Unknown",
            "serial": "N/A",
            "capacity_bytes": scope_info.size_bytes if scope_info else 0,
        }

        if not scope_info.is_safe:
            end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            try:
                filename = Path(target_str).name if not target_str.startswith(r"\\") else target_str
            except Exception:
                filename = target_str
            return self._build_job_record(
                job_id=job_id,
                target_path=target_str,
                filename=filename,
                size_bytes=scope_info.size_bytes,
                pre_sha256="N/A (Scope Rejected)",
                algorithm=algo_enum.value,
                passes_completed=0,
                passes_total=self.overwrite_engine._get_pass_count(algo_enum),
                status="rejected",
                start_iso=start_iso,
                end_iso=end_iso,
                verification_status="skipped",
                operator_name=operator_name,
                device=device_dict,
                verification={"passed": False, "details": scope_info.rejection_reason or "Safety boundary check failed."},
                error_message=f"Safety Rejection: {scope_info.rejection_reason}",
            )

        resolved_path = Path(target_str).resolve()


        # Clear read-only flags if present to allow write/rename
        if scope_info.is_read_only:
            try:
                os.chmod(resolved_path, stat.S_IWRITE | stat.S_IREAD)
            except Exception:
                pass

        # ---------------------------------------------------------------------
        # Step 2: Pre-Wipe Forensic Hashing
        # ---------------------------------------------------------------------
        try:
            pre_wipe_sha256 = compute_file_sha256(resolved_path, chunk_size=self.chunk_size)
            file_size = resolved_path.stat().st_size
            device_dict["capacity_bytes"] = file_size
        except Exception as hash_err:
            end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            return self._build_job_record(
                job_id=job_id,
                target_path=str(resolved_path),
                filename=resolved_path.name,
                size_bytes=0,
                pre_sha256="ERROR",
                algorithm=algo_enum.value,
                passes_completed=0,
                passes_total=self.overwrite_engine._get_pass_count(algo_enum),
                status="failed",
                start_iso=start_iso,
                end_iso=end_iso,
                verification_status="skipped",
                operator_name=operator_name,
                device=device_dict,
                verification={"passed": False, "details": "Failed to compute pre-wipe SHA-256 hash."},
                error_message=f"Pre-wipe hashing error: {hash_err}",
            )

        # ---------------------------------------------------------------------
        # Step 3: Binary Pattern Overwrite
        # ---------------------------------------------------------------------
        overwrite_res: SanitizationResult = self.overwrite_engine.sanitize_file(
            resolved_path,
            algorithm=algo_enum,
            progress_callback=progress_callback,
        )

        if not overwrite_res.success:
            end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            return self._build_job_record(
                job_id=job_id,
                target_path=str(resolved_path),
                filename=resolved_path.name,
                size_bytes=file_size,
                pre_sha256=pre_wipe_sha256,
                algorithm=algo_enum.value,
                passes_completed=overwrite_res.passes_completed,
                passes_total=overwrite_res.passes_total,
                status="failed",
                start_iso=start_iso,
                end_iso=end_iso,
                verification_status="skipped",
                operator_name=operator_name,
                device=device_dict,
                verification={"passed": False, "details": overwrite_res.error_message or "Overwrite failed."},
                error_message=overwrite_res.error_message,
            )

        # ---------------------------------------------------------------------
        # Step 4: Post-Sanitization Independent Verification
        # ---------------------------------------------------------------------
        # Determine expected pattern based on algorithm
        expected_pat: Optional[bytes] = None
        if algo_enum == SanitizationAlgorithm.ZERO_OVERWRITE:
            expected_pat = b"\x00"

        verify_report: VerificationReport = self.verification_engine.inspect(
            resolved_path, expected_pattern=expected_pat
        )

        verification_dict = {
            "passed": verify_report.passed,
            "sample_sectors_checked": verify_report.sample_sectors_checked,
            "residual_data_found": verify_report.residual_data_found,
            "average_entropy": verify_report.average_entropy,
            "expected_pattern_type": verify_report.expected_pattern_type,
            "details": verify_report.details,
        }

        if not verify_report.passed:
            end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            return self._build_job_record(
                job_id=job_id,
                target_path=str(resolved_path),
                filename=resolved_path.name,
                size_bytes=file_size,
                pre_sha256=pre_wipe_sha256,
                algorithm=algo_enum.value,
                passes_completed=overwrite_res.passes_completed,
                passes_total=overwrite_res.passes_total,
                status="failed",
                start_iso=start_iso,
                end_iso=end_iso,
                verification_status="failed",
                operator_name=operator_name,
                device=device_dict,
                verification=verification_dict,
                error_message="Verification check failed: Residual data or low entropy detected on media.",
            )

        # ---------------------------------------------------------------------
        # Step 5: Metadata Scrambling & Deletion
        # ---------------------------------------------------------------------
        try:
            parent_dir = resolved_path.parent
            # Generate 16-character random name to scramble directory entries
            scrambled_name = generate_random_filename(16)
            scrambled_path = parent_dir / scrambled_name

            # Rename to random alphanumeric string
            resolved_path.rename(scrambled_path)

            # Truncate to 0 bytes and unlink file
            try:
                with open(scrambled_path, "wb") as f:
                    pass
            except Exception:
                pass

            os.remove(scrambled_path)

        except Exception as del_err:
            end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            return self._build_job_record(
                job_id=job_id,
                target_path=str(resolved_path),
                filename=resolved_path.name,
                size_bytes=file_size,
                pre_sha256=pre_wipe_sha256,
                algorithm=algo_enum.value,
                passes_completed=overwrite_res.passes_completed,
                passes_total=overwrite_res.passes_total,
                status="failed",
                start_iso=start_iso,
                end_iso=end_iso,
                verification_status="passed",
                operator_name=operator_name,
                device=device_dict,
                verification=verification_dict,
                error_message=f"Sanitization verified but metadata scrubbing/deletion failed: {del_err}",
            )

        # ---------------------------------------------------------------------
        # Step 6: Audit Certificate Output (JSON inside certificates/)
        # ---------------------------------------------------------------------
        end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        job_record = self._build_job_record(
            job_id=job_id,
            target_path=str(resolved_path),
            filename=resolved_path.name,
            size_bytes=file_size,
            pre_sha256=pre_wipe_sha256,
            algorithm=algo_enum.value,
            passes_completed=overwrite_res.passes_completed,
            passes_total=overwrite_res.passes_total,
            status="completed",
            start_iso=start_iso,
            end_iso=end_iso,
            verification_status="passed",
            operator_name=operator_name,
            device=device_dict,
            verification=verification_dict,
        )

        cert_path = self._write_certificate(job_record)
        job_record.certificate_path = str(cert_path)

        return job_record

    def _build_job_record(
        self,
        job_id: str,
        target_path: str,
        filename: str,
        size_bytes: int,
        pre_sha256: str,
        algorithm: str,
        passes_completed: int,
        passes_total: int,
        status: str,
        start_iso: str,
        end_iso: str,
        verification_status: str,
        operator_name: str,
        device: Dict[str, Any],
        verification: Dict[str, Any],
        error_message: Optional[str] = None,
    ) -> SanitizationJobResult:
        """Construct a validated SanitizationJobResult object."""
        return SanitizationJobResult(
            id=job_id,
            target_path=target_path,
            original_filename=filename,
            size_bytes=size_bytes,
            pre_wipe_sha256=pre_sha256,
            erasure_method=algorithm,
            pass_count=passes_completed,
            passes_total=passes_total,
            status=status,
            started_at=start_iso,
            completed_at=end_iso,
            timestamp_iso=end_iso,
            verification_status=verification_status,
            operator_name=operator_name,
            device=device,
            verification=verification,
            error_message=error_message,
        )

    def _write_certificate(self, record: SanitizationJobResult) -> Path:
        """Save JSON audit certificate in certificates/ directory."""
        self.certificates_dir.mkdir(parents=True, exist_ok=True)
        cert_file = self.certificates_dir / f"certificate_{record.id}.json"
        
        with open(cert_file, "w", encoding="utf-8") as f:
            json.dump(record.to_dict(), f, indent=2)

        return cert_file


# Module-level convenience runner
def sanitize_file(
    target_path: str | Path,
    algorithm: SanitizationAlgorithm | str = SanitizationAlgorithm.NIST_800_88_CLEAR,
    operator_name: str = "Forensic Sanitization Operator",
    certificates_dir: str | Path = "certificates",
    approved_roots: Optional[List[Path | str]] = None,
    progress_callback: Optional[Callable[[int, int, int, int], None]] = None,
) -> SanitizationJobResult:
    """
    Execute full end-to-end sanitization workflow:
    Scope Validation -> Pre-Wipe SHA-256 -> Overwrite -> Verification ->
    16-Char Random Rename Deletion -> Audit Certificate Generation.
    """
    sanitizer = Sanitizer(
        certificates_dir=certificates_dir,
        approved_roots=approved_roots,
    )
    return sanitizer.sanitize(
        target_path=target_path,
        algorithm=algorithm,
        operator_name=operator_name,
        progress_callback=progress_callback,
    )
