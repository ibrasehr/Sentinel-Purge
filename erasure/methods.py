"""
Sentinel-Purge Sanitization Methods
Module: erasure.methods

Implementation of chunked binary sanitization routines for file and storage media erasure.

===============================================================================
STANDARDS & IMPLEMENTATION SCOPE (NIST SP 800-88 Rev. 1 & Legacy DoD Guidelines)
===============================================================================
Implemented in this module:
  1. NIST SP 800-88 Rev. 1 "Clear" (1-pass overwrite using cryptographically secure
     random bytes from os.urandom or fixed logical zeros across addressable space).
  2. Legacy DoD 5220.22-M 3-Pass Overwrite:
     - Pass 1: Fixed binary zeros (0x00)
     - Pass 2: Fixed binary complement ones (0xFF)
     - Pass 3: Pseudo-random bytes (os.urandom)
  3. Single-pass fixed pattern wiping (0x00 Zero-fill).

IMPORTANT COMPLIANCE & LIMITATION NOTICES:
  - DoD 5220.22-M is a legacy United States Department of Defense specification
    (superseded) and is NOT a recognized modern NIST SP 800-88 standard. It is
    provided here strictly for historical reference and legacy compatibility testing.
  - NIST SP 800-88 Rev. 1 emphasizes that media type dictates sanitization efficacy:
    * On magnetic spinning media (HDD), logical overwriting effectively mitigates
      standard laboratory recovery techniques.
    * On Flash-based media (SSDs, NVMe, eMMC, USB flash), file-level overwriting
      cannot address over-provisioned sectors, Wear-Leveling remapping, or Flash
      Translation Layer (FTL) hidden blocks. True "Purge" on flash media requires
      firmware-level ATA Secure Erase / NVMe Format Cryptographic Erase, which is
      beyond user-space binary overwrite routines.
  - DISCLAIMER: This is an academic and prototypical implementation. This software
    does NOT claim formal NIST laboratory validation, Common Criteria certification,
    or FIPS accreditation.
===============================================================================
"""

from __future__ import annotations

import enum
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Generator, List, Optional


DEFAULT_CHUNK_SIZE: int = 4096  # Enforced 4096-byte chunk size for binary I/O


class SanitizationAlgorithm(str, enum.Enum):
    """Supported sanitization algorithm definitions."""
    NIST_800_88_CLEAR = "NIST_SP_800_88_CLEAR"
    LEGACY_DOD_5220_22_M = "LEGACY_DOD_5220_22_M"
    ZERO_OVERWRITE = "ZERO_OVERWRITE"
    RANDOM_OVERWRITE = "RANDOM_OVERWRITE"


@dataclass
class PassDetail:
    """Metadata describing a single overwrite pass."""
    pass_number: int
    total_passes: int
    pattern_name: str
    bytes_written: int
    elapsed_seconds: float


@dataclass
class SanitizationResult:
    """Detailed summary of a completed sanitization routine."""
    target_path: str
    algorithm: SanitizationAlgorithm
    total_bytes_sanitized: int
    passes_completed: int
    passes_total: int
    success: bool
    pass_details: List[PassDetail] = field(default_factory=list)
    error_message: Optional[str] = None
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None

    @property
    def duration_seconds(self) -> float:
        if self.completed_at and self.started_at:
            return max(0.0, self.completed_at - self.started_at)
        return 0.0


class BinaryPatternGenerator:
    """Generates chunked byte streams for various wipe patterns."""

    @staticmethod
    def zeros(chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
        """Return a chunk of binary zeros (0x00)."""
        return b"\x00" * chunk_size

    @staticmethod
    def ones(chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
        """Return a chunk of binary ones (0xFF)."""
        return b"\xFF" * chunk_size

    @staticmethod
    def random(chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
        """Return a cryptographically secure random chunk."""
        return os.urandom(chunk_size)


class OverwriteEngine:
    """
    Core binary overwrite execution engine.
    Applies multi-pass or single-pass patterns to files in 4096-byte chunks
    with mandatory filesystem sync (os.fsync).
    """

    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
        self.chunk_size = chunk_size

    def sanitize_file(
        self,
        target_path: str | Path,
        algorithm: SanitizationAlgorithm = SanitizationAlgorithm.NIST_800_88_CLEAR,
        progress_callback: Optional[Callable[[int, int, int, int], None]] = None,
    ) -> SanitizationResult:
        """
        Execute secure binary overwriting on the target file.

        Args:
            target_path: File system path to the target file.
            algorithm: Selected sanitization algorithm.
            progress_callback: Optional callback func(pass_num, total_passes, bytes_done, total_bytes).

        Returns:
            SanitizationResult with execution audit metadata.
        """
        path = Path(target_path).resolve()
        start_time = time.time()

        if not path.is_file():
            return SanitizationResult(
                target_path=str(path),
                algorithm=algorithm,
                total_bytes_sanitized=0,
                passes_completed=0,
                passes_total=self._get_pass_count(algorithm),
                success=False,
                error_message=f"Target path '{path}' does not exist or is not a regular file.",
                started_at=start_time,
                completed_at=time.time(),
            )

        file_size = path.stat().st_size
        pass_patterns = self._get_algorithm_passes(algorithm)
        total_passes = len(pass_patterns)
        pass_details: List[PassDetail] = []

        try:
            # Handle edge case: 0-byte file
            if file_size == 0:
                for idx, (p_name, _) in enumerate(pass_patterns, start=1):
                    pass_details.append(
                        PassDetail(
                            pass_number=idx,
                            total_passes=total_passes,
                            pattern_name=p_name,
                            bytes_written=0,
                            elapsed_seconds=0.0,
                        )
                    )
                return SanitizationResult(
                    target_path=str(path),
                    algorithm=algorithm,
                    total_bytes_sanitized=0,
                    passes_completed=total_passes,
                    passes_total=total_passes,
                    success=True,
                    pass_details=pass_details,
                    started_at=start_time,
                    completed_at=time.time(),
                )

            # Perform each pass
            with open(path, "r+b") as f:
                for pass_num, (pattern_name, chunk_factory) in enumerate(pass_patterns, start=1):
                    pass_start = time.time()
                    f.seek(0)
                    bytes_remaining = file_size
                    bytes_written_this_pass = 0

                    while bytes_remaining > 0:
                        current_chunk_len = min(self.chunk_size, bytes_remaining)
                        pattern_data = chunk_factory(current_chunk_len)
                        
                        f.write(pattern_data)
                        bytes_written_this_pass += current_chunk_len
                        bytes_remaining -= current_chunk_len

                        if progress_callback:
                            progress_callback(pass_num, total_passes, bytes_written_this_pass, file_size)

                    # Flush Python internal buffers and enforce OS storage cache commitment
                    f.flush()
                    os.fsync(f.fileno())

                    pass_duration = time.time() - pass_start
                    pass_details.append(
                        PassDetail(
                            pass_number=pass_num,
                            total_passes=total_passes,
                            pattern_name=pattern_name,
                            bytes_written=bytes_written_this_pass,
                            elapsed_seconds=pass_duration,
                        )
                    )

            return SanitizationResult(
                target_path=str(path),
                algorithm=algorithm,
                total_bytes_sanitized=file_size,
                passes_completed=total_passes,
                passes_total=total_passes,
                success=True,
                pass_details=pass_details,
                started_at=start_time,
                completed_at=time.time(),
            )

        except PermissionError as pe:
            return SanitizationResult(
                target_path=str(path),
                algorithm=algorithm,
                total_bytes_sanitized=0,
                passes_completed=len(pass_details),
                passes_total=total_passes,
                success=False,
                pass_details=pass_details,
                error_message=f"Access Denied (PermissionError): {pe}",
                started_at=start_time,
                completed_at=time.time(),
            )
        except Exception as ex:
            return SanitizationResult(
                target_path=str(path),
                algorithm=algorithm,
                total_bytes_sanitized=0,
                passes_completed=len(pass_details),
                passes_total=total_passes,
                success=False,
                pass_details=pass_details,
                error_message=f"Sanitization Failed: {str(ex)}",
                started_at=start_time,
                completed_at=time.time(),
            )

    def _get_pass_count(self, algorithm: SanitizationAlgorithm) -> int:
        return len(self._get_algorithm_passes(algorithm))

    def _get_algorithm_passes(
        self, algorithm: SanitizationAlgorithm
    ) -> List[tuple[str, Callable[[int], bytes]]]:
        """Map algorithm to pass specifications and chunk generator functions."""
        if algorithm == SanitizationAlgorithm.NIST_800_88_CLEAR:
            # 1-pass random overwrite per NIST Clear procedural guideline
            return [("NIST Clear (Cryptographic Random)", BinaryPatternGenerator.random)]

        elif algorithm == SanitizationAlgorithm.LEGACY_DOD_5220_22_M:
            # Legacy DoD 3-pass overwrite: Pass 1 (0x00), Pass 2 (0xFF), Pass 3 (Random)
            return [
                ("Pass 1: Fixed Zeros (0x00)", BinaryPatternGenerator.zeros),
                ("Pass 2: Fixed Ones (0xFF)", BinaryPatternGenerator.ones),
                ("Pass 3: Pseudo-Random", BinaryPatternGenerator.random),
            ]

        elif algorithm == SanitizationAlgorithm.ZERO_OVERWRITE:
            return [("Zero Overwrite (0x00)", BinaryPatternGenerator.zeros)]

        elif algorithm == SanitizationAlgorithm.RANDOM_OVERWRITE:
            return [("Random Overwrite", BinaryPatternGenerator.random)]

        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")


# Convenient module-level functions
def overwrite_nist_clear(
    target_path: str | Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Optional[Callable[[int, int, int, int], None]] = None,
) -> SanitizationResult:
    """Perform 1-pass NIST SP 800-88 Clear overwrite (random bytes)."""
    engine = OverwriteEngine(chunk_size=chunk_size)
    return engine.sanitize_file(
        target_path,
        algorithm=SanitizationAlgorithm.NIST_800_88_CLEAR,
        progress_callback=progress_callback,
    )


def overwrite_dod_3pass(
    target_path: str | Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Optional[Callable[[int, int, int, int], None]] = None,
) -> SanitizationResult:
    """Perform legacy 3-pass DoD 5220.22-M overwrite (0x00 -> 0xFF -> Random)."""
    engine = OverwriteEngine(chunk_size=chunk_size)
    return engine.sanitize_file(
        target_path,
        algorithm=SanitizationAlgorithm.LEGACY_DOD_5220_22_M,
        progress_callback=progress_callback,
    )
