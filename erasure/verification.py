"""
Sentinel-Purge Verification Engine
Module: erasure.verification

Post-sanitization verification engine. Inspects overwritten storage targets
to confirm data destruction efficacy using pattern matching and statistical
entropy analysis across file headers, body segments, and tail boundaries.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


DEFAULT_SAMPLE_CHUNK_SIZE: int = 4096  # 4KB sample chunk size
DEFAULT_MIN_RANDOM_ENTROPY: float = 7.2  # Threshold for cryptographic random bytes (max 8.0)


@dataclass
class SampleChunkResult:
    """Telemetry for a single sampled binary chunk."""
    location: str  # "header", "body_N", "tail", "full_file"
    offset: int
    size: int
    entropy: float
    matches_pattern: Optional[bool]
    all_zeros: bool
    all_ones: bool


@dataclass
class VerificationReport:
    """Comprehensive forensic verification report for audit logs and certificates."""
    target_path: str
    passed: bool
    file_size_bytes: int
    sample_sectors_checked: int
    residual_data_found: bool
    average_entropy: float
    expected_pattern_type: str
    details: str
    sampled_chunks: List[SampleChunkResult] = field(default_factory=list)


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Compute empirical Shannon entropy in bits per byte (0.0 to 8.0).
    H = - sum(p(x) * log2(p(x)))
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)

    return round(entropy, 4)


class VerificationEngine:
    """
    Independent binary verification engine for storage sanitization audits.
    Samples binary chunks across header, body, and tail to verify sanitization.
    """

    def __init__(
        self,
        sample_chunk_size: int = DEFAULT_SAMPLE_CHUNK_SIZE,
        num_body_samples: int = 3,
        min_random_entropy: float = DEFAULT_MIN_RANDOM_ENTROPY,
    ) -> None:
        self.sample_chunk_size = sample_chunk_size
        self.num_body_samples = num_body_samples
        self.min_random_entropy = min_random_entropy

    def verify(
        self,
        target_path: str | Path,
        expected_pattern: Optional[bytes] = None,
    ) -> bool:
        """
        Verify that target file was properly sanitized.
        Returns True if verification passes, False otherwise.
        """
        report = self.inspect(target_path, expected_pattern=expected_pattern)
        return report.passed

    def inspect(
        self,
        target_path: str | Path,
        expected_pattern: Optional[bytes] = None,
    ) -> VerificationReport:
        """
        Perform detailed inspection of the target file across header, body, and tail.
        Returns a VerificationReport with full telemetry.
        """
        path = Path(target_path).resolve()

        if not path.is_file():
            return VerificationReport(
                target_path=str(path),
                passed=False,
                file_size_bytes=0,
                sample_sectors_checked=0,
                residual_data_found=True,
                average_entropy=0.0,
                expected_pattern_type="unknown",
                details=f"Target file '{path}' does not exist or is not a regular file.",
            )

        file_size = path.stat().st_size

        # Handle 0-byte empty file edge case
        if file_size == 0:
            return VerificationReport(
                target_path=str(path),
                passed=True,
                file_size_bytes=0,
                sample_sectors_checked=0,
                residual_data_found=False,
                average_entropy=0.0,
                expected_pattern_type="empty_file",
                details="0-byte file verified: no residual bytes exist.",
            )

        # Build list of sample offsets: Header, Body (distributed), Tail
        sample_offsets = self._calculate_sample_offsets(file_size)
        sampled_results: List[SampleChunkResult] = []

        with open(path, "rb") as f:
            for loc_name, offset, read_len in sample_offsets:
                f.seek(offset)
                chunk_data = f.read(read_len)
                
                if not chunk_data:
                    continue

                entropy = calculate_shannon_entropy(chunk_data)
                all_zeros = chunk_data == b"\x00" * len(chunk_data)
                all_ones = chunk_data == b"\xFF" * len(chunk_data)

                # Check pattern match if an expected pattern was provided
                matches_pattern: Optional[bool] = None
                if expected_pattern is not None:
                    matches_pattern = self._matches_expected_pattern(chunk_data, expected_pattern)

                sampled_results.append(
                    SampleChunkResult(
                        location=loc_name,
                        offset=offset,
                        size=len(chunk_data),
                        entropy=entropy,
                        matches_pattern=matches_pattern,
                        all_zeros=all_zeros,
                        all_ones=all_ones,
                    )
                )

        if not sampled_results:
            return VerificationReport(
                target_path=str(path),
                passed=False,
                file_size_bytes=file_size,
                sample_sectors_checked=0,
                residual_data_found=True,
                average_entropy=0.0,
                expected_pattern_type="unknown",
                details="Failed to read sample chunks from target file.",
            )

        # Evaluate verification criteria
        avg_entropy = round(
            sum(r.entropy for r in sampled_results) / len(sampled_results), 4
        )

        passed, residual_found, pattern_type_desc, details = self._evaluate_results(
            sampled_results, file_size, expected_pattern, avg_entropy
        )

        return VerificationReport(
            target_path=str(path),
            passed=passed,
            file_size_bytes=file_size,
            sample_sectors_checked=len(sampled_results),
            residual_data_found=residual_found,
            average_entropy=avg_entropy,
            expected_pattern_type=pattern_type_desc,
            details=details,
            sampled_chunks=sampled_results,
        )

    def _calculate_sample_offsets(self, file_size: int) -> List[Tuple[str, int, int]]:
        """Compute (location_name, offset, read_length) tuples across header, body, tail."""
        if file_size <= self.sample_chunk_size:
            return [("full_file", 0, file_size)]

        offsets: List[Tuple[str, int, int]] = []

        # 1. Header (start of file)
        header_len = min(self.sample_chunk_size, file_size)
        offsets.append(("header", 0, header_len))

        # 2. Body (evenly distributed across mid-section)
        body_start = header_len
        body_end = max(header_len, file_size - self.sample_chunk_size)
        body_span = body_end - body_start

        if body_span > 0 and self.num_body_samples > 0:
            step = body_span / (self.num_body_samples + 1)
            for i in range(1, self.num_body_samples + 1):
                sample_pos = int(body_start + (i * step))
                sample_len = min(self.sample_chunk_size, file_size - sample_pos)
                if sample_len > 0:
                    offsets.append((f"body_{i}", sample_pos, sample_len))

        # 3. Tail (end of file)
        tail_offset = max(0, file_size - self.sample_chunk_size)
        tail_len = file_size - tail_offset
        if tail_offset > 0:
            offsets.append(("tail", tail_offset, tail_len))

        return offsets

    def _matches_expected_pattern(self, chunk: bytes, expected: bytes) -> bool:
        """Check if chunk strictly consists of the repeating expected pattern."""
        if not expected:
            return True
        pattern_len = len(expected)
        full_repeats = len(chunk) // pattern_len
        remainder = len(chunk) % pattern_len
        expected_full = (expected * (full_repeats + 1))[: len(chunk)]
        return chunk == expected_full

    def _evaluate_results(
        self,
        sampled_results: List[SampleChunkResult],
        file_size: int,
        expected_pattern: Optional[bytes],
        avg_entropy: float,
    ) -> Tuple[bool, bool, str, str]:
        """Determine overall pass/fail status based on pattern matching or entropy analysis."""
        # Case 1: Explicit pattern verification (e.g. zeros, 0xFF, specific byte sequence)
        if expected_pattern is not None:
            pattern_hex = expected_pattern.hex().upper()
            all_matched = all(r.matches_pattern for r in sampled_results)

            if all_matched:
                return (
                    True,
                    False,
                    f"Fixed Pattern (0x{pattern_hex})",
                    f"All {len(sampled_results)} sampled regions strictly matched pattern 0x{pattern_hex}.",
                )
            else:
                mismatches = [r.location for r in sampled_results if not r.matches_pattern]
                return (
                    False,
                    True,
                    f"Fixed Pattern (0x{pattern_hex})",
                    f"Pattern mismatch in sampled region(s): {', '.join(mismatches)}. Residual data detected.",
                )

        # Case 2: Random overwrite verification (NIST Clear / Random pass)
        # Random data must exhibit high Shannon entropy (typically >= 7.2 for chunks >= 512 bytes)
        # Small files (< 256 bytes) have natural entropy bounds due to sample size
        threshold = self.min_random_entropy if file_size >= 512 else max(3.0, (file_size / 256.0) * 7.0)
        
        low_entropy_regions = [
            r.location for r in sampled_results if r.entropy < threshold and r.size >= 256
        ]

        # Also check if chunks are all 0x00 or all identical repeating bytes when random was expected
        single_byte_runs = [
            r.location for r in sampled_results if r.all_zeros or r.all_ones
        ]

        if not low_entropy_regions and not single_byte_runs:
            return (
                True,
                False,
                "Cryptographic Random / High Entropy",
                f"High Shannon entropy confirmed across all {len(sampled_results)} sampled regions (avg: {avg_entropy:.2f} bits/byte).",
            )
        else:
            failures = list(set(low_entropy_regions + single_byte_runs))
            return (
                False,
                True,
                "Cryptographic Random / High Entropy",
                f"Failed random verification in region(s): {', '.join(failures)} (avg entropy: {avg_entropy:.2f} < threshold {threshold:.2f}).",
            )


# Module-level convenience functions
def verify_erasure(
    target_path: str | Path,
    expected_pattern: Optional[bytes] = None,
    sample_size: int = DEFAULT_SAMPLE_CHUNK_SIZE,
    num_body_samples: int = 3,
    min_entropy: float = DEFAULT_MIN_RANDOM_ENTROPY,
) -> bool:
    """
    Independent post-wipe verification engine.
    Opens the overwritten file, samples binary chunks across header, body, and tail,
    calculates pattern matching or entropy, and returns a boolean status (True/False).

    Args:
        target_path: Path to the target overwritten file.
        expected_pattern: Optional expected byte pattern (e.g. b"\x00"). If None, checks random entropy.
        sample_size: Size in bytes of each sample chunk.
        num_body_samples: Number of distributed samples to take from the body section.
        min_entropy: Minimum Shannon entropy required for random overwrite verification.

    Returns:
        True if sanitization is verified effective, False otherwise.
    """
    engine = VerificationEngine(
        sample_chunk_size=sample_size,
        num_body_samples=num_body_samples,
        min_random_entropy=min_entropy,
    )
    return engine.verify(target_path, expected_pattern=expected_pattern)


def inspect_erasure(
    target_path: str | Path,
    expected_pattern: Optional[bytes] = None,
    sample_size: int = DEFAULT_SAMPLE_CHUNK_SIZE,
    num_body_samples: int = 3,
    min_entropy: float = DEFAULT_MIN_RANDOM_ENTROPY,
) -> VerificationReport:
    """
    Perform a complete forensic inspection of an erased file and return a rich VerificationReport.
    """
    engine = VerificationEngine(
        sample_chunk_size=sample_size,
        num_body_samples=num_body_samples,
        min_random_entropy=min_entropy,
    )
    return engine.inspect(target_path, expected_pattern=expected_pattern)
