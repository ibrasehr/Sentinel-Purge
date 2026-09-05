"""
Sentinel-Purge Core Engine
Package for secure data sanitization, device detection, verification, and forensic audit certification.
"""

from erasure.methods import (
    DEFAULT_CHUNK_SIZE,
    BinaryPatternGenerator,
    OverwriteEngine,
    PassDetail,
    SanitizationAlgorithm,
    SanitizationResult,
    overwrite_dod_3pass,
    overwrite_nist_clear,
)
from erasure.device_detection import (
    StorageMediaType,
    TargetScopeInfo,
    TargetScopeValidator,
    check_target_safety,
    validate_sanitization_target,
)
from erasure.verification import (
    DEFAULT_MIN_RANDOM_ENTROPY,
    DEFAULT_SAMPLE_CHUNK_SIZE,
    SampleChunkResult,
    VerificationEngine,
    VerificationReport,
    calculate_shannon_entropy,
    inspect_erasure,
    verify_erasure,
)
from erasure.sanitizer import (
    SanitizationJobResult,
    Sanitizer,
    compute_file_sha256,
    generate_random_filename,
    sanitize_file,
)
from erasure.audit_trail import (
    AuditEntry,
    AuditTrail,
)
from erasure.handler import (
    authorize,
    handle_clear,
    handle_purge,
)

__all__ = [
    # Methods
    "DEFAULT_CHUNK_SIZE",
    "BinaryPatternGenerator",
    "OverwriteEngine",
    "PassDetail",
    "SanitizationAlgorithm",
    "SanitizationResult",
    "overwrite_dod_3pass",
    "overwrite_nist_clear",
    # Device Detection
    "StorageMediaType",
    "TargetScopeInfo",
    "TargetScopeValidator",
    "check_target_safety",
    "validate_sanitization_target",
    # Verification
    "DEFAULT_SAMPLE_CHUNK_SIZE",
    "DEFAULT_MIN_RANDOM_ENTROPY",
    "SampleChunkResult",
    "VerificationEngine",
    "VerificationReport",
    "calculate_shannon_entropy",
    "inspect_erasure",
    "verify_erasure",
    # Sanitizer Orchestrator
    "SanitizationJobResult",
    "Sanitizer",
    "compute_file_sha256",
    "generate_random_filename",
    "sanitize_file",
    # Handler & Auth
    "authorize",
    "handle_clear",
    "handle_purge",
    # Audit Trail
    "AuditEntry",
    "AuditTrail",
]
