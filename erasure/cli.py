"""
Sentinel-Purge CLI
Module: erasure.cli

Unified Command-Line Interface for Secure Data Sanitization, Forensic Inspection,
Target Scope Validation, Authorized Clear/Purge Operations, and Server Orchestration.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import Optional

from erasure.device_detection import (
    StorageMediaType,
    TargetScopeValidator,
    check_target_safety,
    validate_sanitization_target,
)
from erasure.handler import handle_clear, handle_purge
from erasure.methods import SanitizationAlgorithm
from erasure.sanitizer import Sanitizer, sanitize_file
from erasure.verification import (
    DEFAULT_MIN_RANDOM_ENTROPY,
    VerificationEngine,
    calculate_shannon_entropy,
    inspect_erasure,
)


def _format_bytes(num_bytes: int) -> str:
    """Format bytes to human readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def cmd_sanitize(args: argparse.Namespace) -> int:
    """Execute forensic sanitization on a target file."""
    target_path = Path(args.target).resolve()
    print("=" * 70)
    print("           SENTINEL-PURGE SANITIZATION ENGINE                         ")
    print("=" * 70)
    print(f"Target file     : {target_path}")
    print(f"Algorithm       : {args.algorithm}")
    print(f"Operator        : {args.operator}")
    print(f"Certificates dir: {args.certificates_dir}")
    print("-" * 70)

    if not target_path.exists():
        print(f"[ERROR] Target file does not exist: {target_path}", file=sys.stderr)
        return 1

    # Progress bar callback
    def progress_callback(pass_num: int, total_passes: int, bytes_written: int, total_bytes: int):
        pct = (bytes_written / total_bytes * 100.0) if total_bytes > 0 else 100.0
        bar_len = 30
        filled = int(bar_len * bytes_written // total_bytes) if total_bytes > 0 else bar_len
        bar = "=" * filled + "-" * (bar_len - filled)
        sys.stdout.write(
            f"\r[PASS {pass_num}/{total_passes}] [{bar}] {pct:5.1f}% ({_format_bytes(bytes_written)}/{_format_bytes(total_bytes)})"
        )
        sys.stdout.flush()

    sanitizer = Sanitizer(certificates_dir=args.certificates_dir)
    result = sanitizer.sanitize(
        target_path=target_path,
        algorithm=args.algorithm,
        operator_name=args.operator,
        progress_callback=progress_callback,
    )
    print()  # newline after progress bar
    print("-" * 70)
    print(f"Job Status          : {result.status.upper()}")
    print(f"Job ID              : {result.id}")
    print(f"Pre-Wipe SHA-256    : {result.pre_wipe_sha256}")
    print(f"Verification Status : {result.verification_status.upper()}")

    if result.verification:
        print(f"Average Entropy     : {result.verification.get('average_entropy', 'N/A')} bits/byte")
        print(f"Verification Detail : {result.verification.get('details', 'N/A')}")

    if result.certificate_path:
        print(f"Certificate Saved   : {result.certificate_path}")

    if result.status == "completed":
        print("[SUCCESS] Sanitization & forensic verification completed successfully.")
        return 0
    else:
        print(f"[FAILED] Error: {result.error_message}", file=sys.stderr)
        return 1


def cmd_verify(args: argparse.Namespace) -> int:
    """Perform post-sanitization binary and Shannon entropy inspection."""
    target_path = Path(args.target).resolve()
    print("=" * 70)
    print("           SENTINEL-PURGE INDEPENDENT VERIFICATION ENGINE             ")
    print("=" * 70)
    print(f"Target file: {target_path}")

    if not target_path.exists():
        print(f"[ERROR] Target file does not exist: {target_path}", file=sys.stderr)
        return 1

    expected_pat = None
    if args.expected_pattern == "zeros":
        expected_pat = b"\x00"
    elif args.expected_pattern == "ones":
        expected_pat = b"\xFF"

    report = inspect_erasure(target_path, expected_pattern=expected_pat)

    print(f"File Size Checked   : {_format_bytes(report.file_size_bytes)} ({report.file_size_bytes} bytes)")
    print(f"Sample Sectors      : {report.sample_sectors_checked}")
    print(f"Average Entropy     : {report.average_entropy:.4f} bits/byte (Threshold: >= {DEFAULT_MIN_RANDOM_ENTROPY})")
    print(f"Residual Data Found : {report.residual_data_found}")
    print(f"Expected Pattern    : {report.expected_pattern_type}")
    print(f"Verification Detail : {report.details}")
    print("-" * 70)

    if report.sampled_chunks:
        print("Sampled Sector Breakdown:")
        for sc in report.sampled_chunks:
            print(f"  [{sc.location:^10}] Offset: {sc.offset:<8} Size: {sc.size:<5} Entropy: {sc.entropy:.4f} bits/byte")
        print("-" * 70)

    if report.passed:
        print("[SUCCESS] Verification PASSED.")
        return 0
    else:
        print("[FAILURE] Verification FAILED.", file=sys.stderr)
        return 1


def cmd_check_target(args: argparse.Namespace) -> int:
    """Validate safety boundaries and hardware media type for a target path."""
    target_path = Path(args.target)
    print("=" * 70)
    print("           SENTINEL-PURGE TARGET SCOPE & SAFETY VALIDATOR             ")
    print("=" * 70)
    print(f"Inspecting path: {target_path}")

    scope_info = validate_sanitization_target(target_path)

    print(f"Safety Status    : {'SAFE' if scope_info.is_safe else 'REJECTED / UNSAFE'}")
    print(f"Media Type       : {scope_info.media_type.value}")
    print(f"Target Size      : {_format_bytes(scope_info.size_bytes)} ({scope_info.size_bytes} bytes)")
    print(f"Read-Only Flag   : {scope_info.is_read_only}")
    print(f"Directory Flag   : {scope_info.is_directory}")
    print(f"Block Device     : {scope_info.is_block_device}")

    if scope_info.rejection_reason:
        print(f"Rejection Reason : {scope_info.rejection_reason}")

    print("-" * 70)
    if scope_info.is_safe:
        print("[APPROVED] Target is safe for sanitization.")
        return 0
    else:
        print("[BLOCKED] Target is protected and CANNOT be erased.", file=sys.stderr)
        return 1


def cmd_handler_op(args: argparse.Namespace, operation: str) -> int:
    """Execute authorized Clear or Purge with secret-key gating."""
    target_path = Path(args.target).resolve()
    key = args.key
    if not key:
        key = getpass.getpass("Enter Authorization Secret Key: ")

    print(f"Executing {operation.upper()} on {target_path}...")
    if operation == "clear":
        result = handle_clear(target_path, key)
    else:
        result = handle_purge(target_path, key)

    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 1


def cmd_serve(args: argparse.Namespace) -> int:
    """Start the Sentinel-Purge Web UI & REST API server."""
    from erasure.server import app, STATIC_DIR, UPLOAD_DIR
    print("=" * 70)
    print("           SENTINEL-PURGE WEB SERVER                                  ")
    print("=" * 70)
    print(f"Static directory : {STATIC_DIR}")
    print(f"Upload directory : {UPLOAD_DIR}")
    print(f"Serving at       : http://{args.host}:{args.port}")
    print("=" * 70)
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m erasure.cli",
        description="Sentinel-Purge Forensic Data Erasure & Sanitization CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # sanitize command
    p_sanitize = subparsers.add_parser("sanitize", help="Sanitize a target file with forensic overwrite & verification")
    p_sanitize.add_argument("target", help="Path to target file to sanitize")
    p_sanitize.add_argument(
        "-a", "--algorithm",
        choices=[a.value for a in SanitizationAlgorithm],
        default=SanitizationAlgorithm.NIST_800_88_CLEAR.value,
        help="Sanitization algorithm standard (default: NIST_SP_800_88_CLEAR)",
    )
    p_sanitize.add_argument(
        "-o", "--operator",
        default="CLI Operator",
        help="Name or ID of forensic operator",
    )
    p_sanitize.add_argument(
        "-c", "--certificates-dir",
        default="certificates",
        help="Directory to write JSON audit certificates (default: certificates/)",
    )

    # verify command
    p_verify = subparsers.add_parser("verify", help="Inspect binary sectors & Shannon entropy of a file")
    p_verify.add_argument("target", help="Path to file to inspect")
    p_verify.add_argument(
        "-p", "--expected-pattern",
        choices=["random", "zeros", "ones"],
        default="random",
        help="Expected pattern type (default: random)",
    )

    # check-target command
    p_check = subparsers.add_parser("check-target", help="Validate safety boundaries & media scope of target")
    p_check.add_argument("target", help="Path or drive to inspect")

    # clear command
    p_clear = subparsers.add_parser("clear", help="Execute authorized Clear operation (zero overwrite + truncate)")
    p_clear.add_argument("target", help="Path to file")
    p_clear.add_argument("-k", "--key", default=None, help="Secret authorization key")

    # purge command
    p_purge = subparsers.add_parser("purge", help="Execute authorized Purge operation (random overwrite + unlink)")
    p_purge.add_argument("target", help="Path to file")
    p_purge.add_argument("-k", "--key", default=None, help="Secret authorization key")

    # serve command
    p_serve = subparsers.add_parser("serve", help="Launch the Web UI & API server")
    p_serve.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    p_serve.add_argument("--debug", action="store_true", help="Enable debug mode")

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "sanitize":
        return cmd_sanitize(args)
    elif args.command == "verify":
        return cmd_verify(args)
    elif args.command == "check-target":
        return cmd_check_target(args)
    elif args.command == "clear":
        return cmd_handler_op(args, "clear")
    elif args.command == "purge":
        return cmd_handler_op(args, "purge")
    elif args.command == "serve":
        return cmd_serve(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
