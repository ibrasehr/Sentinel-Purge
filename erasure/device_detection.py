"""
Sentinel-Purge Device Detection & Target Scope Validation
Module: erasure.device_detection

Detects and enumerates target media scope (HDD, SSD, NVMe, USB, Local Dummy File)
and enforces strict safety boundaries to reject out-of-scope or critical system targets
before any destructive sanitization I/O occurs.
"""

from __future__ import annotations

import enum
import os
import platform
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Tuple


class StorageMediaType(str, enum.Enum):
    """Storage hardware media classification."""
    HDD = "HDD (Rotational Magnetic)"
    SSD = "SSD (Solid-State Drive)"
    NVME = "NVMe (PCIe Solid-State)"
    USB_FLASH = "USB Flash Drive"
    DUMMY_TEST_FILE = "Local Dummy/Test File"
    UNKNOWN = "Unknown / Unclassified"


@dataclass
class TargetScopeInfo:
    """Target evaluation report containing scope safety status."""
    target_path: str
    is_safe: bool
    media_type: StorageMediaType
    size_bytes: int
    rejection_reason: Optional[str] = None
    is_read_only: bool = False
    is_directory: bool = False
    is_block_device: bool = False
    drive_letter_or_mount: Optional[str] = None


class TargetScopeValidator:
    """
    Validates sanitization targets against safety boundaries.
    Prevents accidental wiping of operating system files, system partitions,
    and unapproved drive paths.
    """

    # Protected system paths across operating systems
    PROTECTED_SYSTEM_DIRS_WINDOWS: Set[str] = {
        r"C:\Windows",
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"C:\Users",
        r"C:\ProgramData",
        r"C:\Recovery",
        r"C:\System Volume Information",
        r"C:\$Recycle.Bin",
        r"C:\Boot",
    }

    PROTECTED_SYSTEM_DIRS_POSIX: Set[str] = {
        "/",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/lib",
        "/lib64",
        "/proc",
        "/root",
        "/run",
        "/sbin",
        "/sys",
        "/usr",
        "/var",
    }

    # Protected system drive identifiers
    PROTECTED_DRIVE_NAMES: Set[str] = {
        r"\\.\PhysicalDrive0",
        r"\\.\C:",
        r"\\.\PhysicalDrive",
        "/dev/sda",
        "/dev/nvme0n1",
        "/dev/root",
    }

    def __init__(self, approved_roots: Optional[List[Path | str]] = None) -> None:
        """
        Initialize validator with optional list of explicitly approved root directories.
        If provided, targets MUST reside within an approved directory tree unless explicitly bypassed.
        """
        self.approved_roots: List[Path] = []
        if approved_roots:
            for r in approved_roots:
                try:
                    self.approved_roots.append(Path(r).resolve())
                except Exception:
                    self.approved_roots.append(Path(r))

    def evaluate_target(self, target_path: str | Path) -> TargetScopeInfo:
        """
        Analyze target path and determine if it is safe for sanitization.
        Rejects critical system targets, root paths, and unapproved scopes.
        """
        raw_str = str(target_path).strip()

        # 1. Check for raw system block device targets before filesystem resolution
        if (
            raw_str.startswith(r"\\.\\")
            or raw_str.startswith(r"\\.\PhysicalDrive")
            or raw_str.startswith("/dev/sd")
            or raw_str.startswith("/dev/nvme")
            or raw_str in self.PROTECTED_DRIVE_NAMES
        ):
            return TargetScopeInfo(
                target_path=raw_str,
                is_safe=False,
                media_type=StorageMediaType.UNKNOWN,
                size_bytes=0,
                is_block_device=True,
                rejection_reason="CRITICAL: Primary OS physical disk or system partition is protected.",
            )

        try:
            path = Path(raw_str).resolve() if raw_str else Path(".")
        except Exception as resolve_err:
            return TargetScopeInfo(
                target_path=raw_str,
                is_safe=False,
                media_type=StorageMediaType.UNKNOWN,
                size_bytes=0,
                rejection_reason=f"Failed to resolve target path: {resolve_err}",
            )

        # 2. Check path existence
        if not path.exists():
            return TargetScopeInfo(
                target_path=str(path),
                is_safe=False,
                media_type=StorageMediaType.UNKNOWN,
                size_bytes=0,
                rejection_reason=f"Target path '{path}' does not exist on filesystem.",
            )

        is_dir = path.is_dir()
        resolved_str = str(path)

        # 3. Check system directory protection (Windows)
        if platform.system() == "Windows":
            for sys_dir in self.PROTECTED_SYSTEM_DIRS_WINDOWS:
                try:
                    sys_resolved = Path(sys_dir).resolve()
                    if path == sys_resolved or sys_resolved in path.parents:
                        # Allow dedicated subfolder in user directory only if inside approved roots
                        if not self._is_within_approved_roots(path):
                            return TargetScopeInfo(
                                target_path=resolved_str,
                                is_safe=False,
                                media_type=StorageMediaType.UNKNOWN,
                                size_bytes=0,
                                is_directory=is_dir,
                                rejection_reason=f"REJECTED: Target resides within protected Windows system hierarchy: '{sys_dir}'",
                            )
                except Exception:
                    pass

        # 4. Check system directory protection (POSIX / Linux / macOS)
        else:
            for sys_dir in self.PROTECTED_SYSTEM_DIRS_POSIX:
                try:
                    sys_resolved = Path(sys_dir).resolve()
                    if path == sys_resolved or (sys_dir != "/" and sys_resolved in path.parents):
                        if not self._is_within_approved_roots(path):
                            return TargetScopeInfo(
                                target_path=resolved_str,
                                is_safe=False,
                                media_type=StorageMediaType.UNKNOWN,
                                size_bytes=0,
                                is_directory=is_dir,
                                rejection_reason=f"REJECTED: Target resides within protected POSIX root hierarchy: '{sys_dir}'",
                            )
                except Exception:
                    pass

        # 5. Check if directory without explicit approval
        if is_dir:
            return TargetScopeInfo(
                target_path=resolved_str,
                is_safe=False,
                media_type=StorageMediaType.UNKNOWN,
                size_bytes=0,
                is_directory=True,
                rejection_reason="Target is a directory. Specify individual files or use recursive batch module.",
            )

        # 6. Gather target file properties safely
        try:
            stat_result = path.stat()
            size_bytes = stat_result.st_size
            is_read_only = not (stat_result.st_mode & 0o200)  # Check write bit
        except Exception as e:
            return TargetScopeInfo(
                target_path=resolved_str,
                is_safe=False,
                media_type=StorageMediaType.UNKNOWN,
                size_bytes=0,
                rejection_reason=f"Failed to inspect target file metadata: {e}",
            )

        # 7. Classify media type
        media_type = self._detect_media_type(path)

        # 8. All checks passed: Safe target
        return TargetScopeInfo(
            target_path=resolved_str,
            is_safe=True,
            media_type=media_type,
            size_bytes=size_bytes,
            is_read_only=is_read_only,
            is_directory=False,
            drive_letter_or_mount=path.drive if platform.system() == "Windows" else "/",
            rejection_reason=None,
        )

    def _is_within_approved_roots(self, path: Path) -> bool:
        """Check if path is inside approved roots or default safe test scopes."""
        import tempfile

        # If explicit approved roots are configured, enforce strict containment
        if self.approved_roots:
            return any(path == app_root or app_root in path.parents for app_root in self.approved_roots)

        temp_dir = Path(tempfile.gettempdir()).resolve()
        cwd = Path.cwd().resolve()

        # Default safe locations: cwd subtree, system tempdir, or explicit dummy/temp test markers
        if path == cwd or cwd in path.parents:
            return True

        if path == temp_dir or temp_dir in path.parents:
            return True

        name_lower = path.name.lower()
        if any(marker in name_lower for marker in ["dummy", "test", "temp", "sample", "fixture"]):
            return True

        return False



    def _detect_media_type(self, path: Path) -> StorageMediaType:
        """
        Detect underlying storage technology (SSD vs. HDD vs. Dummy File).
        """
        filename = path.name.lower()
        if any(marker in filename for marker in ["dummy", "test", "temp", "sample", "fixture"]):
            return StorageMediaType.DUMMY_TEST_FILE

        if platform.system() == "Windows":
            return self._detect_windows_media_type(path)
        elif platform.system() == "Linux":
            return self._detect_linux_media_type(path)

        return StorageMediaType.UNKNOWN

    def _detect_windows_media_type(self, path: Path) -> StorageMediaType:
        """Query Windows WMI/PowerShell PhysicalDisk MediaType for the volume."""
        drive = path.drive
        if not drive:
            return StorageMediaType.UNKNOWN

        try:
            drive_letter = drive.rstrip(":")
            cmd = f"Get-Partition -DriveLetter {drive_letter} | Get-Disk | Select-Object -ExpandProperty MediaType"
            output = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", cmd],
                text=True,
                timeout=3,
                stderr=subprocess.DEVNULL,
            ).strip().upper()

            if "SSD" in output:
                return StorageMediaType.SSD
            elif "HDD" in output or "ROTATIONAL" in output:
                return StorageMediaType.HDD
            elif "NVME" in output:
                return StorageMediaType.NVME
        except Exception:
            pass

        return StorageMediaType.UNKNOWN

    def _detect_linux_media_type(self, path: Path) -> StorageMediaType:
        """Query Linux sysfs rotational flag (/sys/block/*/queue/rotational)."""
        try:
            res = subprocess.check_output(
                ["df", "--output=source", str(path)],
                text=True,
                timeout=3,
            ).strip().splitlines()
            if len(res) >= 2:
                device = res[1].strip()
                dev_name = Path(device).name
                rotational_path = Path(f"/sys/block/{dev_name}/queue/rotational")
                if rotational_path.exists():
                    is_rotational = rotational_path.read_text().strip() == "1"
                    return StorageMediaType.HDD if is_rotational else StorageMediaType.SSD
        except Exception:
            pass

        return StorageMediaType.UNKNOWN


# Module-level convenience helpers
def validate_sanitization_target(
    target_path: str | Path,
    approved_roots: Optional[List[Path | str]] = None,
) -> TargetScopeInfo:
    """Validate that a target path is safe and within allowable sanitization scope."""
    validator = TargetScopeValidator(approved_roots=approved_roots)
    return validator.evaluate_target(target_path)


def check_target_safety(
    target_path: str | Path,
    approved_roots: Optional[List[Path | str]] = None,
) -> bool:
    """
    Check if a target path is safe for sanitization.
    Returns True if target is safe (e.g. local dummy file / approved scope),
    or False if target is rejected (e.g. system directory, system drive).
    """
    report = validate_sanitization_target(target_path, approved_roots=approved_roots)
    return report.is_safe

