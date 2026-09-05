"""
Sentinel-Purge PyInstaller Build Automation Script
Compiles gui.py into a standalone, single-file executable (Sentinel-Purge.exe).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def check_dependencies():
    """Ensure pyinstaller and customtkinter are installed."""
    try:
        import PyInstaller
        print(f"[+] Found PyInstaller version: {PyInstaller.__version__}")
    except ImportError:
        print("[-] PyInstaller not found. Installing pyinstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    try:
        import customtkinter
        print(f"[+] Found CustomTkinter version: {customtkinter.__version__}")
    except ImportError:
        print("[-] CustomTkinter not found. Installing customtkinter...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "customtkinter"])


def build_executable():
    """Execute PyInstaller build pipeline."""
    base_dir = Path(__file__).resolve().parent
    gui_script = base_dir / "gui.py"
    dist_dir = base_dir / "dist"
    build_dir = base_dir / "build"

    print("=" * 70)
    print("        SENTINEL // PURGE — STANDALONE EXECUTABLE BUILDER            ")
    print("=" * 70)
    print(f"Target Script: {gui_script}")
    print(f"Output Target: {dist_dir / 'Sentinel-Purge.exe'}")
    print("-" * 70)

    if not gui_script.exists():
        print(f"[-] Error: {gui_script} not found!", file=sys.stderr)
        sys.exit(1)

    # PyInstaller arguments
    pyinstaller_args = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconsole",
        "--onefile",
        "--name=Sentinel-Purge",
        "--clean",
        "--collect-all=customtkinter",
        "--hidden-import=erasure",
        "--hidden-import=erasure.methods",
        "--hidden-import=erasure.sanitizer",
        "--hidden-import=erasure.verification",
        "--hidden-import=erasure.device_detection",
        "--hidden-import=erasure.audit_trail",
        "--hidden-import=erasure.handler",
        str(gui_script),
    ]

    print("[*] Running PyInstaller build command...")
    print(f"    {' '.join(pyinstaller_args)}")
    print("-" * 70)

    try:
        result = subprocess.run(pyinstaller_args, cwd=str(base_dir), check=True)
        if result.returncode == 0:
            exe_path = dist_dir / ("Sentinel-Purge.exe" if sys.platform == "win32" else "Sentinel-Purge")
            print("=" * 70)
            print("[SUCCESS] Build completed successfully!")
            print(f"          Standalone Executable: {exe_path.resolve()}")
            print("=" * 70)
    except subprocess.CalledProcessError as e:
        print(f"[-] PyInstaller compilation failed with code: {e.returncode}", file=sys.stderr)
        sys.exit(e.returncode)


if __name__ == "__main__":
    check_dependencies()
    build_executable()
