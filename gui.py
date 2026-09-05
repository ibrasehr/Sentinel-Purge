"""
Sentinel-Purge Desktop GUI
Industrial-Gothic styled forensic media sanitization dashboard powered by CustomTkinter.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Optional

try:
    import customtkinter as ctk
    from tkinter import filedialog, messagebox
except ImportError:
    print("CustomTkinter is required. Please install it using: pip install customtkinter")
    sys.exit(1)

from erasure.methods import SanitizationAlgorithm
from erasure.sanitizer import Sanitizer, compute_file_sha256
from erasure.device_detection import validate_sanitization_target, StorageMediaType


# =============================================================================
# RESOURCE PATH RESOLUTION & FONT LOADER
# =============================================================================
def get_resource_path(relative_path: str) -> str:
    """Resolve resource path for dev mode and PyInstaller frozen executable."""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


def load_gothic_font() -> str:
    """
    Locate and load custom Industrial-Gothic font file with fallback to monospaced.
    Searches bundled assets, local workspace font folder, and default user download path.
    """
    candidate_paths = [
        get_resource_path(os.path.join("font", "BootzyTM.ttf")),
        get_resource_path(os.path.join("fonts", "BootzyTM.ttf")),
        os.path.join(os.path.abspath("."), "font", "BootzyTM.ttf"),
        r"C:\Users\DELL\Downloads\font\BootzyTM.ttf",
    ]

    # Search directories dynamically for any .ttf or .otf
    for search_dir in [
        get_resource_path("font"),
        get_resource_path("fonts"),
        os.path.join(os.path.abspath("."), "font"),
        r"C:\Users\DELL\Downloads\font",
    ]:
        if os.path.exists(search_dir):
            for f in os.listdir(search_dir):
                if f.lower().endswith((".ttf", ".otf")):
                    candidate_paths.append(os.path.join(search_dir, f))

    for font_file in candidate_paths:
        if os.path.isfile(font_file):
            try:
                loaded = ctk.FontManager.load_font(font_file)
                if loaded:
                    return loaded
                return "Bootzy TM"
            except Exception as e:
                print(f"[!] Note: Could not load custom font {font_file}: {e}")

    return "Consolas"


# =============================================================================
# STRICT INDUSTRIAL-GOTHIC PALETTE
# =============================================================================
# Main Window & Canvas Background: #301934 (Deep Eggplant)
# Main Text, Values & Titles:     #CBC3E3 (Light Lavender / Parchment)
# Primary Accent:                 #AA98A9 (Dusty Industrial Lavender)
# Secondary Accent:               #51414F (Dark Grey-Purple)
PALETTE = {
    "bg_main": "#301934",        # Deep Eggplant
    "text_main": "#CBC3E3",      # Light Lavender / Parchment
    "accent_primary": "#AA98A9", # Dusty Industrial Lavender
    "accent_secondary": "#51414F", # Dark Grey-Purple
    "bg_terminal": "#301934",    # Deep Terminal Background
}

MONO_FONT = "Consolas"


def format_bytes(num_bytes: int) -> str:
    """Format byte count into human-readable representation."""
    if num_bytes < 0:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


# =============================================================================
# MAIN APPLICATION WINDOW
# =============================================================================
class SentinelPurgeApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Load Custom Gothic Font Family
        self.gothic_family = load_gothic_font()

        # Window Configuration
        self.title("SENTINEL // PURGE — INDUSTRIAL-GOTHIC SANITIZATION CONSOLE")
        self.geometry("1000x900")
        self.minsize(940, 820)
        self.configure(fg_color=PALETTE["bg_main"])

        ctk.set_appearance_mode("dark")

        # Application State
        self.selected_file: Optional[Path] = None
        self.file_size_bytes: int = 0
        self.is_sanitizing: bool = False
        self.last_certificate_path: Optional[str] = None
        self.sanitizer = Sanitizer(certificates_dir="certificates")

        # Protocol mapping
        self.protocol_map = {
            "NIST SP 800-88 Rev. 1 Clear (1-Pass Cryptographic Random)": SanitizationAlgorithm.NIST_800_88_CLEAR,
            "DoD 5220.22-M Legacy (3-Pass Zeros/Ones/Random)": SanitizationAlgorithm.LEGACY_DOD_5220_22_M,
            "Quick Zero Overwrite (1-Pass Fixed 0x00)": SanitizationAlgorithm.ZERO_OVERWRITE,
        }

        # Build UI Structure
        self._create_layout()
        self._log("SYSTEM", "Sentinel-Purge Industrial-Gothic Engine initialized.", PALETTE["accent_primary"])
        self._log("STATUS", "Engine status: READY. Select a target file to begin.", PALETTE["text_main"])

    # -------------------------------------------------------------------------
    # UI CONSTRUCTION (MODULAR ARCHITECTURAL GRID)
    # -------------------------------------------------------------------------
    def _create_layout(self):
        # Scrollable Main Workspace Canvas
        self.main_container = ctk.CTkScrollableFrame(
            self,
            fg_color=PALETTE["bg_main"],
            corner_radius=0,
            scrollbar_button_color=PALETTE["accent_secondary"],
            scrollbar_button_hover_color=PALETTE["accent_primary"],
        )
        self.main_container.pack(fill="both", expand=True, padx=24, pady=20)

        self._build_header()
        self._build_target_panel()
        self._build_controls_panel()
        self._build_telemetry_panel()
        self._build_footer()

    def _build_header(self):
        """Header Section with Gothic branding title and architectural badge."""
        header_panel = ctk.CTkFrame(
            self.main_container,
            fg_color=PALETTE["accent_secondary"],
            corner_radius=0,
            border_width=1,
            border_color=PALETTE["accent_primary"],
        )
        header_panel.pack(fill="x", pady=(0, 16), ipady=6)

        inner_frame = ctk.CTkFrame(header_panel, fg_color="transparent", corner_radius=0)
        inner_frame.pack(fill="x", padx=20, pady=12)

        # Left branding block
        brand_left = ctk.CTkFrame(inner_frame, fg_color="transparent", corner_radius=0)
        brand_left.pack(side="left", fill="y")

        title_label = ctk.CTkLabel(
            brand_left,
            text="SENTINEL // PURGE",
            font=ctk.CTkFont(family=self.gothic_family, size=24, weight="bold"),
            text_color=PALETTE["text_main"],
        )
        title_label.pack(anchor="w")

        subtitle_label = ctk.CTkLabel(
            brand_left,
            text="NIST SP 800-88 MEDIA SANITIZATION & FORENSIC DESTRUCTION ENGINE",
            font=ctk.CTkFont(family=MONO_FONT, size=11),
            text_color=PALETTE["accent_primary"],
        )
        subtitle_label.pack(anchor="w", pady=(4, 0))

        # Right status badge (architectural recess)
        self.status_badge = ctk.CTkLabel(
            inner_frame,
            text="[ ENGINE READY ]",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            text_color=PALETTE["text_main"],
            fg_color=PALETTE["bg_main"],
            corner_radius=0,
            padx=16,
            pady=8,
        )
        self.status_badge.pack(side="right", padx=0)

    def _build_target_panel(self):
        """Panel 01: Target File Selection & Metadata Inspection Grid."""
        panel = ctk.CTkFrame(
            self.main_container,
            fg_color=PALETTE["accent_secondary"],
            corner_radius=0,
            border_width=1,
            border_color=PALETTE["accent_primary"],
        )
        panel.pack(fill="x", pady=(0, 16))

        # Panel Header Bar
        header_bar = ctk.CTkFrame(panel, fg_color=PALETTE["bg_main"], corner_radius=0)
        header_bar.pack(fill="x", padx=1, pady=1)

        header_lbl = ctk.CTkLabel(
            header_bar,
            text="// 01. TARGET FILE SPECIFICATION & FORENSIC METADATA",
            font=ctk.CTkFont(family=self.gothic_family, size=13, weight="bold"),
            text_color=PALETTE["text_main"],
        )
        header_lbl.pack(anchor="w", padx=16, pady=8)

        content_area = ctk.CTkFrame(panel, fg_color="transparent", corner_radius=0)
        content_area.pack(fill="x", padx=16, pady=14)

        # Secondary Action Button (Hollow Design with Dusty Lavender Border)
        self.target_btn_card = ctk.CTkButton(
            content_area,
            text="[ + ]  BROWSE & SELECT TARGET FILE",
            font=ctk.CTkFont(family=MONO_FONT, size=13, weight="bold"),
            fg_color="transparent",
            hover_color=PALETTE["accent_secondary"],
            border_width=1,
            border_color=PALETTE["accent_primary"],
            text_color=PALETTE["accent_primary"],
            height=46,
            corner_radius=0,
            command=self._select_file_dialog,
        )
        self.target_btn_card.pack(fill="x", pady=(0, 12))

        # Metadata Inspection Recess
        details_box = ctk.CTkFrame(
            content_area,
            fg_color=PALETTE["bg_main"],
            corner_radius=0,
            border_width=1,
            border_color=PALETTE["accent_primary"],
        )
        details_box.pack(fill="x", ipady=6)

        # Target Path Row
        path_row = ctk.CTkFrame(details_box, fg_color="transparent", corner_radius=0)
        path_row.pack(fill="x", padx=14, pady=4)
        ctk.CTkLabel(
            path_row,
            text="TARGET PATH :",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            text_color=PALETTE["accent_primary"],
            width=120,
            anchor="w",
        ).pack(side="left")
        self.lbl_file_path = ctk.CTkLabel(
            path_row,
            text="No target file specified",
            font=ctk.CTkFont(family=MONO_FONT, size=11),
            text_color=PALETTE["text_main"],
            anchor="w",
        )
        self.lbl_file_path.pack(side="left", fill="x", expand=True)

        # Target Size Row
        size_row = ctk.CTkFrame(details_box, fg_color="transparent", corner_radius=0)
        size_row.pack(fill="x", padx=14, pady=4)
        ctk.CTkLabel(
            size_row,
            text="TARGET SIZE :",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            text_color=PALETTE["accent_primary"],
            width=120,
            anchor="w",
        ).pack(side="left")
        self.lbl_file_size = ctk.CTkLabel(
            size_row,
            text="—",
            font=ctk.CTkFont(family=MONO_FONT, size=11),
            text_color=PALETTE["text_main"],
            anchor="w",
        )
        self.lbl_file_size.pack(side="left", fill="x", expand=True)

        # Pre-Wipe SHA-256 Row
        hash_row = ctk.CTkFrame(details_box, fg_color="transparent", corner_radius=0)
        hash_row.pack(fill="x", padx=14, pady=4)
        ctk.CTkLabel(
            hash_row,
            text="PRE-WIPE SHA:",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            text_color=PALETTE["accent_primary"],
            width=120,
            anchor="w",
        ).pack(side="left")
        self.lbl_file_hash = ctk.CTkLabel(
            hash_row,
            text="—",
            font=ctk.CTkFont(family=MONO_FONT, size=11),
            text_color=PALETTE["text_main"],
            anchor="w",
        )
        self.lbl_file_hash.pack(side="left", fill="x", expand=True)

    def _build_controls_panel(self):
        """Panel 02: Protocol Selection, Operator Signature, and Primary Execution Button."""
        panel = ctk.CTkFrame(
            self.main_container,
            fg_color=PALETTE["accent_secondary"],
            corner_radius=0,
            border_width=1,
            border_color=PALETTE["accent_primary"],
        )
        panel.pack(fill="x", pady=(0, 16))

        # Panel Header Bar
        header_bar = ctk.CTkFrame(panel, fg_color=PALETTE["bg_main"], corner_radius=0)
        header_bar.pack(fill="x", padx=1, pady=1)

        header_lbl = ctk.CTkLabel(
            header_bar,
            text="// 02. PROTOCOL SPECIFICATION & EXECUTION CONTROL",
            font=ctk.CTkFont(family=self.gothic_family, size=13, weight="bold"),
            text_color=PALETTE["text_main"],
        )
        header_lbl.pack(anchor="w", padx=16, pady=8)

        content_area = ctk.CTkFrame(panel, fg_color="transparent", corner_radius=0)
        content_area.pack(fill="x", padx=16, pady=14)

        grid_frame = ctk.CTkFrame(content_area, fg_color="transparent", corner_radius=0)
        grid_frame.pack(fill="x", pady=(0, 14))

        # Protocol Dropdown Box
        proto_box = ctk.CTkFrame(grid_frame, fg_color="transparent", corner_radius=0)
        proto_box.pack(side="left", fill="x", expand=True, padx=(0, 10))

        ctk.CTkLabel(
            proto_box,
            text="SANITIZATION PROTOCOL",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            text_color=PALETTE["text_main"],
        ).pack(anchor="w", pady=(0, 6))

        self.protocol_dropdown = ctk.CTkOptionMenu(
            proto_box,
            values=list(self.protocol_map.keys()),
            fg_color=PALETTE["bg_main"],
            button_color=PALETTE["accent_secondary"],
            button_hover_color=PALETTE["accent_primary"],
            text_color=PALETTE["text_main"],
            dropdown_fg_color=PALETTE["accent_secondary"],
            dropdown_text_color=PALETTE["text_main"],
            dropdown_hover_color=PALETTE["accent_primary"],
            height=38,
            corner_radius=0,
            font=ctk.CTkFont(family=MONO_FONT, size=11),
        )
        self.protocol_dropdown.pack(fill="x")
        self.protocol_dropdown.set(list(self.protocol_map.keys())[0])

        # Operator Signature Box
        operator_box = ctk.CTkFrame(grid_frame, fg_color="transparent", corner_radius=0)
        operator_box.pack(side="right", fill="x", expand=True, padx=(10, 0))

        ctk.CTkLabel(
            operator_box,
            text="OPERATOR SIGNATURE / IDENTITY",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            text_color=PALETTE["text_main"],
        ).pack(anchor="w", pady=(0, 6))

        self.entry_operator = ctk.CTkEntry(
            operator_box,
            fg_color=PALETTE["bg_main"],
            border_color=PALETTE["accent_primary"],
            border_width=1,
            text_color=PALETTE["text_main"],
            placeholder_text="SecOps Lead / Forensic Officer",
            height=38,
            corner_radius=0,
            font=ctk.CTkFont(family=MONO_FONT, size=11),
        )
        self.entry_operator.pack(fill="x")
        self.entry_operator.insert(0, "SecOps Engineer")

        # Primary Execution Button (Solid fill with 2px border)
        self.btn_execute = ctk.CTkButton(
            content_area,
            text="[ ⚔ ]  EXECUTE SANITIZATION & FORENSIC PURGE",
            font=ctk.CTkFont(family=self.gothic_family, size=14, weight="bold"),
            fg_color=PALETTE["accent_secondary"],
            hover_color=PALETTE["accent_primary"],
            border_color=PALETTE["accent_primary"],
            border_width=2,
            text_color=PALETTE["text_main"],
            height=48,
            corner_radius=0,
            command=self._on_execute_click,
        )
        self.btn_execute.pack(fill="x")

    def _build_telemetry_panel(self):
        """Panel 03: Real-Time Telemetry, Entropy Display, and Live Console Stream."""
        panel = ctk.CTkFrame(
            self.main_container,
            fg_color=PALETTE["accent_secondary"],
            corner_radius=0,
            border_width=1,
            border_color=PALETTE["accent_primary"],
        )
        panel.pack(fill="both", expand=True, pady=(0, 16))

        # Panel Header Bar with Shannon Entropy readout
        header_bar = ctk.CTkFrame(panel, fg_color=PALETTE["bg_main"], corner_radius=0)
        header_bar.pack(fill="x", padx=1, pady=1)

        header_lbl = ctk.CTkLabel(
            header_bar,
            text="// 03. LIVE FORENSIC TELEMETRY & AUDIT STREAM",
            font=ctk.CTkFont(family=self.gothic_family, size=13, weight="bold"),
            text_color=PALETTE["text_main"],
        )
        header_lbl.pack(side="left", padx=16, pady=8)

        # Entropy Badge (Gothic Readout)
        self.entropy_badge = ctk.CTkLabel(
            header_bar,
            text="ENTROPY H(X): — bits/byte",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            text_color=PALETTE["text_main"],
            fg_color=PALETTE["accent_secondary"],
            corner_radius=0,
            padx=12,
            pady=4,
        )
        self.entropy_badge.pack(side="right", padx=16, pady=6)

        content_area = ctk.CTkFrame(panel, fg_color="transparent", corner_radius=0)
        content_area.pack(fill="both", expand=True, padx=16, pady=14)

        # Progress Bar
        self.progress_bar = ctk.CTkProgressBar(
            content_area,
            fg_color=PALETTE["bg_main"],
            progress_color=PALETTE["accent_primary"],
            height=8,
            corner_radius=0,
        )
        self.progress_bar.pack(fill="x", pady=(0, 4))
        self.progress_bar.set(0.0)

        self.lbl_progress = ctk.CTkLabel(
            content_area,
            text="Ready (0.0%)",
            font=ctk.CTkFont(family=MONO_FONT, size=11),
            text_color=PALETTE["text_main"],
            anchor="w",
        )
        self.lbl_progress.pack(anchor="w", pady=(0, 10))

        # Embedded Gothic Console Stream
        self.terminal_box = ctk.CTkTextbox(
            content_area,
            fg_color=PALETTE["bg_terminal"],
            text_color=PALETTE["text_main"],
            font=ctk.CTkFont(family=MONO_FONT, size=11),
            border_width=1,
            border_color=PALETTE["accent_primary"],
            corner_radius=0,
            height=200,
            wrap="word",
        )
        self.terminal_box.pack(fill="both", expand=True, pady=(0, 12))

        # Certificate Quick Actions Bar (Hollow Buttons)
        actions_bar = ctk.CTkFrame(content_area, fg_color="transparent", corner_radius=0)
        actions_bar.pack(fill="x")

        self.btn_open_cert = ctk.CTkButton(
            actions_bar,
            text="[ 📄 ]  OPEN AUDIT CERTIFICATE",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            fg_color="transparent",
            hover_color=PALETTE["accent_secondary"],
            border_width=1,
            border_color=PALETTE["accent_primary"],
            text_color=PALETTE["accent_primary"],
            height=34,
            corner_radius=0,
            command=self._open_last_certificate,
            state="disabled",
        )
        self.btn_open_cert.pack(side="left", padx=(0, 10))

        self.btn_open_dir = ctk.CTkButton(
            actions_bar,
            text="[ 📁 ]  VIEW CERTIFICATES FOLDER",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            fg_color="transparent",
            hover_color=PALETTE["accent_secondary"],
            border_width=1,
            border_color=PALETTE["accent_primary"],
            text_color=PALETTE["accent_primary"],
            height=34,
            corner_radius=0,
            command=self._open_certificates_folder,
        )
        self.btn_open_dir.pack(side="left")

    def _build_footer(self):
        """Footer Section with version and compliance signature."""
        footer_lbl = ctk.CTkLabel(
            self.main_container,
            text="SENTINEL-PURGE v1.0.0 // INDUSTRIAL-GOTHIC FORENSIC SANITIZATION FRAMEWORK",
            font=ctk.CTkFont(family=MONO_FONT, size=10),
            text_color=PALETTE["accent_primary"],
        )
        footer_lbl.pack(pady=(0, 5))

    # -------------------------------------------------------------------------
    # EVENT HANDLERS & SANITIZATION ENGINE INTEGRATION
    # -------------------------------------------------------------------------
    def _select_file_dialog(self):
        if self.is_sanitizing:
            return

        file_path = filedialog.askopenfilename(
            title="Select Target File for Secure Sanitization",
        )
        if not file_path:
            return

        self._set_selected_target(Path(file_path))

    def _set_selected_target(self, target: Path):
        self.selected_file = target.resolve()
        if not self.selected_file.exists():
            messagebox.showerror("Error", f"Target file does not exist: {self.selected_file}")
            return

        try:
            self.file_size_bytes = self.selected_file.stat().st_size
        except Exception:
            self.file_size_bytes = 0

        self.lbl_file_path.configure(text=str(self.selected_file))
        self.lbl_file_size.configure(
            text=f"{format_bytes(self.file_size_bytes)} ({self.file_size_bytes:,} bytes)"
        )
        self.lbl_file_hash.configure(text="Calculating SHA-256...")

        self._log("TARGET", f"Target selected: {self.selected_file.name} ({format_bytes(self.file_size_bytes)})", PALETTE["text_main"])

        # Check safety guardrails immediately
        scope_info = validate_sanitization_target(self.selected_file)
        if not scope_info.is_safe:
            self._log("GUARDRAIL", f"CRITICAL: Target protected! Reason: {scope_info.rejection_reason}", PALETTE["accent_primary"])
            self.status_badge.configure(text="[ TARGET BLOCKED ]")
        else:
            self.status_badge.configure(text="[ TARGET VALIDATED ]")

        # Compute SHA-256 preview in background thread
        threading.Thread(target=self._compute_hash_preview, daemon=True).start()

    def _compute_hash_preview(self):
        if not self.selected_file or not self.selected_file.exists():
            return
        try:
            h = compute_file_sha256(self.selected_file)
            self.after(0, lambda: self.lbl_file_hash.configure(text=h))
            self.after(0, lambda: self._log("HASH", f"Pre-wipe SHA-256 computed: {h[:16]}...{h[-16:]}", PALETTE["accent_primary"]))
        except Exception as e:
            self.after(0, lambda: self.lbl_file_hash.configure(text=f"Error: {e}"))

    def _on_execute_click(self):
        if self.is_sanitizing:
            return

        if not self.selected_file:
            messagebox.showwarning("Target Required", "Please select a target file first.")
            return

        if not self.selected_file.exists():
            messagebox.showerror("Target Missing", "Selected target file no longer exists.")
            return

        # Validate Guardrails
        scope_info = validate_sanitization_target(self.selected_file)
        if not scope_info.is_safe:
            messagebox.showerror("Sanitization Blocked", f"Target is protected by security guardrails:\n{scope_info.rejection_reason}")
            return

        selected_label = self.protocol_dropdown.get()
        algorithm = self.protocol_map.get(selected_label, SanitizationAlgorithm.NIST_800_88_CLEAR)
        operator = self.entry_operator.get().strip() or "SecOps Operator"

        # Confirmation Dialog
        confirm_msg = (
            f"WARNING: PERMANENT DESTRUCTIVE SANITIZATION\n\n"
            f"Target: {self.selected_file.name}\n"
            f"Size: {format_bytes(self.file_size_bytes)}\n"
            f"Algorithm: {algorithm.value}\n"
            f"Operator: {operator}\n\n"
            f"This operation will cryptographically overwrite the target sectors and unlink the filesystem metadata.\n"
            f"Are you sure you want to proceed?"
        )
        if not messagebox.askyesno("Confirm Sanitization", confirm_msg, icon="warning"):
            return

        # Begin Background Execution
        self._start_sanitization(algorithm, operator)

    def _start_sanitization(self, algorithm: SanitizationAlgorithm, operator: str):
        self.is_sanitizing = True
        self.btn_execute.configure(
            text="[ ⏳ ]  SANITIZING IN PROGRESS...",
            state="disabled",
        )
        self.target_btn_card.configure(state="disabled")
        self.protocol_dropdown.configure(state="disabled")
        self.status_badge.configure(text="[ SANITIZING ACTIVE ]")
        self.progress_bar.set(0.0)
        self.lbl_progress.configure(text="Initializing overwrite buffers...")

        self._log("EXECUTE", f"Starting sanitization workflow ({algorithm.value})", PALETTE["accent_primary"])

        worker_thread = threading.Thread(
            target=self._run_sanitization_worker,
            args=(self.selected_file, algorithm, operator),
            daemon=True,
        )
        worker_thread.start()

    def _run_sanitization_worker(self, target_path: Path, algorithm: SanitizationAlgorithm, operator: str):
        def progress_callback(pass_num: int, total_passes: int, bytes_written: int, total_bytes: int):
            fraction = (bytes_written / total_bytes) if total_bytes > 0 else 1.0
            overall = ((pass_num - 1) + fraction) / total_passes
            pct = overall * 100.0

            status_msg = f"Pass {pass_num}/{total_passes} — Overwriting: {format_bytes(bytes_written)} / {format_bytes(total_bytes)} ({pct:5.1f}%)"
            self.after(0, lambda: self._update_progress(overall, status_msg))

        try:
            result = self.sanitizer.sanitize(
                target_path=target_path,
                algorithm=algorithm,
                operator_name=operator,
                progress_callback=progress_callback,
            )
            self.after(0, lambda: self._on_sanitization_finished(result))
        except Exception as e:
            self.after(0, lambda: self._on_sanitization_error(str(e)))

    def _update_progress(self, progress: float, message: str):
        self.progress_bar.set(min(1.0, max(0.0, progress)))
        self.lbl_progress.configure(text=message)

    def _on_sanitization_finished(self, result):
        self.is_sanitizing = False
        self.btn_execute.configure(
            text="[ ⚔ ]  EXECUTE SANITIZATION & FORENSIC PURGE",
            state="normal",
        )
        self.target_btn_card.configure(state="normal")
        self.protocol_dropdown.configure(state="normal")

        if result.status == "completed":
            self.progress_bar.set(1.0)
            self.lbl_progress.configure(text="Sanitization & Verification Completed 100%")
            self.status_badge.configure(text="[ PURGE VERIFIED ]")

            # Entropy Score Readout
            entropy = result.verification.get("average_entropy", 0.0)
            self.entropy_badge.configure(
                text=f"ENTROPY H(X): {entropy:.4f} bits/byte [PASS]",
            )

            self.last_certificate_path = result.certificate_path
            if self.last_certificate_path and Path(self.last_certificate_path).exists():
                self.btn_open_cert.configure(state="normal")

            self._log("SUCCESS", f"Sanitization complete for {result.original_filename}", PALETTE["text_main"])
            self._log("VERIFY", f"Verification Status: PASSED (Shannon Entropy: {entropy:.4f} bits/byte)", PALETTE["accent_primary"])
            self._log("CERT", f"Audit certificate emitted: {result.certificate_path}", PALETTE["text_main"])

            # Clear file selection
            self.selected_file = None
            self.lbl_file_path.configure(text="Target erased and unlinked from filesystem.")
            self.lbl_file_size.configure(text="0 B (Truncated & Unlinked)")
            self.lbl_file_hash.configure(text="—")

            messagebox.showinfo(
                "Sanitization Successful",
                f"Target file successfully sanitized and verified.\n\n"
                f"Job ID: {result.id}\n"
                f"Shannon Entropy: {entropy:.4f} bits/byte\n"
                f"Certificate: {result.certificate_path}",
            )
        else:
            self.status_badge.configure(text="[ OPERATION FAILED ]")
            self._log("ERROR", f"Sanitization failed: {result.error_message}", PALETTE["accent_primary"])
            messagebox.showerror("Sanitization Failed", f"Sanitization error:\n{result.error_message}")

    def _on_sanitization_error(self, error_msg: str):
        self.is_sanitizing = False
        self.btn_execute.configure(
            text="[ ⚔ ]  EXECUTE SANITIZATION & FORENSIC PURGE",
            state="normal",
        )
        self.target_btn_card.configure(state="normal")
        self.protocol_dropdown.configure(state="normal")
        self.status_badge.configure(text="[ ERROR ]")
        self._log("EXCEPTION", f"Unexpected error during execution: {error_msg}", PALETTE["accent_primary"])
        messagebox.showerror("Execution Error", f"An unexpected error occurred:\n{error_msg}")

    def _log(self, tag: str, message: str, color_hex: str = "#CBC3E3"):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{tag:<9}] {message}\n"
        self.terminal_box.insert("end", log_entry)
        self.terminal_box.see("end")

    def _open_last_certificate(self):
        if not self.last_certificate_path:
            return
        cert_path = Path(self.last_certificate_path).resolve()
        if not cert_path.exists():
            messagebox.showerror("Error", "Certificate file not found.")
            return

        try:
            if sys.platform == "win32":
                os.startfile(str(cert_path))
            elif sys.platform == "darwin":
                subprocess.run(["open", str(cert_path)], check=True)
            else:
                subprocess.run(["xdg-open", str(cert_path)], check=True)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open certificate file: {e}")

    def _open_certificates_folder(self):
        cert_dir = Path("certificates").resolve()
        cert_dir.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(str(cert_dir))
            elif sys.platform == "darwin":
                subprocess.run(["open", str(cert_dir)], check=True)
            else:
                subprocess.run(["xdg-open", str(cert_dir)], check=True)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open certificates directory: {e}")


# =============================================================================
# ENTRY POINT
# =============================================================================
def main():
    app = SentinelPurgeApp()
    app.mainloop()


if __name__ == "__main__":
    main()
