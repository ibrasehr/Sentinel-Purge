"""
Sentinel-Purge Desktop GUI
Cyberpunk-styled forensic media sanitization dashboard powered by CustomTkinter.
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
# PALETTE & DESIGN SYSTEM
# =============================================================================
PALETTE = {
    "bg_main": "#0D0D12",        # Deep Obsidian Charcoal
    "bg_surface": "#181820",     # Surface Card Dark
    "bg_surface_alt": "#1E1E28", # Surface Accent
    "bg_terminal": "#0A0A0F",    # Deep Terminal Screen
    "border": "#27273A",         # Clean Card Border
    "border_focus": "#A855F7",   # Electric Purple Border Glow
    "accent_primary": "#A855F7", # Electric Purple
    "accent_hover": "#9333EA",   # Deep Purple Hover
    "accent_glow": "#C084FC",    # Glow Violet
    "text_primary": "#F3F4F6",   # Bright White/Grey
    "text_secondary": "#9CA3AF", # Muted Slate
    "text_accent": "#C084FC",    # Electric Violet Text
    "status_success": "#10B981", # Emerald Green
    "status_error": "#EF4444",   # Crimson Alert
    "status_warning": "#F59E0B", # Amber Warning
}

FONT_FAMILY = "Segoe UI"
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

        # Window Configuration
        self.title("SENTINEL // PURGE — Forensic Sanitization Console")
        self.geometry("980x880")
        self.minsize(920, 800)
        self.configure(fg_color=PALETTE["bg_main"])

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

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
        self._log("SYSTEM", "Sentinel-Purge Forensic Engine initialized.", PALETTE["accent_glow"])
        self._log("STATUS", "Engine status: READY. Select a target file to begin.", PALETTE["text_secondary"])

    # -------------------------------------------------------------------------
    # UI CONSTRUCTION
    # -------------------------------------------------------------------------
    def _create_layout(self):
        # Top Scrollable or Main Container
        self.main_container = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color=PALETTE["border"],
            scrollbar_button_hover_color=PALETTE["accent_primary"],
        )
        self.main_container.pack(fill="both", expand=True, padx=20, pady=15)

        self._build_header()
        self._build_target_card()
        self._build_controls_card()
        self._build_telemetry_card()
        self._build_footer()

    def _build_header(self):
        header_frame = ctk.CTkFrame(
            self.main_container,
            fg_color=PALETTE["bg_surface"],
            corner_radius=12,
            border_width=1,
            border_color=PALETTE["border"],
        )
        header_frame.pack(fill="x", pady=(0, 15), ipady=8)

        inner_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        inner_frame.pack(fill="x", padx=20, pady=10)

        # Left branding block
        brand_left = ctk.CTkFrame(inner_frame, fg_color="transparent")
        brand_left.pack(side="left", fill="y")

        title_label = ctk.CTkLabel(
            brand_left,
            text="SENTINEL // PURGE",
            font=ctk.CTkFont(family=MONO_FONT, size=24, weight="bold"),
            text_color=PALETTE["accent_primary"],
        )
        title_label.pack(anchor="w")

        subtitle_label = ctk.CTkLabel(
            brand_left,
            text="NIST SP 800-88 Media Sanitization Framework & Cryptographic Erasure",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12),
            text_color=PALETTE["text_secondary"],
        )
        subtitle_label.pack(anchor="w", pady=(2, 0))

        # Right status badge
        self.status_badge = ctk.CTkLabel(
            inner_frame,
            text="[ ENGINE READY ]",
            font=ctk.CTkFont(family=MONO_FONT, size=12, weight="bold"),
            text_color=PALETTE["accent_primary"],
            fg_color=PALETTE["bg_main"],
            corner_radius=8,
            padx=14,
            pady=6,
        )
        self.status_badge.pack(side="right", padx=5)

    def _build_target_card(self):
        card = ctk.CTkFrame(
            self.main_container,
            fg_color=PALETTE["bg_surface"],
            corner_radius=12,
            border_width=1,
            border_color=PALETTE["border"],
        )
        card.pack(fill="x", pady=(0, 15), padx=0)

        # Section Header
        header_lbl = ctk.CTkLabel(
            card,
            text="// 01. TARGET FILE SPECIFICATION",
            font=ctk.CTkFont(family=MONO_FONT, size=13, weight="bold"),
            text_color=PALETTE["accent_glow"],
        )
        header_lbl.pack(anchor="w", padx=20, pady=(15, 10))

        # Interactive Target Area / File Drop Area
        self.target_btn_card = ctk.CTkButton(
            card,
            text="📁  CLICK TO SELECT OR BROWSE TARGET FILE",
            font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold"),
            fg_color=PALETTE["bg_main"],
            hover_color=PALETTE["bg_surface_alt"],
            border_width=1,
            border_color=PALETTE["border"],
            text_color=PALETTE["text_primary"],
            height=60,
            corner_radius=10,
            command=self._select_file_dialog,
        )
        self.target_btn_card.pack(fill="x", padx=20, pady=(0, 12))

        # File Details Grid
        details_box = ctk.CTkFrame(
            card,
            fg_color=PALETTE["bg_main"],
            corner_radius=8,
            border_width=1,
            border_color=PALETTE["border"],
        )
        details_box.pack(fill="x", padx=20, pady=(0, 15), ipady=8)

        # Path Row
        path_row = ctk.CTkFrame(details_box, fg_color="transparent")
        path_row.pack(fill="x", padx=15, pady=4)
        ctk.CTkLabel(
            path_row,
            text="TARGET PATH :",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            text_color=PALETTE["text_secondary"],
            width=110,
            anchor="w",
        ).pack(side="left")
        self.lbl_file_path = ctk.CTkLabel(
            path_row,
            text="No target file selected",
            font=ctk.CTkFont(family=MONO_FONT, size=11),
            text_color=PALETTE["text_primary"],
            anchor="w",
        )
        self.lbl_file_path.pack(side="left", fill="x", expand=True)

        # Size & Scope Row
        meta_row = ctk.CTkFrame(details_box, fg_color="transparent")
        meta_row.pack(fill="x", padx=15, pady=4)
        ctk.CTkLabel(
            meta_row,
            text="TARGET SIZE :",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            text_color=PALETTE["text_secondary"],
            width=110,
            anchor="w",
        ).pack(side="left")
        self.lbl_file_size = ctk.CTkLabel(
            meta_row,
            text="—",
            font=ctk.CTkFont(family=MONO_FONT, size=11),
            text_color=PALETTE["text_primary"],
            anchor="w",
        )
        self.lbl_file_size.pack(side="left", fill="x", expand=True)

        # SHA-256 Row
        hash_row = ctk.CTkFrame(details_box, fg_color="transparent")
        hash_row.pack(fill="x", padx=15, pady=4)
        ctk.CTkLabel(
            hash_row,
            text="PRE-WIPE SHA:",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            text_color=PALETTE["text_secondary"],
            width=110,
            anchor="w",
        ).pack(side="left")
        self.lbl_file_hash = ctk.CTkLabel(
            hash_row,
            text="—",
            font=ctk.CTkFont(family=MONO_FONT, size=11),
            text_color=PALETTE["accent_glow"],
            anchor="w",
        )
        self.lbl_file_hash.pack(side="left", fill="x", expand=True)

    def _build_controls_card(self):
        card = ctk.CTkFrame(
            self.main_container,
            fg_color=PALETTE["bg_surface"],
            corner_radius=12,
            border_width=1,
            border_color=PALETTE["border"],
        )
        card.pack(fill="x", pady=(0, 15))

        # Section Header
        header_lbl = ctk.CTkLabel(
            card,
            text="// 02. SANITIZATION PROTOCOL & OPERATOR IDENTITY",
            font=ctk.CTkFont(family=MONO_FONT, size=13, weight="bold"),
            text_color=PALETTE["accent_glow"],
        )
        header_lbl.pack(anchor="w", padx=20, pady=(15, 10))

        grid_frame = ctk.CTkFrame(card, fg_color="transparent")
        grid_frame.pack(fill="x", padx=20, pady=(0, 15))

        # Protocol Dropdown Field
        proto_box = ctk.CTkFrame(grid_frame, fg_color="transparent")
        proto_box.pack(side="left", fill="x", expand=True, padx=(0, 10))

        ctk.CTkLabel(
            proto_box,
            text="SANITIZATION PROTOCOL",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            text_color=PALETTE["text_secondary"],
        ).pack(anchor="w", pady=(0, 5))

        self.protocol_dropdown = ctk.CTkOptionMenu(
            proto_box,
            values=list(self.protocol_map.keys()),
            fg_color=PALETTE["bg_main"],
            button_color=PALETTE["border"],
            button_hover_color=PALETTE["accent_primary"],
            text_color=PALETTE["text_primary"],
            dropdown_fg_color=PALETTE["bg_surface"],
            dropdown_text_color=PALETTE["text_primary"],
            dropdown_hover_color=PALETTE["accent_primary"],
            height=38,
            corner_radius=8,
            font=ctk.CTkFont(family=FONT_FAMILY, size=12),
        )
        self.protocol_dropdown.pack(fill="x")
        self.protocol_dropdown.set(list(self.protocol_map.keys())[0])

        # Operator ID Field
        operator_box = ctk.CTkFrame(grid_frame, fg_color="transparent")
        operator_box.pack(side="right", fill="x", expand=True, padx=(10, 0))

        ctk.CTkLabel(
            operator_box,
            text="OPERATOR SIGNATURE / ID",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            text_color=PALETTE["text_secondary"],
        ).pack(anchor="w", pady=(0, 5))

        self.entry_operator = ctk.CTkEntry(
            operator_box,
            fg_color=PALETTE["bg_main"],
            border_color=PALETTE["border"],
            text_color=PALETTE["text_primary"],
            placeholder_text="SecOps Lead / Forensic Officer",
            height=38,
            corner_radius=8,
            font=ctk.CTkFont(family=FONT_FAMILY, size=12),
        )
        self.entry_operator.pack(fill="x")
        self.entry_operator.insert(0, "SecOps Engineer")

        # Action Execution Button
        self.btn_execute = ctk.CTkButton(
            card,
            text="⚡  EXECUTE SANITIZATION & FORENSIC PURGE",
            font=ctk.CTkFont(family=MONO_FONT, size=14, weight="bold"),
            fg_color=PALETTE["accent_primary"],
            hover_color=PALETTE["accent_hover"],
            text_color="#FFFFFF",
            height=48,
            corner_radius=10,
            command=self._on_execute_click,
        )
        self.btn_execute.pack(fill="x", padx=20, pady=(0, 18))

    def _build_telemetry_card(self):
        card = ctk.CTkFrame(
            self.main_container,
            fg_color=PALETTE["bg_surface"],
            corner_radius=12,
            border_width=1,
            border_color=PALETTE["border"],
        )
        card.pack(fill="both", expand=True, pady=(0, 15))

        # Header with Entropy display
        top_bar = ctk.CTkFrame(card, fg_color="transparent")
        top_bar.pack(fill="x", padx=20, pady=(15, 10))

        header_lbl = ctk.CTkLabel(
            top_bar,
            text="// 03. LIVE FORENSIC TELEMETRY & AUDIT LOG",
            font=ctk.CTkFont(family=MONO_FONT, size=13, weight="bold"),
            text_color=PALETTE["accent_glow"],
        )
        header_lbl.pack(side="left")

        # Entropy Badge
        self.entropy_badge = ctk.CTkLabel(
            top_bar,
            text="ENTROPY H(X): — bits/byte",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            text_color=PALETTE["text_secondary"],
            fg_color=PALETTE["bg_main"],
            corner_radius=6,
            padx=10,
            pady=4,
        )
        self.entropy_badge.pack(side="right")

        # Progress Bar & Progress Label
        progress_box = ctk.CTkFrame(card, fg_color="transparent")
        progress_box.pack(fill="x", padx=20, pady=(0, 10))

        self.progress_bar = ctk.CTkProgressBar(
            progress_box,
            fg_color=PALETTE["bg_main"],
            progress_color=PALETTE["accent_primary"],
            height=10,
            corner_radius=5,
        )
        self.progress_bar.pack(fill="x", pady=(0, 4))
        self.progress_bar.set(0.0)

        self.lbl_progress = ctk.CTkLabel(
            progress_box,
            text="Ready (0.0%)",
            font=ctk.CTkFont(family=MONO_FONT, size=11),
            text_color=PALETTE["text_secondary"],
            anchor="w",
        )
        self.lbl_progress.pack(anchor="w")

        # Embedded Console Output
        self.terminal_box = ctk.CTkTextbox(
            card,
            fg_color=PALETTE["bg_terminal"],
            text_color=PALETTE["text_primary"],
            font=ctk.CTkFont(family=MONO_FONT, size=11),
            border_width=1,
            border_color=PALETTE["border"],
            corner_radius=8,
            height=180,
            wrap="word",
        )
        self.terminal_box.pack(fill="both", expand=True, padx=20, pady=(0, 15))

        # Certificate Quick Actions Bar
        actions_bar = ctk.CTkFrame(card, fg_color="transparent")
        actions_bar.pack(fill="x", padx=20, pady=(0, 15))

        self.btn_open_cert = ctk.CTkButton(
            actions_bar,
            text="📄  OPEN AUDIT CERTIFICATE",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            fg_color=PALETTE["bg_main"],
            hover_color=PALETTE["bg_surface_alt"],
            border_width=1,
            border_color=PALETTE["border"],
            text_color=PALETTE["text_primary"],
            height=34,
            corner_radius=6,
            command=self._open_last_certificate,
            state="disabled",
        )
        self.btn_open_cert.pack(side="left", padx=(0, 10))

        self.btn_open_dir = ctk.CTkButton(
            actions_bar,
            text="📁  VIEW CERTIFICATES FOLDER",
            font=ctk.CTkFont(family=MONO_FONT, size=11, weight="bold"),
            fg_color=PALETTE["bg_main"],
            hover_color=PALETTE["bg_surface_alt"],
            border_width=1,
            border_color=PALETTE["border"],
            text_color=PALETTE["text_primary"],
            height=34,
            corner_radius=6,
            command=self._open_certificates_folder,
        )
        self.btn_open_dir.pack(side="left")

    def _build_footer(self):
        footer_lbl = ctk.CTkLabel(
            self.main_container,
            text="Sentinel-Purge v1.0.0 — Forensic Data Sanitization Engine | Authorized SecOps Operations Only",
            font=ctk.CTkFont(family=FONT_FAMILY, size=11),
            text_color=PALETTE["text_secondary"],
        )
        footer_lbl.pack(pady=(0, 5))

    # -------------------------------------------------------------------------
    # EVENT HANDLERS & LOGIC
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

        self._log("TARGET", f"Target selected: {self.selected_file.name} ({format_bytes(self.file_size_bytes)})", PALETTE["accent_glow"])

        # Check safety guardrails immediately
        scope_info = validate_sanitization_target(self.selected_file)
        if not scope_info.is_safe:
            self._log("GUARDRAIL", f"CRITICAL: Target is protected! Reason: {scope_info.rejection_reason}", PALETTE["status_error"])
            self.status_badge.configure(text="[ TARGET BLOCKED ]", text_color=PALETTE["status_error"])
        else:
            self.status_badge.configure(text="[ TARGET VALIDATED ]", text_color=PALETTE["status_success"])

        # Compute SHA-256 preview in background
        threading.Thread(target=self._compute_hash_preview, daemon=True).start()

    def _compute_hash_preview(self):
        if not self.selected_file or not self.selected_file.exists():
            return
        try:
            h = compute_file_sha256(self.selected_file)
            self.after(0, lambda: self.lbl_file_hash.configure(text=h))
            self.after(0, lambda: self._log("HASH", f"Pre-wipe SHA-256 computed: {h[:16]}...{h[-16:]}", PALETTE["text_secondary"]))
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
            f"This operation will cryptographically overwrite the target sectors and unlink the metadata. "
            f"Are you sure you want to proceed?"
        )
        if not messagebox.askyesno("Confirm Sanitization", confirm_msg, icon="warning"):
            return

        # Begin Background Execution
        self._start_sanitization(algorithm, operator)

    def _start_sanitization(self, algorithm: SanitizationAlgorithm, operator: str):
        self.is_sanitizing = True
        self.btn_execute.configure(
            text="⏳  SANITIZING IN PROGRESS...",
            fg_color=PALETTE["bg_surface_alt"],
            state="disabled",
        )
        self.target_btn_card.configure(state="disabled")
        self.protocol_dropdown.configure(state="disabled")
        self.status_badge.configure(text="[ SANITIZING ACTIVE ]", text_color=PALETTE["accent_primary"])
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
            text="⚡  EXECUTE SANITIZATION & FORENSIC PURGE",
            fg_color=PALETTE["accent_primary"],
            state="normal",
        )
        self.target_btn_card.configure(state="normal")
        self.protocol_dropdown.configure(state="normal")

        if result.status == "completed":
            self.progress_bar.set(1.0)
            self.lbl_progress.configure(text="Sanitization & Verification Completed 100%")
            self.status_badge.configure(text="[ PURGE VERIFIED ]", text_color=PALETTE["status_success"])

            # Entropy Score
            entropy = result.verification.get("average_entropy", 0.0)
            self.entropy_badge.configure(
                text=f"ENTROPY H(X): {entropy:.4f} bits/byte [PASS]",
                text_color=PALETTE["status_success"],
            )

            self.last_certificate_path = result.certificate_path
            if self.last_certificate_path and Path(self.last_certificate_path).exists():
                self.btn_open_cert.configure(state="normal")

            self._log("SUCCESS", f"Sanitization complete for {result.original_filename}", PALETTE["status_success"])
            self._log("VERIFY", f"Verification Status: PASSED (Shannon Entropy: {entropy:.4f} bits/byte)", PALETTE["status_success"])
            self._log("CERT", f"Audit certificate emitted: {result.certificate_path}", PALETTE["accent_glow"])

            # Clear file selection since it was securely unlinked
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
            self.status_badge.configure(text="[ OPERATION FAILED ]", text_color=PALETTE["status_error"])
            self._log("ERROR", f"Sanitization failed: {result.error_message}", PALETTE["status_error"])
            messagebox.showerror("Sanitization Failed", f"Sanitization error:\n{result.error_message}")

    def _on_sanitization_error(self, error_msg: str):
        self.is_sanitizing = False
        self.btn_execute.configure(
            text="⚡  EXECUTE SANITIZATION & FORENSIC PURGE",
            fg_color=PALETTE["accent_primary"],
            state="normal",
        )
        self.target_btn_card.configure(state="normal")
        self.protocol_dropdown.configure(state="normal")
        self.status_badge.configure(text="[ ERROR ]", text_color=PALETTE["status_error"])
        self._log("EXCEPTION", f"Unexpected error during execution: {error_msg}", PALETTE["status_error"])
        messagebox.showerror("Execution Error", f"An unexpected error occurred:\n{error_msg}")

    def _log(self, tag: str, message: str, color_hex: str = "#F3F4F6"):
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
