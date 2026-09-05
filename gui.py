"""
Sentinel-Purge Desktop GUI
Industrial-Gothic Digital Forensics & Media Sanitization Console
Designed for high-contrast architectural discipline: Purple & Black hue palette only.
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
# MANDATORY FONT LOADING LOGIC (PRESERVED EXACTLY)
# =============================================================================
FONT_FILENAME = "BootzyTM.ttf"

def resolve_font_path():
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, "font", FONT_FILENAME)
    return os.path.join(r"C:\Users\DELL\Downloads\font", FONT_FILENAME)

FONT_PATH = resolve_font_path()

if os.path.exists(FONT_PATH):
    try:
        ctk.FontManager.load_font(FONT_PATH)
        GOTHIC_FONT = "BootzyTM"  # Hardcoded font family name
        print(f"[+] Loaded font: {FONT_PATH}")
    except Exception as e:
        print(f"[-] Font load error: {e}")
        GOTHIC_FONT = "Consolas"
else:
    print(f"[-] Font file not found at: {FONT_PATH}")
    GOTHIC_FONT = "Consolas"

# Typography Hierarchy
FONT_BANNER = (GOTHIC_FONT, 38, "bold")
FONT_HEADER = (GOTHIC_FONT, 18)
FONT_BUTTON = (GOTHIC_FONT, 20, "bold")
FONT_BODY = ("Consolas", 11)  # Monospace for technical data & logs
FONT_BODY_BOLD = ("Consolas", 11, "bold")
FONT_SUBTITLE = ("Consolas", 10)


# =============================================================================
# PURPLE & BLACK COLOR PALETTE (STRICT SINGLE-HUE SYSTEM)
# =============================================================================
COLOR_BG = "#0C0A10"                # Near-black canvas with faint violet undertone
COLOR_PANEL = "#1A1420"             # Charcoal-violet structural panel
COLOR_PANEL_ALT = "#140F1A"         # Slightly deeper panel recess
COLOR_BORDER_PLUM = "#332638"       # 1px hairline border in muted plum
COLOR_ACCENT_AMETHYST = "#6B2FA6"   # Deep royal / amethyst purple (primary actions & active states)
COLOR_ACCENT_DIVIDER = "#5D2E8C"    # Amethyst section divider bar
COLOR_ACCENT_LAVENDER = "#B8A9C9"   # Light desaturated lavender-grey (highlights & active labels)
COLOR_MUTED_LAVENDER = "#9B8AAE"    # Secondary muted lavender-grey
COLOR_DANGER_AUBERGINE = "#2A1230"  # Dark aubergine fill for destructive execution
COLOR_DANGER_BORDER = "#8A38D4"     # Intense electric violet border for destructive warnings
COLOR_TEXT = "#EDE7F0"              # Pale lavender-white body text
COLOR_SUCCESS_LILAC = "#C9A9E8"     # Bright lilac for verified & success telemetry
COLOR_TERMINAL_BG = "#08060B"       # Ultra-deep terminal screen


def format_bytes(num_bytes: int) -> str:
    """Format byte count into monospaced human-readable representation."""
    if num_bytes < 0:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


# =============================================================================
# MAIN FORENSIC APPLICATION WINDOW
# =============================================================================
class SentinelPurgeApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Root Window Configuration
        self.title("SENTINEL // PURGE — Industrial-Gothic Digital Forensics Console")
        self.geometry("1020x920")
        self.minsize(960, 840)
        self.configure(fg_color=COLOR_BG)

        ctk.set_appearance_mode("dark")

        # Operational State
        self.selected_file: Optional[Path] = None
        self.file_size_bytes: int = 0
        self.is_sanitizing: bool = False
        self.last_certificate_path: Optional[str] = None
        self.sanitizer = Sanitizer(certificates_dir="certificates")

        # Protocol Mapping
        self.protocol_map = {
            "NIST SP 800-88 Rev. 1 Clear (1-Pass Pseudo-Random)": SanitizationAlgorithm.NIST_800_88_CLEAR,
            "DoD 5220.22-M Legacy (3-Pass Zeros/Ones/Random)": SanitizationAlgorithm.LEGACY_DOD_5220_22_M,
            "Quick Zero Overwrite (1-Pass Fixed 0x00)": SanitizationAlgorithm.ZERO_OVERWRITE,
        }

        # Build Interface
        self._create_layout()

        # Telemetry Initial State
        self._log("SYSTEM", "Forensic Media Sanitization Engine initialized.", COLOR_MUTED_LAVENDER)
        self._log("AUDIT", "Hardware scope validation active. Awaiting operator target.", COLOR_MUTED_LAVENDER)

    # -------------------------------------------------------------------------
    # LAYOUT & ARCHITECTURAL STRUCTURE
    # -------------------------------------------------------------------------
    def _create_layout(self):
        # Master Workspace Frame
        self.main_container = ctk.CTkScrollableFrame(
            self,
            fg_color=COLOR_BG,
            corner_radius=0,
            scrollbar_button_color=COLOR_BORDER_PLUM,
            scrollbar_button_hover_color=COLOR_ACCENT_AMETHYST,
        )
        self.main_container.pack(fill="both", expand=True, padx=26, pady=22)

        # Fallback Notification (Displays visibly if BootzyTM.ttf failed to load)
        if GOTHIC_FONT == "Consolas":
            self._build_font_warning_banner()

        self._build_header_banner()
        self._build_divider()
        self._build_target_panel()
        self._build_controls_panel()
        self._build_telemetry_panel()
        self._build_footer()

    def _build_font_warning_banner(self):
        """Visible diagnostic alert displayed if custom typography fell back to monospace."""
        warn_frame = ctk.CTkFrame(
            self.main_container,
            fg_color=COLOR_DANGER_AUBERGINE,
            border_color=COLOR_DANGER_BORDER,
            border_width=1,
            corner_radius=0,
        )
        warn_frame.pack(fill="x", pady=(0, 14), ipady=4)

        warn_label = ctk.CTkLabel(
            warn_frame,
            text=f"[ TYPOGRAPHY NOTICE: 'BootzyTM' NOT FOUND AT {FONT_PATH} — FALLBACK TO CONSOLAS ACTIVE ]",
            font=FONT_BODY_BOLD,
            text_color=COLOR_ACCENT_LAVENDER,
        )
        warn_label.pack(padx=12, pady=4)

    def _build_header_banner(self):
        """Commanding Cathedral-Scale Header Banner with architectural status badge."""
        header_frame = ctk.CTkFrame(
            self.main_container,
            fg_color=COLOR_PANEL,
            border_color=COLOR_BORDER_PLUM,
            border_width=1,
            corner_radius=0,
        )
        header_frame.pack(fill="x", pady=(0, 12))

        inner = ctk.CTkFrame(header_frame, fg_color="transparent", corner_radius=0)
        inner.pack(fill="x", padx=24, pady=18)

        # Left: Typographic Title & Forensics Subtitle
        left_box = ctk.CTkFrame(inner, fg_color="transparent", corner_radius=0)
        left_box.pack(side="left", fill="y")

        title_lbl = ctk.CTkLabel(
            left_box,
            text="SENTINEL // PURGE",
            font=FONT_BANNER,
            text_color=COLOR_TEXT,
        )
        title_lbl.pack(anchor="w")

        subtitle_lbl = ctk.CTkLabel(
            left_box,
            text="FORENSIC DATA SANITIZATION & METADATA ERASURE APPARATUS // NIST SP 800-88 REV. 1",
            font=FONT_SUBTITLE,
            text_color=COLOR_MUTED_LAVENDER,
        )
        subtitle_lbl.pack(anchor="w", pady=(6, 0))

        # Right: Architectural Status Terminal Badge
        right_box = ctk.CTkFrame(inner, fg_color="transparent", corner_radius=0)
        right_box.pack(side="right", fill="y")

        self.status_badge = ctk.CTkLabel(
            right_box,
            text="[ ENGINE: STANDBY ]",
            font=FONT_BODY_BOLD,
            text_color=COLOR_SUCCESS_LILAC,
            fg_color=COLOR_BG,
            corner_radius=0,
            padx=18,
            pady=10,
        )
        self.status_badge.pack(anchor="e")

    def _build_divider(self):
        """Thin amethyst horizontal divider separating header from technical modules."""
        divider = ctk.CTkFrame(
            self.main_container,
            fg_color=COLOR_ACCENT_DIVIDER,
            height=2,
            corner_radius=0,
        )
        divider.pack(fill="x", pady=(0, 16))

    def _build_target_panel(self):
        """Structural Card 01: Target File Specification & Inode Analysis."""
        panel = ctk.CTkFrame(
            self.main_container,
            fg_color=COLOR_PANEL,
            border_color=COLOR_BORDER_PLUM,
            border_width=1,
            corner_radius=0,
        )
        panel.pack(fill="x", pady=(0, 16))

        # Panel Header with schematic corner notation
        header_bar = ctk.CTkFrame(panel, fg_color=COLOR_PANEL_ALT, corner_radius=0)
        header_bar.pack(fill="x", padx=1, pady=1)

        section_lbl = ctk.CTkLabel(
            header_bar,
            text="┌─ [ 01 ] TARGET FILE SPECIFICATION & CRYPTOGRAPHIC INODE",
            font=FONT_HEADER,
            text_color=COLOR_ACCENT_LAVENDER,
        )
        section_lbl.pack(side="left", padx=16, pady=10)

        corner_tag = ctk.CTkLabel(
            header_bar,
            text="SEC-OPS // LEVEL 4",
            font=FONT_BODY,
            text_color=COLOR_BORDER_PLUM,
        )
        corner_tag.pack(side="right", padx=16)

        # Content Area
        content = ctk.CTkFrame(panel, fg_color="transparent", corner_radius=0)
        content.pack(fill="x", padx=18, pady=14)

        # Secondary Button (Hollow Design with Lavender-Grey border)
        self.btn_select_target = ctk.CTkButton(
            content,
            text="SELECT TARGET EVIDENCE FILE",
            font=FONT_BUTTON,
            fg_color=COLOR_PANEL_ALT,
            hover_color=COLOR_BORDER_PLUM,
            border_color=COLOR_BORDER_PLUM,
            border_width=1,
            text_color=COLOR_ACCENT_LAVENDER,
            height=46,
            corner_radius=0,
            command=self._select_file_dialog,
        )
        self.btn_select_target.pack(fill="x", pady=(0, 14))

        # Monospace Inode Metadata Box
        details_box = ctk.CTkFrame(
            content,
            fg_color=COLOR_BG,
            border_color=COLOR_BORDER_PLUM,
            border_width=1,
            corner_radius=0,
        )
        details_box.pack(fill="x", ipady=8)

        # Target Path
        row1 = ctk.CTkFrame(details_box, fg_color="transparent", corner_radius=0)
        row1.pack(fill="x", padx=14, pady=3)
        ctk.CTkLabel(
            row1,
            text="TARGET PATH    :",
            font=FONT_BODY_BOLD,
            text_color=COLOR_MUTED_LAVENDER,
            width=135,
            anchor="w",
        ).pack(side="left")
        self.lbl_file_path = ctk.CTkLabel(
            row1,
            text="No target file currently designated",
            font=FONT_BODY,
            text_color=COLOR_TEXT,
            anchor="w",
        )
        self.lbl_file_path.pack(side="left", fill="x", expand=True)

        # Target Size
        row2 = ctk.CTkFrame(details_box, fg_color="transparent", corner_radius=0)
        row2.pack(fill="x", padx=14, pady=3)
        ctk.CTkLabel(
            row2,
            text="ALLOCATED SIZE :",
            font=FONT_BODY_BOLD,
            text_color=COLOR_MUTED_LAVENDER,
            width=135,
            anchor="w",
        ).pack(side="left")
        self.lbl_file_size = ctk.CTkLabel(
            row2,
            text="—",
            font=FONT_BODY,
            text_color=COLOR_TEXT,
            anchor="w",
        )
        self.lbl_file_size.pack(side="left", fill="x", expand=True)

        # Pre-Wipe SHA-256
        row3 = ctk.CTkFrame(details_box, fg_color="transparent", corner_radius=0)
        row3.pack(fill="x", padx=14, pady=3)
        ctk.CTkLabel(
            row3,
            text="PRE-WIPE SHA256:",
            font=FONT_BODY_BOLD,
            text_color=COLOR_MUTED_LAVENDER,
            width=135,
            anchor="w",
        ).pack(side="left")
        self.lbl_file_hash = ctk.CTkLabel(
            row3,
            text="—",
            font=FONT_BODY,
            text_color=COLOR_SUCCESS_LILAC,
            anchor="w",
        )
        self.lbl_file_hash.pack(side="left", fill="x", expand=True)

    def _build_controls_panel(self):
        """Structural Card 02: Protocol Configuration & Weighty Destructive Action."""
        panel = ctk.CTkFrame(
            self.main_container,
            fg_color=COLOR_PANEL,
            border_color=COLOR_BORDER_PLUM,
            border_width=1,
            corner_radius=0,
        )
        panel.pack(fill="x", pady=(0, 16))

        # Panel Header
        header_bar = ctk.CTkFrame(panel, fg_color=COLOR_PANEL_ALT, corner_radius=0)
        header_bar.pack(fill="x", padx=1, pady=1)

        section_lbl = ctk.CTkLabel(
            header_bar,
            text="┌─ [ 02 ] OVERWRITE PROTOCOL SPECIFICATION & EXECUTION GATING",
            font=FONT_HEADER,
            text_color=COLOR_ACCENT_LAVENDER,
        )
        section_lbl.pack(side="left", padx=16, pady=10)

        content = ctk.CTkFrame(panel, fg_color="transparent", corner_radius=0)
        content.pack(fill="x", padx=18, pady=14)

        # Dual Input Grid
        grid = ctk.CTkFrame(content, fg_color="transparent", corner_radius=0)
        grid.pack(fill="x", pady=(0, 14))

        # Protocol Dropdown Box
        left_col = ctk.CTkFrame(grid, fg_color="transparent", corner_radius=0)
        left_col.pack(side="left", fill="x", expand=True, padx=(0, 10))

        ctk.CTkLabel(
            left_col,
            text="SANITIZATION PROTOCOL STANDARD",
            font=FONT_BODY_BOLD,
            text_color=COLOR_MUTED_LAVENDER,
        ).pack(anchor="w", pady=(0, 5))

        self.protocol_dropdown = ctk.CTkOptionMenu(
            left_col,
            values=list(self.protocol_map.keys()),
            fg_color=COLOR_BG,
            button_color=COLOR_BORDER_PLUM,
            button_hover_color=COLOR_ACCENT_AMETHYST,
            text_color=COLOR_TEXT,
            dropdown_fg_color=COLOR_PANEL,
            dropdown_text_color=COLOR_TEXT,
            dropdown_hover_color=COLOR_ACCENT_AMETHYST,
            height=40,
            corner_radius=0,
            font=FONT_BODY,
        )
        self.protocol_dropdown.pack(fill="x")
        self.protocol_dropdown.set(list(self.protocol_map.keys())[0])

        # Operator Signature Box
        right_col = ctk.CTkFrame(grid, fg_color="transparent", corner_radius=0)
        right_col.pack(side="right", fill="x", expand=True, padx=(10, 0))

        ctk.CTkLabel(
            right_col,
            text="OPERATOR AUTHENTICATION SIGNATURE",
            font=FONT_BODY_BOLD,
            text_color=COLOR_MUTED_LAVENDER,
        ).pack(anchor="w", pady=(0, 5))

        self.entry_operator = ctk.CTkEntry(
            right_col,
            fg_color=COLOR_BG,
            border_color=COLOR_BORDER_PLUM,
            border_width=1,
            text_color=COLOR_TEXT,
            placeholder_text="SecOps Lead / Forensic Investigator",
            height=40,
            corner_radius=0,
            font=FONT_BODY,
        )
        self.entry_operator.pack(fill="x")
        self.entry_operator.insert(0, "SecOps Investigator")

        # Destructive Primary Action Button (Weighty dark aubergine with electric violet border)
        self.btn_execute = ctk.CTkButton(
            content,
            text="INITIATE SECURE ERASURE",
            font=FONT_BUTTON,
            fg_color=COLOR_DANGER_AUBERGINE,
            hover_color=COLOR_ACCENT_AMETHYST,
            border_color=COLOR_DANGER_BORDER,
            border_width=2,
            text_color=COLOR_TEXT,
            height=54,
            corner_radius=0,
            command=self._on_execute_click,
        )
        self.btn_execute.pack(fill="x")

    def _build_telemetry_panel(self):
        """Structural Card 03: Monospace Terminal Console & Forensic Telemetry."""
        panel = ctk.CTkFrame(
            self.main_container,
            fg_color=COLOR_PANEL,
            border_color=COLOR_BORDER_PLUM,
            border_width=1,
            corner_radius=0,
        )
        panel.pack(fill="both", expand=True, pady=(0, 16))

        # Panel Header with Entropy Value Display
        header_bar = ctk.CTkFrame(panel, fg_color=COLOR_PANEL_ALT, corner_radius=0)
        header_bar.pack(fill="x", padx=1, pady=1)

        section_lbl = ctk.CTkLabel(
            header_bar,
            text="┌─ [ 03 ] FORENSIC AUDIT STREAM & SHANNON ENTROPY TELEMETRY",
            font=FONT_HEADER,
            text_color=COLOR_ACCENT_LAVENDER,
        )
        section_lbl.pack(side="left", padx=16, pady=10)

        # Gothic-Technical Entropy Metric Badge
        self.entropy_badge = ctk.CTkLabel(
            header_bar,
            text="SHANNON ENTROPY H(X): — bits/byte",
            font=FONT_BODY_BOLD,
            text_color=COLOR_SUCCESS_LILAC,
            fg_color=COLOR_BG,
            corner_radius=0,
            padx=14,
            pady=4,
        )
        self.entropy_badge.pack(side="right", padx=16, pady=6)

        content = ctk.CTkFrame(panel, fg_color="transparent", corner_radius=0)
        content.pack(fill="both", expand=True, padx=18, pady=14)

        # Monospace Progress Bar
        self.progress_bar = ctk.CTkProgressBar(
            content,
            fg_color=COLOR_BG,
            progress_color=COLOR_ACCENT_AMETHYST,
            height=8,
            corner_radius=0,
        )
        self.progress_bar.pack(fill="x", pady=(0, 4))
        self.progress_bar.set(0.0)

        self.lbl_progress = ctk.CTkLabel(
            content,
            text="IDLE // BUFFER READY (0.0%)",
            font=FONT_BODY,
            text_color=COLOR_MUTED_LAVENDER,
            anchor="w",
        )
        self.lbl_progress.pack(anchor="w", pady=(0, 10))

        # Terminal Console Box (True Monospace with Deep Black-Violet Canvas)
        self.terminal_box = ctk.CTkTextbox(
            content,
            fg_color=COLOR_TERMINAL_BG,
            text_color=COLOR_TEXT,
            font=FONT_BODY,
            border_width=1,
            border_color=COLOR_BORDER_PLUM,
            corner_radius=0,
            height=200,
            wrap="word",
        )
        self.terminal_box.pack(fill="both", expand=True, pady=(0, 14))

        # Audit Certificate Action Bar (Hollow Architectural Buttons)
        actions_bar = ctk.CTkFrame(content, fg_color="transparent", corner_radius=0)
        actions_bar.pack(fill="x")

        self.btn_open_cert = ctk.CTkButton(
            actions_bar,
            text="VIEW AUDIT CERTIFICATE",
            font=FONT_BUTTON,
            fg_color=COLOR_PANEL_ALT,
            hover_color=COLOR_BORDER_PLUM,
            border_width=1,
            border_color=COLOR_BORDER_PLUM,
            text_color=COLOR_ACCENT_LAVENDER,
            height=38,
            corner_radius=0,
            command=self._open_last_certificate,
            state="disabled",
        )
        self.btn_open_cert.pack(side="left", padx=(0, 12))

        self.btn_open_dir = ctk.CTkButton(
            actions_bar,
            text="OPEN CERTIFICATES ARCHIVE",
            font=FONT_BUTTON,
            fg_color=COLOR_PANEL_ALT,
            hover_color=COLOR_BORDER_PLUM,
            border_width=1,
            border_color=COLOR_BORDER_PLUM,
            text_color=COLOR_ACCENT_LAVENDER,
            height=38,
            corner_radius=0,
            command=self._open_certificates_folder,
        )
        self.btn_open_dir.pack(side="left")

    def _build_footer(self):
        """Bottom Schematic Annotations."""
        foot_frame = ctk.CTkFrame(self.main_container, fg_color="transparent", corner_radius=0)
        foot_frame.pack(fill="x", pady=(4, 0))

        foot_lbl = ctk.CTkLabel(
            foot_frame,
            text="SENTINEL-PURGE FORENSIC ARCHITECTURE // ISO-8601 COMPLIANT AUDIT // AUTHORIZED SECOPS USE ONLY",
            font=FONT_SUBTITLE,
            text_color=COLOR_BORDER_PLUM,
        )
        foot_lbl.pack(side="left")

        ver_lbl = ctk.CTkLabel(
            foot_frame,
            text="v1.1.0-GOTHIC",
            font=FONT_SUBTITLE,
            text_color=COLOR_BORDER_PLUM,
        )
        ver_lbl.pack(side="right")

    # -------------------------------------------------------------------------
    # OPERATIONAL LOGIC & CORE ENGINE EVENT HANDLERS
    # -------------------------------------------------------------------------
    def _select_file_dialog(self):
        if self.is_sanitizing:
            return

        file_path = filedialog.askopenfilename(
            title="Designate Target File for Permanent Sanitization",
        )
        if not file_path:
            return

        self._set_selected_target(Path(file_path))

    def _set_selected_target(self, target: Path):
        self.selected_file = target.resolve()
        if not self.selected_file.exists():
            messagebox.showerror("Target Inaccessible", f"Selected target not found:\n{self.selected_file}")
            return

        try:
            self.file_size_bytes = self.selected_file.stat().st_size
        except Exception:
            self.file_size_bytes = 0

        self.lbl_file_path.configure(text=str(self.selected_file))
        self.lbl_file_size.configure(
            text=f"{format_bytes(self.file_size_bytes)}  ({self.file_size_bytes:,} BYTES)"
        )
        self.lbl_file_hash.configure(text="COMPUTING STREAMING SHA-256 HASH...")

        self._log("TARGET", f"Designated target: {self.selected_file.name} [{format_bytes(self.file_size_bytes)}]", COLOR_ACCENT_LAVENDER)

        # Validate Scope Guardrails Immediately
        scope_info = validate_sanitization_target(self.selected_file)
        if not scope_info.is_safe:
            self._log("GUARDRAIL", f"INTERCEPT: Target is protected! Reason: {scope_info.rejection_reason}", COLOR_DANGER_BORDER)
            self.status_badge.configure(text="[ CRITICAL: SCOPE INTERCEPT ]", text_color=COLOR_DANGER_BORDER)
        else:
            self._log("GUARDRAIL", f"Scope check passed: {scope_info.media_type.value}", COLOR_MUTED_LAVENDER)
            self.status_badge.configure(text="[ TARGET VALIDATED ]", text_color=COLOR_SUCCESS_LILAC)

        # Compute Pre-Wipe SHA-256 Preview in Background Thread
        threading.Thread(target=self._compute_hash_preview, daemon=True).start()

    def _compute_hash_preview(self):
        if not self.selected_file or not self.selected_file.exists():
            return
        try:
            h = compute_file_sha256(self.selected_file)
            self.after(0, lambda: self.lbl_file_hash.configure(text=h))
            self.after(0, lambda: self._log("HASH", f"Pre-wipe SHA-256 established: {h[:20]}...{h[-20:]}", COLOR_MUTED_LAVENDER))
        except Exception as e:
            self.after(0, lambda: self.lbl_file_hash.configure(text=f"HASH ERROR: {e}"))

    def _on_execute_click(self):
        if self.is_sanitizing:
            return

        if not self.selected_file:
            messagebox.showwarning("Target Required", "Designate a target file before initiating sanitization.")
            return

        if not self.selected_file.exists():
            messagebox.showerror("Target Missing", "Designated target file is no longer accessible on disk.")
            return

        # Guardrail Validation
        scope_info = validate_sanitization_target(self.selected_file)
        if not scope_info.is_safe:
            messagebox.showerror("Execution Aborted", f"Target is shielded by system guardrails:\n{scope_info.rejection_reason}")
            return

        selected_label = self.protocol_dropdown.get()
        algorithm = self.protocol_map.get(selected_label, SanitizationAlgorithm.NIST_800_88_CLEAR)
        operator = self.entry_operator.get().strip() or "SecOps Investigator"

        # Explicit Forensic Confirmation
        confirm_msg = (
            f"INITIATE IRREVERSIBLE FORENSIC ERASURE?\n\n"
            f"TARGET    : {self.selected_file.name}\n"
            f"ALLOCATION: {format_bytes(self.file_size_bytes)}\n"
            f"ALGORITHM : {algorithm.value}\n"
            f"OPERATOR  : {operator}\n\n"
            f"All physical clusters allocated to this inode will be overwritten with cryptographic passes, "
            f"verified via Shannon Entropy sampling, and the file table entry will be unlinked."
        )
        if not messagebox.askyesno("CONFIRM DESTRUCTION", confirm_msg, icon="warning"):
            return

        self._start_sanitization(algorithm, operator)

    def _start_sanitization(self, algorithm: SanitizationAlgorithm, operator: str):
        self.is_sanitizing = True
        self.btn_execute.configure(
            text="ERASURE IN PROGRESS...",
            fg_color=COLOR_BORDER_PLUM,
            state="disabled",
        )
        self.btn_select_target.configure(state="disabled")
        self.protocol_dropdown.configure(state="disabled")
        self.status_badge.configure(text="[ ACTIVE SANITIZATION ]", text_color=COLOR_ACCENT_LAVENDER)
        self.progress_bar.set(0.0)
        self.lbl_progress.configure(text="DISPATCHING CHUNKED OVERWRITE PASS...")

        self._log("EXECUTE", f"Engaging sanitization pipeline ({algorithm.value})", COLOR_ACCENT_AMETHYST)

        worker = threading.Thread(
            target=self._run_sanitization_worker,
            args=(self.selected_file, algorithm, operator),
            daemon=True,
        )
        worker.start()

    def _run_sanitization_worker(self, target_path: Path, algorithm: SanitizationAlgorithm, operator: str):
        def progress_callback(pass_num: int, total_passes: int, bytes_written: int, total_bytes: int):
            fraction = (bytes_written / total_bytes) if total_bytes > 0 else 1.0
            overall = ((pass_num - 1) + fraction) / total_passes
            pct = overall * 100.0

            status_msg = (
                f"PASS {pass_num}/{total_passes} // WRITTEN: {format_bytes(bytes_written)} / {format_bytes(total_bytes)} ({pct:5.1f}%)"
            )
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
            text="INITIATE SECURE ERASURE",
            fg_color=COLOR_DANGER_AUBERGINE,
            state="normal",
        )
        self.btn_select_target.configure(state="normal")
        self.protocol_dropdown.configure(state="normal")

        if result.status == "completed":
            self.progress_bar.set(1.0)
            self.lbl_progress.configure(text="CYCLE COMPLETE // 100% OVERWRITE & VERIFICATION ATTAINED")
            self.status_badge.configure(text="[ DESTRUCTION VERIFIED ]", text_color=COLOR_SUCCESS_LILAC)

            # Shannon Entropy Extraction
            entropy = result.verification.get("average_entropy", 0.0)
            self.entropy_badge.configure(
                text=f"SHANNON ENTROPY H(X): {entropy:.4f} bits/byte [PASS >= 7.2]",
                text_color=COLOR_SUCCESS_LILAC,
            )

            self.last_certificate_path = result.certificate_path
            if self.last_certificate_path and Path(self.last_certificate_path).exists():
                self.btn_open_cert.configure(state="normal")

            self._log("SUCCESS", f"Sanitization successful: {result.original_filename}", COLOR_SUCCESS_LILAC)
            self._log("VERIFY", f"Statistical Entropy H(X): {entropy:.4f} bits/byte (Threshold satisfied)", COLOR_SUCCESS_LILAC)
            self._log("CERT", f"Signed audit certificate generated: {result.certificate_path}", COLOR_ACCENT_LAVENDER)

            # Inode Unlinked Notice
            self.selected_file = None
            self.lbl_file_path.configure(text="[ INODE UNLINKED & METADATA DESTROYED ]")
            self.lbl_file_size.configure(text="0 B (TRUNCATED TO NULL)")
            self.lbl_file_hash.configure(text="—")

            messagebox.showinfo(
                "Sanitization Complete",
                f"Destruction and entropy verification confirmed.\n\n"
                f"JOB IDENTIFIER : {result.id}\n"
                f"SHANNON ENTROPY: {entropy:.4f} bits/byte\n"
                f"CERTIFICATE    : {result.certificate_path}",
            )
        else:
            self.status_badge.configure(text="[ PIPELINE ERROR ]", text_color=COLOR_DANGER_BORDER)
            self._log("ERROR", f"Sanitization aborted: {result.error_message}", COLOR_DANGER_BORDER)
            messagebox.showerror("Pipeline Failure", f"Sanitization error occurred:\n{result.error_message}")

    def _on_sanitization_error(self, error_msg: str):
        self.is_sanitizing = False
        self.btn_execute.configure(
            text="INITIATE SECURE ERASURE",
            fg_color=COLOR_DANGER_AUBERGINE,
            state="normal",
        )
        self.btn_select_target.configure(state="normal")
        self.protocol_dropdown.configure(state="normal")
        self.status_badge.configure(text="[ EXCEPTION HALTED ]", text_color=COLOR_DANGER_BORDER)
        self._log("ERROR", f"Critical exception during execution: {error_msg}", COLOR_DANGER_BORDER)
        messagebox.showerror("Critical Error", f"Unhandled execution exception:\n{error_msg}")

    def _log(self, tag: str, message: str, color_hex: str = COLOR_TEXT):
        """Append saturation-coded monospace log lines."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{tag:<9}] {message}\n"
        self.terminal_box.insert("end", log_entry)
        self.terminal_box.see("end")

    def _open_last_certificate(self):
        if not self.last_certificate_path:
            return
        cert_path = Path(self.last_certificate_path).resolve()
        if not cert_path.exists():
            messagebox.showerror("File Error", "Audit certificate file cannot be found on disk.")
            return

        try:
            if sys.platform == "win32":
                os.startfile(str(cert_path))
            elif sys.platform == "darwin":
                subprocess.run(["open", str(cert_path)], check=True)
            else:
                subprocess.run(["xdg-open", str(cert_path)], check=True)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open certificate: {e}")

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
            messagebox.showerror("Error", f"Failed to open archive folder: {e}")


# =============================================================================
# APPLICATION ENTRYPOINT
# =============================================================================
def main():
    app = SentinelPurgeApp()
    app.mainloop()


if __name__ == "__main__":
    main()
