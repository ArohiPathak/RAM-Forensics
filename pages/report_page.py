import customtkinter as ctk
import os
import time
from tkinter import messagebox
from pages.base_page import BasePage
from services.data_provider import DataProvider
from typing import Dict, Any

# Use the shared, fully-formatted report builder instead of hand-writing PDF
# bytes here. This is the same module/tests we already built and verified
# (reports/pdf_generator.py) - it gives us proper tables, page breaks, text
# wrapping, and the black-and-white DFIR layout, instead of a single page of
# unwrapped raw text.
from reports.pdf_generator import generate_forensic_pdf


class ReportPage(BasePage):
    """
    ReportPage compiles dynamic summary fields into a preview document.
    Features:
    - Left side: High-fidelity document page preview mapping:
      - Case ID, Investigator name (updating live from inputs).
      - Target memory file path, OS profile, risk score.
      - Bullet points listing forensic findings and actionable recommendations.
    - Right side: Config inputs (Case ID, Investigator name).
    - Generate PDF Action: builds the real PDF via reports/pdf_generator.py
      and displays a success/error popup.
    """
    def __init__(self, master, data_service: DataProvider, **kwargs):
        super().__init__(
            master, 
            data_service, 
            title="Analysis Reports", 
            description="Generate, review, and export compiled memory forensics reporting structures.", 
            **kwargs
        )
        
        # Hide standard refresh button to focus on report preview
        self.refresh_btn.grid_remove()
        
        # Configure layout (2 columns: left is document preview, right is compiler controls)
        self.content_frame.grid_columnconfigure(0, weight=3)  # Preview card (spacious)
        self.content_frame.grid_columnconfigure(1, weight=2)  # Controls drawer
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        # --- LEFT PANEL: DYNAMIC DOCUMENT PREVIEW ---
        self.preview_panel = ctk.CTkFrame(
            self.content_frame,
            fg_color=("#F8FAFC", "#0F1624"),
            border_color=("#D0D5DD", "#1E2D4A"),
            border_width=1.5,
            corner_radius=12
        )
        self.preview_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.preview_panel.grid_columnconfigure(0, weight=1)
        self.preview_panel.grid_rowconfigure(1, weight=1)  # Scrollable details stretch
        
        # Preview Header Banner
        self.preview_hdr = ctk.CTkFrame(self.preview_panel, fg_color=("#EAECF0", "#121C2C"), height=50, corner_radius=0)
        self.preview_hdr.grid(row=0, column=0, sticky="ew", padx=1.5, pady=(1.5, 0))
        self.preview_hdr.grid_columnconfigure(0, weight=1)
        self.preview_hdr.grid_propagate(False)
        
        self.preview_title = ctk.CTkLabel(
            self.preview_hdr,
            text="FORENSIC INVESTIGATION REPORT PREVIEW",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("#008B9B", "#00E5FF")
        )
        self.preview_title.grid(row=0, column=0, padx=20, pady=12, sticky="w")
        
        # Preview Details Scroll Frame (Representing the document body)
        self.doc_scroll = ctk.CTkScrollableFrame(
            self.preview_panel,
            fg_color="transparent"
        )
        self.doc_scroll._scrollbar.configure(
            fg_color="transparent",
            button_color=("#C1C9D2", "#1E2D4A"),
            button_hover_color=("#00B4CC", "#00E5FF")
        )
        self.doc_scroll.grid(row=1, column=0, sticky="nsew", padx=16, pady=16)
        self.doc_scroll.grid_columnconfigure(0, weight=1)
        
        # Document Title
        self.doc_title = ctk.CTkLabel(
            self.doc_scroll,
            text="VOLATILITY 3 MEMORY AUDIT INCIDENT LOG",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=("#0F172A", "#FFFFFF"),
            anchor="w"
        )
        self.doc_title.grid(row=0, column=0, sticky="w", pady=(10, 15))
        
        # Document metadata grid block
        self.meta_block = ctk.CTkFrame(self.doc_scroll, fg_color=("#FFFFFF", "#121C2C"), border_color=("#D0D5DD", "#1E2D4A"), border_width=1, corner_radius=6)
        self.meta_block.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        self.meta_block.grid_columnconfigure(1, weight=1)
        
        self.meta_labels = {}
        meta_rows = [
            ("case_id", "Incident Case ID"),
            ("analyst", "Primary Investigator"),
            ("target", "Target Memory Image"),
            ("profile", "Operating System Profile"),
            ("risk", "Threat Risk Score")
        ]
        
        for idx, (meta_key, display_label) in enumerate(meta_rows):
            lbl_title = ctk.CTkLabel(
                self.meta_block,
                text=display_label,
                font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
                text_color=("#475569", "#627284"),
                anchor="w"
            )
            lbl_title.grid(row=idx, column=0, sticky="w", pady=6, padx=(16, 20))
            
            lbl_val = ctk.CTkLabel(
                self.meta_block,
                text="-",
                font=ctk.CTkFont(family="Consolas" if meta_key in ["target", "case_id"] else "Segoe UI", size=11),
                text_color=("#0F172A", "#FFFFFF"),
                anchor="w",
                wraplength=340,
                justify="left"
            )
            lbl_val.grid(row=idx, column=1, sticky="w", pady=6, padx=(0, 16))
            self.meta_labels[meta_key] = lbl_val
            
        # Findings List Frame
        self.findings_frame = ctk.CTkFrame(self.doc_scroll, fg_color="transparent")
        self.findings_frame.grid(row=2, column=0, sticky="ew", pady=10)
        self.findings_frame.grid_columnconfigure(0, weight=1)
        
        self.findings_hdr = ctk.CTkLabel(
            self.findings_frame,
            text="CRITICAL INCIDENT FINDINGS",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#FF3B30",
            anchor="w"
        )
        self.findings_hdr.grid(row=0, column=0, sticky="w", pady=(0, 6))
        
        # Recommendations List Frame
        self.recs_frame = ctk.CTkFrame(self.doc_scroll, fg_color="transparent")
        self.recs_frame.grid(row=3, column=0, sticky="ew", pady=10)
        self.recs_frame.grid_columnconfigure(0, weight=1)
        
        self.recs_hdr = ctk.CTkLabel(
            self.recs_frame,
            text="ACTIONABLE MITIGATION RECOMMENDATIONS",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("#1E7E34", "#00FF88"),
            anchor="w"
        )
        self.recs_hdr.grid(row=0, column=0, sticky="w", pady=(0, 6))
        
        # --- RIGHT PANEL: COMPILER CONTROLS ---
        self.controls_panel = ctk.CTkFrame(
            self.content_frame,
            fg_color=("#FFFFFF", "#121C2C"),
            border_color=("#D0D5DD", "#1E2D4A"),
            border_width=1.5,
            corner_radius=10
        )
        self.controls_panel.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self.controls_panel.grid_columnconfigure(0, weight=1)
        self.controls_panel.grid_rowconfigure(3, weight=1)  # Spacer/logs stretch
        
        self.ctrl_title = ctk.CTkLabel(
            self.controls_panel,
            text="REPORT COMPILER METADATA",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("#008B9B", "#00E5FF"),
            anchor="w"
        )
        self.ctrl_title.grid(row=0, column=0, sticky="w", padx=16, pady=(16, 12))
        
        # Case ID Input
        self.case_lbl = ctk.CTkLabel(
            self.controls_panel,
            text="Forensic Case ID Reference",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=("#5E6E82", "#8F9CAE"),
            anchor="w"
        )
        self.case_lbl.grid(row=1, column=0, sticky="w", padx=16, pady=(6, 2))
        
        self.case_input = ctk.CTkEntry(
            self.controls_panel,
            placeholder_text="Enter Case ID (e.g., CASE-2026-04)",
            fg_color=("#F8FAFC", "#0B0F19"),
            border_color=("#D0D5DD", "#1E2D4A"),
            text_color=("#0F172A", "#FFFFFF"),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            height=30
        )
        self.case_input.grid(row=1, column=0, sticky="ew", padx=16, pady=(2, 10))
        self.case_input.insert(0, "CASE-2026-004")
        self.case_input.bind("<KeyRelease>", self._on_input_update)
        
        # Investigator Input
        self.analyst_lbl = ctk.CTkLabel(
            self.controls_panel,
            text="Lead Forensic Investigator Name",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=("#5E6E82", "#8F9CAE"),
            anchor="w"
        )
        self.analyst_lbl.grid(row=2, column=0, sticky="w", padx=16, pady=(6, 2))
        
        self.analyst_input = ctk.CTkEntry(
            self.controls_panel,
            placeholder_text="Enter Investigator name...",
            fg_color=("#F8FAFC", "#0B0F19"),
            border_color=("#D0D5DD", "#1E2D4A"),
            text_color=("#0F172A", "#FFFFFF"),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            height=30
        )
        self.analyst_input.grid(row=2, column=0, sticky="ew", padx=16, pady=(2, 10))
        self.analyst_input.insert(0, "Cyber Analyst Team 404")
        self.analyst_input.bind("<KeyRelease>", self._on_input_update)
        
        # Exporter Log Box
        self.log_box = ctk.CTkFrame(self.controls_panel, fg_color=("#F8FAFC", "#0B0F19"), border_color=("#D0D5DD", "#1E2D4A"), border_width=1, corner_radius=6)
        self.log_box.grid(row=3, column=0, sticky="nsew", padx=16, pady=12)
        self.log_box.grid_columnconfigure(0, weight=1)
        self.log_box.grid_rowconfigure(1, weight=1)
        
        self.log_hdr = ctk.CTkLabel(
            self.log_box,
            text="COMPILER RUNTIME LOGGER",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=("#5E6E82", "#8F9CAE"),
            anchor="w"
        )
        self.log_hdr.grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))
        
        self.log_txt = ctk.CTkTextbox(
            self.log_box,
            fg_color="transparent",
            text_color=("#1E7E34", "#00FF88"),
            font=ctk.CTkFont(family="Consolas", size=10),
            corner_radius=0,
            border_width=0
        )
        self.log_txt.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 10))
        self.log_txt.insert("1.0", "Compiler status: Standby. Ready to compile forensic artifacts.")
        self.log_txt.configure(state="disabled")
        
        # Action Exporter Button
        self.pdf_btn = ctk.CTkButton(
            self.controls_panel,
            text="📊 Generate PDF Incident Report",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=("#00B4CC", "#00E5FF"),
            hover_color=("#008B9B", "#00B8CC"),
            text_color=("#090E17", "#090E17"),
            height=36,
            command=self._generate_pdf_report
        )
        self.pdf_btn.grid(row=4, column=0, sticky="ew", padx=16, pady=(0, 16))
        
        self.refresh()

    def refresh(self):
        """Loads report variables from DataProvider and updates preview document."""
        summary = self.data_service.get_summary()
        findings = self.data_service.get_findings()
        recs = self.data_service.get_recommendations()
        
        # Log page refresh event
        if hasattr(self.data_service, "add_log"):
            self.data_service.add_log("Refreshed Forensic Report Page preview.")
            
        # 1. Update Preview Meta Labels
        self.meta_labels["case_id"].configure(text=self.case_input.get().strip())
        self.meta_labels["analyst"].configure(text=self.analyst_input.get().strip())
        
        dump_p = summary.get("dump_file", "mem_dump.raw")
        self.meta_labels["target"].configure(text=dump_p)
        self.meta_labels["profile"].configure(text=summary.get("profile", "Unknown"))
        
        risk = summary.get("risk_score", 0)
        self.meta_labels["risk"].configure(
            text=f"{risk} / 100 (CRITICAL LEVEL)" if risk > 60 else f"{risk} / 100",
            text_color="#FF3B30" if risk > 60 else "#FFB300" if risk > 30 else "#00FF88"
        )
        
        # 2. Re-populate Findings List Preview
        for widget in self.findings_frame.winfo_children():
            if widget != self.findings_hdr:
                widget.destroy()
                
        for idx, finding in enumerate(findings):
            lbl = ctk.CTkLabel(
                self.findings_frame,
                text=f"•  {finding}",
                font=ctk.CTkFont(family="Segoe UI", size=11),
                text_color=("#334155", "#E2E8F0"),
                wraplength=360,
                justify="left",
                anchor="w"
            )
            lbl.grid(row=idx + 1, column=0, sticky="w", padx=14, pady=3)
            
        # 3. Re-populate Recommendations List Preview
        for widget in self.recs_frame.winfo_children():
            if widget != self.recs_hdr:
                widget.destroy()
                
        for idx, rec in enumerate(recs):
            lbl = ctk.CTkLabel(
                self.recs_frame,
                text=f"{idx + 1}.  {rec}",
                font=ctk.CTkFont(family="Segoe UI", size=11),
                text_color=("#334155", "#E2E8F0"),
                wraplength=360,
                justify="left",
                anchor="w"
            )
            lbl.grid(row=idx + 1, column=0, sticky="w", padx=14, pady=3)

        # 4. Display all system runtime activity logs
        if hasattr(self.data_service, "get_logs"):
            self.log_txt.configure(state="normal")
            self.log_txt.delete("1.0", "end")
            for logLine in self.data_service.get_logs():
                self.log_txt.insert("end", logLine + "\n")
            self.log_txt.configure(state="disabled")

    def _on_input_update(self, event=None):
        """Dynamic text listener updating the preview in real-time."""
        self.meta_labels["case_id"].configure(text=self.case_input.get().strip())
        self.meta_labels["analyst"].configure(text=self.analyst_input.get().strip())

    def _append_log_lines(self, lines):
        """
        Small helper: append one or more lines to the on-screen runtime
        logger textbox. Pulled out of _generate_pdf_report so that function
        can focus on building the report instead of repeating textbox
        enable/insert/disable calls.
        """
        self.log_txt.configure(state="normal")
        for line in lines:
            self.log_txt.insert("end", line + "\n")
        self.log_txt.configure(state="disabled")

    def _generate_pdf_report(self):
        """
        Generates the forensic PDF report and writes it to the output/ folder.

        This now delegates the actual PDF building to
        reports.pdf_generator.generate_forensic_pdf(), the same
        well-tested, nicely formatted (tables, page breaks, wrapped text)
        report builder used elsewhere in the app - instead of writing raw
        PDF bytes by hand here. That means this page only has to gather
        the report data and handle the UI side (logging + success/error
        popups); the PDF layout logic lives in exactly one place.
        """
        case_id = self.case_input.get().strip()
        analyst = self.analyst_input.get().strip()
        if not case_id:
            messagebox.showerror("Validation Error", "Please provide a valid Incident Case ID to compile reports.")
            return
            
        summary = self.data_service.get_summary()
        findings = self.data_service.get_findings()
        recs = self.data_service.get_recommendations()

        # detection_details is optional - only some DataProvider
        # implementations expose a per-category breakdown (e.g. how many
        # hidden processes, unknown DLLs, etc. were found). If it's not
        # available we simply skip that part of the report.
        detection_details = None
        if hasattr(self.data_service, "get_detection_details"):
            detection_details = self.data_service.get_detection_details()
        
        # Absolute path to the PDF inside output_dir
        pdf_filename = f"RAM_Report_Case_{case_id}.pdf"
        pdf_path = os.path.abspath(os.path.join(self.data_service.output_dir, pdf_filename))
        
        # Log start of PDF generation
        if hasattr(self.data_service, "add_log"):
            self.data_service.add_log(f"Compiling forensic report {pdf_filename}...")
        
        # Refresh logs display, then show a few progress lines while we build the PDF
        self.log_txt.configure(state="normal")
        self.log_txt.delete("1.0", "end")
        if hasattr(self.data_service, "get_logs"):
            for logLine in self.data_service.get_logs():
                self.log_txt.insert("end", logLine + "\n")
        self.log_txt.configure(state="disabled")
        self._append_log_lines([
            "[~] Packaging forensic audit segments...",
            f"[*] Target output path: {pdf_path}",
            "[+] Compiling findings timeline and DLL checksums...",
        ])
        
        metadata = {
            "Case ID": case_id,
            "Lead Investigator": analyst,
            "Target File": summary.get("dump_file", "mem_dump.raw"),
            "Profile": summary.get("profile", "Unknown"),
            "Risk Score": f"{summary.get('risk_score', 0)}/100",
            "Report Date": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        
        # Generate the PDF file using the shared report builder.
        try:
            generate_forensic_pdf(
                pdf_path,
                metadata,
                findings,
                recs,
                detection_details=detection_details,
            )

            if hasattr(self.data_service, "add_log"):
                self.data_service.add_log(f"Successfully generated PDF: {pdf_filename}")
            
            # Log success to console
            self._append_log_lines(["[✔] Compiled successfully. File locked on disk."])
            
            # Show success popup
            messagebox.showinfo(
                "PDF Export Success",
                f"✔ Forensic Report successfully compiled and saved to output directory:\n\n"
                f"Path: {pdf_path}"
            )
        except Exception as e:
            if hasattr(self.data_service, "add_log"):
                self.data_service.add_log(f"Error compiling PDF: {e}")
            self._append_log_lines([f"[!] Error compiling PDF: {e}"])
            messagebox.showerror("Export Error", f"Failed to save PDF report file:\n{e}")