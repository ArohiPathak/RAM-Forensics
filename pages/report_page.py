import customtkinter as ctk
import os
from tkinter import messagebox
from pages.base_page import BasePage
from services.data_provider import DataProvider
from typing import Dict, Any

class ReportPage(BasePage):
    """
    ReportPage compiles dynamic summary fields into a preview document.
    Features:
    - Left side: High-fidelity document page preview mapping:
      - Case ID, Investigator name (updating live from inputs).
      - Target memory file path, OS profile, risk score.
      - Bullet points listing forensic findings and actionable recommendations.
    - Right side: Config inputs (Case ID, Investigator name).
    - Generate PDF Action: displays a successful validation popup.
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
        import time
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

    def _generate_pdf_report(self):
        """Generates a valid standard PDF document and writes it to the output/ folder."""
        import time
        case_id = self.case_input.get().strip()
        analyst = self.analyst_input.get().strip()
        if not case_id:
            messagebox.showerror("Validation Error", "Please provide a valid Incident Case ID to compile reports.")
            return
            
        summary = self.data_service.get_summary()
        findings = self.data_service.get_findings()
        recs = self.data_service.get_recommendations()
        
        # Absolute path to the PDF inside output_dir
        pdf_filename = f"RAM_Report_Case_{case_id}.pdf"
        pdf_path = os.path.abspath(os.path.join(self.data_service.output_dir, pdf_filename))
        
        # Log start of PDF generation
        if hasattr(self.data_service, "add_log"):
            self.data_service.add_log(f"Compiling forensic report {pdf_filename}...")
        
        # Refresh logs display
        self.log_txt.configure(state="normal")
        self.log_txt.delete("1.0", "end")
        if hasattr(self.data_service, "get_logs"):
            for logLine in self.data_service.get_logs():
                self.log_txt.insert("end", logLine + "\n")
        self.log_txt.insert("end", "[~] Packaging forensic audit segments...\n")
        self.log_txt.insert("end", f"[*] Target output path: {pdf_path}\n")
        self.log_txt.insert("end", "[+] Compiling findings timeline and DLL checksums...\n")
        self.log_txt.configure(state="disabled")
        
        metadata = {
            "Case ID": case_id,
            "Lead Investigator": analyst,
            "Target File": summary.get("dump_file", "mem_dump.raw"),
            "Profile": summary.get("profile", "Unknown"),
            "Risk Score": f"{summary.get('risk_score', 0)}/100",
            "Report Date": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Generate the PDF file
        try:
            # Create folder if missing
            os.makedirs(os.path.dirname(pdf_path), exist_ok=True)
            
            # Simple PDF construction
            stream_content = []
            stream_content.append("BT")
            stream_content.append("/F1 16 Tf")
            stream_content.append("70 750 Td")
            stream_content.append("(VOLATILITY 3 MEMORY FORENSICS REPORT) Tj")
            stream_content.append("0 -30 Td")
            
            stream_content.append("/F1 10 Tf")
            for key, val in metadata.items():
                safe_val = str(val).replace("(", "\\(").replace(")", "\\)")
                stream_content.append(f"({key}: {safe_val}) Tj")
                stream_content.append("0 -15 Td")
                
            stream_content.append("0 -15 Td")
            stream_content.append("/F1 12 Tf")
            stream_content.append("(FORENSIC FINDINGS:) Tj")
            stream_content.append("0 -20 Td")
            stream_content.append("/F1 9 Tf")
            for f in findings:
                safe_f = f.replace("(", "\\(").replace(")", "\\)")
                stream_content.append(f"(- {safe_f}) Tj")
                stream_content.append("0 -13 Td")
                
            stream_content.append("0 -15 Td")
            stream_content.append("/F1 12 Tf")
            stream_content.append("(MITIGATION RECOMMENDATIONS:) Tj")
            stream_content.append("0 -20 Td")
            stream_content.append("/F1 9 Tf")
            for r in recs:
                safe_r = r.replace("(", "\\(").replace(")", "\\)")
                stream_content.append(f"(- {safe_r}) Tj")
                stream_content.append("0 -13 Td")
                
            stream_content.append("ET")
            
            stream_str = "\n".join(stream_content)
            stream_bytes = stream_str.encode('latin1')
            
            objects = []
            objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
            objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
            objects.append(b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 595.27 841.89] /Contents 5 0 R >>")
            objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
            objects.append(f"<< /Length {len(stream_bytes)} >>\nstream\n".encode('latin1') + stream_bytes + b"\nendstream")
            
            with open(pdf_path, "wb") as f:
                f.write(b"%PDF-1.4\n")
                offsets = []
                for idx, obj in enumerate(objects):
                    offsets.append(f.tell())
                    f.write(f"{idx+1} 0 obj\n".encode('latin1'))
                    f.write(obj)
                    f.write(b"\nendobj\n")
                    
                xref_offset = f.tell()
                f.write(b"xref\n")
                f.write(f"0 {len(objects)+1}\n".encode('latin1'))
                f.write(b"0000000000 65535 f \n")
                for offset in offsets:
                    f.write(f"{offset:010d} 00000 n \n".encode('latin1'))
                    
                f.write(b"trailer\n")
                f.write(f"<< /Size {len(objects)+1} /Root 1 0 R >>\n".encode('latin1'))
                f.write(b"startxref\n")
                f.write(f"{xref_offset}\n".encode('latin1'))
                f.write(b"%%EOF\n")
                
            if hasattr(self.data_service, "add_log"):
                self.data_service.add_log(f"Successfully generated PDF: {pdf_filename}")
            
            # Log success to console
            self.log_txt.configure(state="normal")
            self.log_txt.insert("end", "[✔] Compiled successfully. File locked on disk.\n")
            self.log_txt.configure(state="disabled")
            
            # Show success popup
            messagebox.showinfo(
                "PDF Export Success",
                f"✔ Forensic Report successfully compiled and saved to output directory:\n\n"
                f"Path: {pdf_path}"
            )
        except Exception as e:
            if hasattr(self.data_service, "add_log"):
                self.data_service.add_log(f"Error compiling PDF: {e}")
            messagebox.showerror("Export Error", f"Failed to save PDF report file:\n{e}")
