import customtkinter as ctk
import os
from tkinter import filedialog, messagebox
from pages.base_page import BasePage
from services.data_provider import DataProvider

class UploadPage(BasePage):
    """
    UploadPage provides a dedicated interface to load memory dumps.
    Features:
    - Large simulated drag-and-drop area.
    - Extension validation enforcing (.raw, .mem, .vmem) constraints.
    - Status indicators mapping file sizes and path variables.
    - Browse, Analyze, and Cancel control actions.
    - Integrates with the Loading Page simulator.
    """
    def __init__(self, master, data_service: DataProvider, **kwargs):
        super().__init__(
            master, 
            data_service, 
            title="Upload Memory Dump", 
            description="Import acquired raw RAM images to analyze process space structural anomalies.", 
            **kwargs
        )
        
        # Hide standard refresh button to focus on page form buttons
        self.refresh_btn.grid_remove()
        
        self.selected_file_path = ""
        self.supported_extensions = [".raw", ".mem", ".vmem"]
        
        # Configure layout: Column 0 stretches, Row 0 stretches
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        # Main form panel
        self.form_panel = ctk.CTkFrame(
            self.content_frame,
            fg_color=("#FFFFFF", "#121C2C"),
            border_color=("#D0D5DD", "#1E2D4A"),
            border_width=1.5,
            corner_radius=12
        )
        self.form_panel.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.form_panel.grid_columnconfigure(0, weight=1)
        self.form_panel.grid_rowconfigure(0, weight=1)  # Upload box stretches
        
        # 1. Upload box (Large simulated Drag-and-Drop Area)
        # Using a darker inset color to represent drop target zone
        self.drop_zone = ctk.CTkFrame(
            self.form_panel,
            fg_color=("#F8FAFC", "#0B0F19"),
            border_color=("#D0D5DD", "#1E2D4A"),
            border_width=2,
            corner_radius=8
        )
        self.drop_zone.grid(row=0, column=0, padx=30, pady=(30, 20), sticky="nsew")
        self.drop_zone.grid_columnconfigure(0, weight=1)
        self.drop_zone.grid_rowconfigure(0, weight=1)
        
        # Interactive elements inside drop zone
        self.drop_content = ctk.CTkFrame(self.drop_zone, fg_color="transparent")
        self.drop_content.grid(row=0, column=0)
        self.drop_content.grid_columnconfigure(0, weight=1)
        
        self.drop_icon = ctk.CTkLabel(
            self.drop_content,
            text="📂",
            font=ctk.CTkFont(size=56),
            text_color=("#00B4CC", "#00E5FF")
        )
        self.drop_icon.grid(row=0, column=0, pady=(0, 10))
        
        self.drop_title = ctk.CTkLabel(
            self.drop_content,
            text="Drag & drop your memory image here\nor click browse to locate the file",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="normal"),
            text_color=("#5E6E82", "#8F9CAE"),
            justify="center"
        )
        self.drop_title.grid(row=1, column=0, pady=2)
        
        self.drop_ext = ctk.CTkLabel(
            self.drop_content,
            text="Supported types: .raw, .mem, .vmem (Volatility standard)",
            font=ctk.CTkFont(family="Segoe UI", size=11, slant="italic"),
            text_color=("#64748B", "#627284")
        )
        self.drop_ext.grid(row=2, column=0, pady=(6, 0))
        
        # 2. Control Buttons Area
        self.actions_frame = ctk.CTkFrame(self.form_panel, fg_color="transparent")
        self.actions_frame.grid(row=1, column=0, padx=30, pady=(0, 30), sticky="ew")
        
        # Standard buttons: Browse, Analyze, Cancel
        # Grid weight coordinates to distribute buttons evenly
        self.actions_frame.grid_columnconfigure(0, weight=1) # Cancel (left aligned)
        self.actions_frame.grid_columnconfigure(2, weight=1) # Analyze (right aligned)
        
        self.cancel_btn = ctk.CTkButton(
            self.actions_frame,
            text="✖ Cancel Selection",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="transparent",
            border_color="#FF3B30",
            border_width=1,
            hover_color=("#FDE8E8", "#2D1A1A"),
            text_color="#FF3B30",
            height=36,
            command=self._cancel_selection
        )
        self.cancel_btn.grid(row=0, column=0, sticky="w", padx=(0, 10))
        
        self.browse_btn = ctk.CTkButton(
            self.actions_frame,
            text="🔍 Browse Target File",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=("#EAECF0", "#162235"),
            hover_color=("#D0D5DD", "#1E2D4A"),
            border_color=("#D0D5DD", "#1E2D4A"),
            border_width=1.5,
            text_color=("#00B4CC", "#00E5FF"),
            height=36,
            command=self._browse_file
        )
        self.browse_btn.grid(row=0, column=1, padx=10)
        
        self.analyze_btn = ctk.CTkButton(
            self.actions_frame,
            text="🚀 Start Forensic Analysis",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=("#00B4CC", "#00E5FF"),
            hover_color=("#008B9B", "#00B8CC"),
            text_color=("#090E17", "#090E17"),
            height=36,
            command=self._analyze_file
        )
        self.analyze_btn.grid(row=0, column=2, sticky="e", padx=(10, 0))
        
        self.refresh()

    def refresh(self):
        """Loads and pre-populates previous files selected if any."""
        summary = self.data_service.get_summary()
        dump_path = summary.get("dump_file", "")
        
        if dump_path and os.path.exists(dump_path):
            self._update_selected_file(dump_path)
        else:
            self._reset_selection_display()

    def _browse_file(self):
        """Opens native file system directory explorer."""
        file_path = filedialog.askopenfilename(
            title="Select Memory Dump target",
            filetypes=[
                ("Volatility Target Images", "*.raw;*.mem;*.vmem"), 
                ("All Files", "*.*")
            ]
        )
        
        if not file_path:
            return
            
        # Verify file extensions
        _, ext = os.path.splitext(file_path.lower())
        if ext not in self.supported_extensions:
            messagebox.showerror(
                "Unsupported File Type",
                f"Selected file extension '{ext}' is not supported.\n\n"
                f"Supported types: {', '.join(self.supported_extensions)}"
            )
            return
            
        self._update_selected_file(file_path)

    def _update_selected_file(self, file_path: str):
        """Prepares the selected path and updates screen metrics."""
        self.selected_file_path = file_path
        filename = os.path.basename(file_path)
        ext = os.path.splitext(filename)[1].lower()
        
        try:
            sz_bytes = os.path.getsize(file_path)
            sz_gb = sz_bytes / (1024 * 1024 * 1024)
            size_txt = f"{sz_gb:.2f} GB"
        except OSError:
            size_txt = "16.00 GB (Dummy Size)"
            
        # Update Drag & Drop Visual Box to green/cyan details card
        self.drop_icon.configure(text="✔", text_color=("#1E7E34", "#00FF88"))
        self.drop_title.configure(
            text=f"TARGET LOADED SUCCESSFULLY\n\nFile Name: {filename}\nFile Size: {size_txt}\nExtension: {ext}\nStatus: Ready for Analysis",
            text_color=("#1E7E34", "#00FF88")
        )
        self.drop_ext.configure(
            text=f"Full Path: {file_path}",
            text_color=("#475569", "#8F9CAE")
        )
        self.drop_zone.configure(border_color=("#00C868", "#00FF88"))
        
        # Enable analyze button
        self.analyze_btn.configure(state="normal", fg_color=("#00B4CC", "#00E5FF"), text_color=("#090E17", "#090E17"))

    def _cancel_selection(self):
        """Resets the input files selected."""
        self._reset_selection_display()
        
    def _reset_selection_display(self):
        """Clears states and labels."""
        self.selected_file_path = ""
        self.drop_icon.configure(text="📂", text_color=("#00B4CC", "#00E5FF"))
        self.drop_title.configure(
            text="Drag & drop your memory image here\nor click browse to locate the file",
            text_color=("#5E6E82", "#8F9CAE")
        )
        self.drop_ext.configure(
            text="Supported types: .raw, .mem, .vmem (Volatility standard)",
            text_color=("#64748B", "#627284")
        )
        self.drop_zone.configure(border_color=("#D0D5DD", "#1E2D4A"))
        
        # Disable analyze button until file is selected
        self.analyze_btn.configure(state="disabled", fg_color=("#F1F5F9", "#1A2436"), text_color=("#94A3B8", "#627284"))

    def _analyze_file(self):
        """Launches loading view screen to run simulation plugin execution."""
        if not self.selected_file_path:
            return
            
        # Save filepath to data provider database
        summary = self.data_service.get_summary()
        summary["dump_file"] = self.selected_file_path
        summary["status"] = "Analyzing..."
        
        try:
            with open(self.data_service.get_output_path("summary.json"), "w", encoding="utf-8") as f:
                import json
                json.dump(summary, f, indent=4)
        except Exception as e:
            print(f"Error saving updated target filepath: {e}")
            
        # Navigate to loading view frame registered in top-level App
        app = self.winfo_toplevel()
        if hasattr(app, "show_page") and "loading" in app.pages:
            # Switch view first
            app.show_page("loading")
            # Trigger Volatility simulated thread logs run
            app.pages["loading"].start_analysis(self.selected_file_path)
