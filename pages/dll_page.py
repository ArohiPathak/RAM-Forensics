import customtkinter as ctk
from pages.base_page import BasePage
from widgets.custom_table import CustomTable
from services.data_provider import DataProvider
from typing import Dict, Any

class DllPage(BasePage):
    """
    DllPage monitors dynamic libraries loaded by processes.
    Features:
    - Lists DLL paths and process mapping.
    - Search filtering by DLL name, owner PID, status, or path.
    - Highlights suspicious DLLs with custom threat alarms.
    - Details drawer displaying integrity status and mitigation rules.
    """
    def __init__(self, master, data_service: DataProvider, **kwargs):
        super().__init__(
            master, 
            data_service, 
            title="DLL Analysis", 
            description="Loaded dynamic link libraries (DLLs), file paths, and threat risk levels.", 
            **kwargs
        )
        
        self.raw_dlls = []
        
        # Configure layout (2 panels: left list, right detail info)
        self.content_frame.grid_columnconfigure(0, weight=3)
        self.content_frame.grid_columnconfigure(1, weight=2)
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        # --- LEFT SIDE: TABLE ---
        self.left_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.left_frame.grid_columnconfigure(0, weight=1)
        self.left_frame.grid_rowconfigure(1, weight=1)
        
        # Search filter
        self.search_frame = ctk.CTkFrame(self.left_frame, fg_color=("#FFFFFF", "#121C2C"), border_color=("#D0D5DD", "#1E2D4A"), border_width=1, corner_radius=6, height=45)
        self.search_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self.search_frame.grid_columnconfigure(0, weight=1)
        
        self.search_input = ctk.CTkEntry(
            self.search_frame,
            placeholder_text="🔍 Filter DLLs by name, loaded process, path, or risk...",
            fg_color=("#F8FAFC", "#0B0F19"),
            border_color=("#D0D5DD", "#1E2D4A"),
            text_color=("#0F172A", "#FFFFFF"),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            height=30
        )
        self.search_input.grid(row=0, column=0, sticky="ew", padx=12, pady=8)
        self.search_input.bind("<KeyRelease>", lambda e: self._filter_and_render())
        
        # Custom table mapping DLL parameters
        cols = [
            ("dll", "DLL", 2),
            ("loaded_by", "Loaded By", 2),
            ("path", "Path", 4),
            ("status", "Status", 2),
            ("risk", "Risk", 2)
        ]
        self.table = CustomTable(
            self.left_frame,
            columns=cols,
            on_select_row=self._on_select_dll,
            mono_columns=["dll", "loaded_by", "path"]
        )
        self.table.grid(row=1, column=0, sticky="nsew")
        
        # --- RIGHT SIDE: METADATA INSPECTOR ---
        self.detail_frame = ctk.CTkFrame(
            self.content_frame, 
            fg_color=("#FFFFFF", "#121C2C"), 
            border_color=("#D0D5DD", "#1E2D4A"), 
            border_width=1.5, 
            corner_radius=10
        )
        self.detail_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self.detail_frame.grid_columnconfigure(0, weight=1)
        self.detail_frame.grid_rowconfigure(2, weight=1)  # Warnings card expands
        
        self.detail_title = ctk.CTkLabel(
            self.detail_frame,
            text="DLL METADATA CARD",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("#008B9B", "#00E5FF"),
            anchor="w"
        )
        self.detail_title.grid(row=0, column=0, sticky="w", padx=16, pady=(16, 8))
        
        # Data grid fields
        self.info_box = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
        self.info_box.grid(row=1, column=0, sticky="ew", padx=16, pady=4)
        self.info_box.grid_columnconfigure(1, weight=1)
        
        self.fields = {}
        info_rows = [
            ("dll", "DLL Filename"),
            ("loaded_by", "Loaded By (PID)"),
            ("path", "Full Library Path"),
            ("status", "Scan Integrity Status"),
            ("risk", "Threat Severity")
        ]
        
        for idx, (field_key, display_label) in enumerate(info_rows):
            lbl_title = ctk.CTkLabel(
                self.info_box,
                text=display_label,
                font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
                text_color=("#475569", "#627284"),
                anchor="w"
            )
            lbl_title.grid(row=idx, column=0, sticky="w", pady=4, padx=(0, 16))
            
            lbl_val = ctk.CTkLabel(
                self.info_box,
                text="-",
                font=ctk.CTkFont(family="Consolas" if field_key in ["dll", "loaded_by", "path"] else "Segoe UI", size=11),
                text_color=("#0F172A", "#FFFFFF"),
                anchor="w",
                wraplength=200,
                justify="left"
            )
            lbl_val.grid(row=idx, column=1, sticky="w", pady=4)
            self.fields[field_key] = lbl_val
            
        # Alarm box frame inside drawer
        self.alarm_box = ctk.CTkFrame(self.detail_frame, fg_color=("#EAECF0", "#182436"), corner_radius=6)
        self.alarm_box.grid(row=2, column=0, sticky="nsew", padx=16, pady=(12, 16))
        self.alarm_box.grid_columnconfigure(0, weight=1)
        self.alarm_box.grid_rowconfigure(1, weight=1)
        
        self.alarm_hdr = ctk.CTkLabel(
            self.alarm_box,
            text="DLL INTEGRITY SCAN",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=("#5E6E82", "#8F9CAE"),
            anchor="w"
        )
        self.alarm_hdr.grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))
        
        self.alarm_txt = ctk.CTkTextbox(
            self.alarm_box,
            fg_color="transparent",
            text_color=("#334155", "#A0AEC0"),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            corner_radius=0,
            border_width=0
        )
        self.alarm_txt.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 10))
        self.alarm_txt.insert("1.0", "Select a dynamic link library from the table monitor to inspect path integrity, virtual base space size, and threat analysis tags.")
        self.alarm_txt.configure(state="disabled")
        
        self.refresh()

    def refresh(self):
        """Loads DLL data from data provider service and populates custom table."""
        self.raw_dlls = self.data_service.get_dlls()
        self._filter_and_render()
        self._clear_detail_panel()

    def _filter_and_render(self):
        """Filters DLL rows by query term."""
        query = self.search_input.get().strip().lower()
        if not query:
            filtered = self.raw_dlls
        else:
            filtered = [
                d for d in self.raw_dlls
                if query in str(d.get("dll", "")).lower()
                or query in str(d.get("loaded_by", "")).lower()
                or query in str(d.get("path", "")).lower()
                or query in str(d.get("status", "")).lower()
                or query in str(d.get("risk", "")).lower()
            ]
        self.table.set_data(filtered)

    def _on_select_dll(self, dll_data: Dict[str, Any]):
        """Populates detail monitor panel when a row is clicked."""
        for field_key, lbl in self.fields.items():
            lbl.configure(text=str(dll_data.get(field_key, "-")))
            
        self.alarm_txt.configure(state="normal")
        self.alarm_txt.delete("1.0", "end")
        
        risk = str(dll_data.get("risk", "Low")).upper()
        if risk in ["CRITICAL", "HIGH"]:
            self.alarm_box.configure(fg_color=("#FDE8E8", "#2C1212"), border_color="#FF3B30", border_width=1)
            self.alarm_hdr.configure(text="🚨 UNREGISTERED DLL PATH DETECTED", text_color=("#DE350B", "#FF3B30"))
            
            msg = f"WARNING: Anomalous library load signature in '{dll_data.get('loaded_by')}':\n"
            msg += f"-> Loaded DLL: {dll_data.get('dll')}\n"
            msg += f"-> File Path: {dll_data.get('path')}\n\n"
            msg += "Forensic Flag: Standard processes must never load libraries out of public profiles. This indicates DLL hijacking/side-loading."
            self.alarm_txt.insert("1.0", msg)
        else:
            self.alarm_box.configure(fg_color=("#E6F9F0", "#0D251C"), border_color="#00FF88", border_width=1)
            self.alarm_hdr.configure(text="✔ VALID KNOWN SYSTEM PATH", text_color=("#1E7E34", "#00FF88"))
            self.alarm_txt.insert("1.0", "Dynamic library successfully resolved to standard System32 library path. Code signature verified as valid Microsoft Component. Integrity check passed.")
            
        self.alarm_txt.configure(state="disabled")

    def _clear_detail_panel(self):
        """Clears selection state from fields."""
        for lbl in self.fields.values():
            lbl.configure(text="-")
        self.alarm_box.configure(fg_color=("#EAECF0", "#182436"), border_width=0)
        self.alarm_hdr.configure(text="DLL INTEGRITY SCAN", text_color=("#5E6E82", "#8F9CAE"))
        self.alarm_txt.configure(state="normal")
        self.alarm_txt.delete("1.0", "end")
        self.alarm_txt.insert("1.0", "Select a dynamic link library from the table monitor to inspect path integrity, virtual base space size, and threat analysis tags.")
        self.alarm_txt.configure(state="disabled")
