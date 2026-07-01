import customtkinter as ctk
from frontend.pages.base_page import BasePage
from frontend.widgets.custom_table import CustomTable
from frontend.services.data_provider import DataProvider
from typing import Dict, Any

class ProcessesPage(BasePage):
    """
    ProcessesPage monitors running and hidden processes from the RAM dump.
    Features:
    - Text search bar filtering processes by PID, Name, or Parent.
    - CustomTable listing process parameters:
      (PID, Process Name, Parent Process, Threads, Memory Usage, Risk).
    - Details drawer showing complete metadata, integrity checks, and analyst guidance.
    """
    def __init__(self, master, data_service: DataProvider, **kwargs):
        super().__init__(
            master, 
            data_service, 
            title="Processes Monitor", 
            description="Process listing, virtual memory space, and threat risk levels.", 
            **kwargs
        )
        
        self.raw_processes = []
        
        # Configure layout (2 columns: left is table/search, right is detail panel)
        self.content_frame.grid_columnconfigure(0, weight=3)  # List frame
        self.content_frame.grid_columnconfigure(1, weight=2)  # Detail frame
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        # --- LEFT SIDE: TABLE AND FILTER SEARCH ---
        self.list_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.list_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.list_frame.grid_columnconfigure(0, weight=1)
        self.list_frame.grid_rowconfigure(1, weight=1)  # Table expands
        
        # Search panel
        self.search_frame = ctk.CTkFrame(self.list_frame, fg_color=("#FFFFFF", "#121C2C"), border_color=("#D0D5DD", "#1E2D4A"), border_width=1, corner_radius=6, height=45)
        self.search_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self.search_frame.grid_columnconfigure(0, weight=1)
        
        self.search_input = ctk.CTkEntry(
            self.search_frame,
            placeholder_text="🔍 Filter processes by PID, Name, Parent, or Risk...",
            fg_color=("#F8FAFC", "#0B0F19"),
            border_color=("#D0D5DD", "#1E2D4A"),
            text_color=("#0F172A", "#FFFFFF"),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            height=30
        )
        self.search_input.grid(row=0, column=0, sticky="ew", padx=12, pady=8)
        self.search_input.bind("<KeyRelease>", self._on_search_key)
        
        # Clear filter button
        self.clear_btn = ctk.CTkButton(
            self.search_frame,
            text="Clear",
            width=50,
            height=28,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color=("#EAECF0", "#162235"),
            hover_color=("#D0D5DD", "#1E2D4A"),
            text_color=("#475569", "#8F9CAE"),
            command=self._clear_search
        )
        self.clear_btn.grid(row=0, column=1, sticky="e", padx=(0, 12), pady=8)
        
        # Processes custom table widget
        cols = [
            ("pid", "PID", 1),
            ("name", "Process Name", 3),
            ("parent", "Parent Process", 2),
            ("threads", "Threads", 1),
            ("memory", "Memory Usage", 2),
            ("risk", "Risk", 2)
        ]
        self.table = CustomTable(
            self.list_frame,
            columns=cols,
            on_select_row=self._on_select_process,
            mono_columns=["pid", "parent", "threads", "memory"]
        )
        self.table.grid(row=1, column=0, sticky="nsew")
        
        # --- RIGHT SIDE: DETAILED MONITOR DRAWER ---
        self.detail_frame = ctk.CTkFrame(
            self.content_frame, 
            fg_color=("#FFFFFF", "#121C2C"), 
            border_color=("#D0D5DD", "#1E2D4A"), 
            border_width=1.5, 
            corner_radius=10
        )
        self.detail_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self.detail_frame.grid_columnconfigure(0, weight=1)
        self.detail_frame.grid_rowconfigure(2, weight=1)  # Notes block stretches
        
        # Detail Header
        self.detail_title = ctk.CTkLabel(
            self.detail_frame,
            text="PROCESS METADATA CARD",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("#008B9B", "#00E5FF"),
            anchor="w"
        )
        self.detail_title.grid(row=0, column=0, sticky="w", padx=16, pady=(16, 8))
        
        # Info Box wrapper (displays process fields)
        self.info_box = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
        self.info_box.grid(row=1, column=0, sticky="ew", padx=16, pady=4)
        self.info_box.grid_columnconfigure(1, weight=1)
        
        self.fields = {}
        info_rows = [
            ("pid", "Process ID (PID)"),
            ("name", "Process Name"),
            ("parent", "Parent Process (PPID)"),
            ("threads", "Active Threads"),
            ("memory", "Memory Usage"),
            ("risk", "Threat Risk Level")
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
                font=ctk.CTkFont(family="Consolas" if field_key in ["pid", "parent", "memory"] else "Segoe UI", size=11),
                text_color=("#0F172A", "#FFFFFF"),
                anchor="w",
                wraplength=200,
                justify="left"
            )
            lbl_val.grid(row=idx, column=1, sticky="w", pady=4)
            self.fields[field_key] = lbl_val

        # Status badge frame inside detail drawer
        self.status_box = ctk.CTkFrame(self.detail_frame, fg_color=("#EAECF0", "#182436"), corner_radius=6, height=36)
        self.status_box.grid(row=2, column=0, sticky="ew", padx=16, pady=(12, 4))
        self.status_box.grid_columnconfigure(0, weight=1)
        self.status_box.grid_rowconfigure(0, weight=1)
        
        self.status_lbl = ctk.CTkLabel(
            self.status_box,
            text="No Process Selected",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("#5E6E82", "#8F9CAE")
        )
        self.status_lbl.grid(row=0, column=0, sticky="nsew", padx=10, pady=8)

        # Analyst Notes Panel
        self.notes_frame = ctk.CTkFrame(self.detail_frame, fg_color=("#F8FAFC", "#0B0F19"), border_color=("#D0D5DD", "#1E2D4A"), border_width=1, corner_radius=6)
        self.notes_frame.grid(row=3, column=0, sticky="nsew", padx=16, pady=(8, 16))
        self.notes_frame.grid_columnconfigure(0, weight=1)
        self.notes_frame.grid_rowconfigure(1, weight=1)
        
        self.notes_title = ctk.CTkLabel(
            self.notes_frame,
            text="ANALYST FORENSIC NOTES",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=("#5E6E82", "#8F9CAE"),
            anchor="w"
        )
        self.notes_title.grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))
        
        self.notes_txt = ctk.CTkTextbox(
            self.notes_frame,
            fg_color="transparent",
            text_color=("#334155", "#A0AEC0"),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            corner_radius=0,
            border_width=0
        )
        self.notes_txt.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 10))
        self.notes_txt.insert("1.0", "Select a process from the monitor grid to review detailed memory snapshot alerts, associated handles, thread count patterns, and static path anomaly checks.")
        self.notes_txt.configure(state="disabled")
        
        self.refresh()

    def refresh(self):
        """Loads processes from data provider service and updates the custom table."""
        self.raw_processes = self.data_service.get_processes()
        self._filter_and_render()
        self._clear_detail_panel()

    def _filter_and_render(self):
        """Applies search filters to process table."""
        query = self.search_input.get().strip().lower()
        if not query:
            filtered = self.raw_processes
        else:
            filtered = [
                p for p in self.raw_processes
                if query in str(p.get("pid", "")).lower()
                or query in str(p.get("parent", "")).lower()
                or query in str(p.get("name", "")).lower()
                or query in str(p.get("memory", "")).lower()
                or query in str(p.get("risk", "")).lower()
            ]
        self.table.set_data(filtered)

    def _on_search_key(self, event=None):
        self._filter_and_render()

    def _clear_search(self):
        self.search_input.delete(0, "end")
        self._filter_and_render()

    def _on_select_process(self, proc_data: Dict[str, Any]):
        """Populates detail monitor panel when a row is clicked."""
        for field_key, lbl in self.fields.items():
            val = proc_data.get(field_key, "-")
            lbl.configure(text=str(val))
            
        # Draw status badge based on risk
        risk = str(proc_data.get("risk", "Low")).upper()
        if risk in ["CRITICAL", "HIGH"]:
            self.status_box.configure(fg_color=("#FDE8E8", "#2C1212"), border_color="#FF3B30", border_width=1)
            self.status_lbl.configure(text="CRITICAL THREAT FLAG", text_color=("#DE350B", "#FF3B30"))
        elif risk in ["MEDIUM", "WARNING"]:
            self.status_box.configure(fg_color=("#FFF8E1", "#251F0D"), border_color="#FFB300", border_width=1)
            self.status_lbl.configure(text="SUSPICIOUS ACTIVITY FLAG", text_color=("#B7791F", "#FFB300"))
        else:
            self.status_box.configure(fg_color=("#E6F9F0", "#0D251C"), border_color="#00FF88", border_width=1)
            self.status_lbl.configure(text="VERIFIED SECURE PROFILE", text_color=("#1E7E34", "#00FF88"))
            
        # Update analyst notes
        self.notes_txt.configure(state="normal")
        self.notes_txt.delete("1.0", "end")
        notes = proc_data.get("notes", "No anomaly signatures matched for this process image.")
        self.notes_txt.insert("1.0", notes)
        self.notes_txt.configure(state="disabled")

    def _clear_detail_panel(self):
        """Clears selection state from fields."""
        for lbl in self.fields.values():
            lbl.configure(text="-")
        self.status_box.configure(fg_color=("#EAECF0", "#182436"), border_width=0)
        self.status_lbl.configure(text="No Process Selected", text_color=("#5E6E82", "#8F9CAE"))
        self.notes_txt.configure(state="normal")
        self.notes_txt.delete("1.0", "end")
        self.notes_txt.insert("1.0", "Select a process from the monitor grid to review detailed memory snapshot alerts, associated handles, thread count patterns, and static path anomaly checks.")
        self.notes_txt.configure(state="disabled")
