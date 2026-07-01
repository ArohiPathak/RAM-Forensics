import customtkinter as ctk
from pages.base_page import BasePage
from widgets.custom_table import CustomTable
from services.data_provider import DataProvider
from typing import Dict, Any

class NetworkPage(BasePage):
    """
    NetworkPage displays active network sockets captured in RAM (netscan plugin).
    Features:
    - Quick filter tab segments (All Sockets, Established, Listening, Suspicious).
    - CustomTable mapping socket properties:
      (Local IP, Remote IP, Port, Protocol, Process, Risk).
    - Side drawer showing IP geo-context placeholders and socket owner details.
    """
    def __init__(self, master, data_service: DataProvider, **kwargs):
        super().__init__(
            master, 
            data_service, 
            title="Network Connections", 
            description="Active TCP/UDP sockets, listening ports, and threat risk levels.", 
            **kwargs
        )
        
        self.raw_connections = []
        self.active_filter = "ALL"
        self.filter_buttons = {}
        
        # Configure layout (2 columns: left is table/filters, right is detail panel)
        self.content_frame.grid_columnconfigure(0, weight=3)
        self.content_frame.grid_columnconfigure(1, weight=2)
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        # --- LEFT SIDE: TABLE AND FILTERS ---
        self.left_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.left_frame.grid_columnconfigure(0, weight=1)
        self.left_frame.grid_rowconfigure(1, weight=1)  # Table expands
        
        # Filter controls header
        self.controls_frame = ctk.CTkFrame(self.left_frame, fg_color=("#FFFFFF", "#121C2C"), border_color=("#D0D5DD", "#1E2D4A"), border_width=1, corner_radius=6)
        self.controls_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self.controls_frame.grid_columnconfigure(0, weight=1)
        
        # Quick Filter Button Segment
        self.filter_bar = ctk.CTkFrame(self.controls_frame, fg_color="transparent")
        self.filter_bar.grid(row=0, column=0, sticky="w", padx=8, pady=8)
        
        filters = [
            ("ALL", "All Connections"),
            ("ESTABLISHED", "Established"),
            ("LISTENING", "Listening Only"),
            ("SUSPICIOUS", "🚨 Anomalies")
        ]
        
        for idx, (f_key, f_lbl) in enumerate(filters):
            btn = ctk.CTkButton(
                self.filter_bar,
                text=f_lbl,
                width=110,
                height=26,
                font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold" if f_key == "ALL" else "normal"),
                fg_color=("#EAECF0", "#1E2D4A") if f_key == "ALL" else "transparent",
                hover_color=("#D0D5DD", "#1A273D"),
                text_color=("#008B9B", "#00E5FF") if f_key == "ALL" else ("#5E6E82", "#8F9CAE"),
                corner_radius=4,
                command=lambda k=f_key: self._set_active_filter(k)
            )
            btn.grid(row=0, column=idx, padx=4)
            self.filter_buttons[f_key] = btn
            
        # Search Entry box inside controls header
        self.search_input = ctk.CTkEntry(
            self.controls_frame,
            placeholder_text="🔍 Filter by IP, Port, Protocol, Process, or Risk...",
            fg_color=("#F8FAFC", "#0B0F19"),
            border_color=("#D0D5DD", "#1E2D4A"),
            text_color=("#0F172A", "#FFFFFF"),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            height=26,
            width=200
        )
        self.search_input.grid(row=0, column=1, sticky="e", padx=12, pady=8)
        self.search_input.bind("<KeyRelease>", lambda e: self._filter_and_render())
        
        # Network Custom Table
        cols = [
            ("local_ip", "Local IP", 3),
            ("remote_ip", "Remote IP", 3),
            ("port", "Port", 1),
            ("protocol", "Protocol", 1),
            ("process", "Process", 2),
            ("risk", "Risk", 2)
        ]
        self.table = CustomTable(
            self.left_frame,
            columns=cols,
            on_select_row=self._on_select_socket,
            mono_columns=["local_ip", "remote_ip", "port", "protocol"]
        )
        self.table.grid(row=1, column=0, sticky="nsew")
        
        # --- RIGHT SIDE: DETAILED SOCKET PANEL ---
        self.detail_frame = ctk.CTkFrame(
            self.content_frame, 
            fg_color=("#FFFFFF", "#121C2C"), 
            border_color=("#D0D5DD", "#1E2D4A"), 
            border_width=1.5, 
            corner_radius=10
        )
        self.detail_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self.detail_frame.grid_columnconfigure(0, weight=1)
        self.detail_frame.grid_rowconfigure(2, weight=1)  # Threat warning frame expands
        
        self.detail_title = ctk.CTkLabel(
            self.detail_frame,
            text="SOCKET METADATA CARD",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("#008B9B", "#00E5FF"),
            anchor="w"
        )
        self.detail_title.grid(row=0, column=0, sticky="w", padx=16, pady=(16, 8))
        
        # Details grid fields
        self.info_box = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
        self.info_box.grid(row=1, column=0, sticky="ew", padx=16, pady=4)
        self.info_box.grid_columnconfigure(1, weight=1)
        
        self.fields = {}
        info_rows = [
            ("process", "Owner Process"),
            ("local_ip", "Local IP Endpoint"),
            ("remote_ip", "Remote IP Endpoint"),
            ("port", "Socket Port"),
            ("protocol", "Network Protocol"),
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
                font=ctk.CTkFont(family="Consolas" if field_key in ["local_ip", "remote_ip", "port"] else "Segoe UI", size=11),
                text_color=("#0F172A", "#FFFFFF"),
                anchor="w",
                wraplength=200,
                justify="left"
            )
            lbl_val.grid(row=idx, column=1, sticky="w", pady=4)
            self.fields[field_key] = lbl_val

        # Warning notification area inside side drawer
        self.warning_box = ctk.CTkFrame(self.detail_frame, fg_color=("#EAECF0", "#182436"), corner_radius=6)
        self.warning_box.grid(row=2, column=0, sticky="nsew", padx=16, pady=(12, 16))
        self.warning_box.grid_columnconfigure(0, weight=1)
        self.warning_box.grid_rowconfigure(1, weight=1)
        
        self.warning_hdr = ctk.CTkLabel(
            self.warning_box,
            text="THREAT INTEL REPUTATION",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=("#5E6E82", "#8F9CAE"),
            anchor="w"
        )
        self.warning_hdr.grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))
        
        self.warning_txt = ctk.CTkTextbox(
            self.warning_box,
            fg_color="transparent",
            text_color=("#334155", "#A0AEC0"),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            corner_radius=0,
            border_width=0
        )
        self.warning_txt.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 10))
        self.warning_txt.insert("1.0", "Select an active connection socket row to inspect endpoint data and cross-reference remote IPs against threat intelligence command feeds.")
        self.warning_txt.configure(state="disabled")
        
        self.refresh()

    def refresh(self):
        """Loads connections from data provider service and updates custom table views."""
        self.raw_connections = self.data_service.get_network_connections()
        self._filter_and_render()
        self._clear_detail_panel()

    def _set_active_filter(self, filter_key: str):
        """Sets the active button tab state and filters."""
        self.active_filter = filter_key
        
        # Reset button colors
        for key, btn in self.filter_buttons.items():
            if key == filter_key:
                btn.configure(
                    fg_color="#1E2D4A",
                    text_color="#00E5FF",
                    font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold")
                )
            else:
                btn.configure(
                    fg_color="transparent",
                    text_color="#8F9CAE",
                    font=ctk.CTkFont(family="Segoe UI", size=11, weight="normal")
                )
        self._filter_and_render()

    def _filter_and_render(self):
        """Applies search filters and quick filters to network connections."""
        query = self.search_input.get().strip().lower()
        
        filtered = self.raw_connections
        
        # Apply Quick Filters
        if self.active_filter == "ESTABLISHED":
            filtered = [n for n in filtered if n.get("state") == "ESTABLISHED"]
        elif self.active_filter == "LISTENING":
            filtered = [n for n in filtered if n.get("state") == "LISTENING"]
        elif self.active_filter == "SUSPICIOUS":
            filtered = [n for n in filtered if n.get("suspicious", False)]
            
        # Apply Search Input Filters
        if query:
            filtered = [
                n for n in filtered
                if query in str(n.get("process", "")).lower()
                or query in str(n.get("local_ip", "")).lower()
                or query in str(n.get("remote_ip", "")).lower()
                or query in str(n.get("port", "")).lower()
                or query in str(n.get("protocol", "")).lower()
                or query in str(n.get("risk", "")).lower()
            ]
            
        self.table.set_data(filtered)

    def _on_select_socket(self, socket_data: Dict[str, Any]):
        """Populates detail monitor panel when a row is clicked."""
        for field_key, lbl in self.fields.items():
            val = socket_data.get(field_key, "-")
            lbl.configure(text=str(val))
            
        # Check risk severity level
        risk = str(socket_data.get("risk", "Low")).upper()
        self.warning_txt.configure(state="normal")
        self.warning_txt.delete("1.0", "end")
        
        if risk in ["CRITICAL", "HIGH"]:
            self.warning_box.configure(fg_color=("#FDE8E8", "#2C1212"), border_color="#FF3B30", border_width=1)
            self.warning_hdr.configure(text="🚨 CRITICAL SECURITY THREAT FLAG", text_color=("#DE350B", "#FF3B30"))
            
            msg = f"CRITICAL: Process '{socket_data.get('process')}' established outbound network connection:\n"
            msg += f"-> {socket_data.get('local_ip')} connects to {socket_data.get('remote_ip')}:{socket_data.get('port')}\n\n"
            msg += "TI Feed Flags: Known Command and Control (C2) beacon or Trojan gateway port.\n\n"
            msg += "Guidance: Inspect the memory regions and loaded DLL modules of this process immediately."
            self.warning_txt.insert("1.0", msg)
        elif risk in ["MEDIUM", "WARNING"]:
            self.warning_box.configure(fg_color=("#FFF8E1", "#251F0D"), border_color="#FFB300", border_width=1)
            self.warning_hdr.configure(text="⚠ SUSPICIOUS SOCKET ACCESS", text_color=("#B7791F", "#FFB300"))
            self.warning_txt.insert("1.0", f"Warning: Process '{socket_data.get('process')}' is listening on or connecting through port {socket_data.get('port')}.\n\nInspect parent process maps for potential service hijacking.")
        else:
            self.warning_box.configure(fg_color=("#E6F9F0", "#0D251C"), border_color="#00FF88", border_width=1)
            self.warning_hdr.configure(text="✔ CLEAN ENDPOINT IP PROFILE", text_color=("#1E7E34", "#00FF88"))
            self.warning_txt.insert("1.0", "Local socket connection verified as secure. Resolved remote endpoint points to a recognized standard system service provider. No threat rules triggered.")
            
        self.warning_txt.configure(state="disabled")

    def _clear_detail_panel(self):
        """Resets the detail text labels."""
        for lbl in self.fields.values():
            lbl.configure(text="-")
        self.warning_box.configure(fg_color=("#EAECF0", "#182436"), border_width=0)
        self.warning_hdr.configure(text="THREAT INTEL REPUTATION", text_color=("#5E6E82", "#8F9CAE"))
        self.warning_txt.configure(state="normal")
        self.warning_txt.delete("1.0", "end")
        self.warning_txt.insert("1.0", "Select an active connection socket row to inspect endpoint data and cross-reference remote IPs against threat intelligence command feeds.")
        self.warning_txt.configure(state="disabled")
