import customtkinter as ctk
from pages.base_page import BasePage
from services.data_provider import DataProvider
from typing import Dict, Any

class TimelinePage(BasePage):
    """
    TimelinePage renders a professional graphical vertical timeline.
    Shows the boot-to-infection chain:
    System Boot -> Explorer Started -> Chrome Started -> PowerShell Started -> External Connection -> Suspicious DLL.
    Features:
    - Glowing color-coded nodes mapping severity levels.
    - Vertical arrow connecting links.
    - Contextual forensic info cards detailing PIDs and descriptions.
    """
    def __init__(self, master, data_service: DataProvider, **kwargs):
        super().__init__(
            master, 
            data_service, 
            title="Forensics Timeline", 
            description="Chronological event analysis of the memory dump file.", 
            **kwargs
        )
        
        # Hide standard refresh button to focus on timeline view
        self.refresh_btn.grid_remove()
        
        # Configure layout (Scrollable container in content frame)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        self.timeline_scroll = ctk.CTkScrollableFrame(
            self.content_frame,
            fg_color="transparent"
        )
        self.timeline_scroll._scrollbar.configure(
            fg_color="transparent",
            button_color=("#C1C9D2", "#1E2D4A"),
            button_hover_color=("#00B4CC", "#00E5FF")
        )
        self.timeline_scroll.grid(row=0, column=0, sticky="nsew")
        self.timeline_scroll.grid_columnconfigure(0, weight=1)
        
        self.refresh()

    def refresh(self):
        """Loads events from the data provider and draws the vertical node chain."""
        # Clear existing timeline widgets
        for widget in self.timeline_scroll.winfo_children():
            widget.destroy()
            
        events = self.data_service.get_timeline()
        
        # Main inner container grid
        # Col 0: Timestamp (Consolas, right-aligned)
        # Col 1: Node Icon & Vertical Connector line (centered)
        # Col 2: Event Details Card (expandable frame, left-aligned)
        self.timeline_grid = ctk.CTkFrame(self.timeline_scroll, fg_color="transparent")
        self.timeline_grid.pack(padx=20, pady=20, fill="x")
        self.timeline_grid.grid_columnconfigure(2, weight=1)
        
        if not events:
            no_lbl = ctk.CTkLabel(
                self.timeline_grid,
                text="✔ No chronological timeline events found in current memory target.",
                font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
                text_color="#00FF88"
            )
            no_lbl.grid(row=0, column=0, columnspan=3, pady=40)
            return

        grid_row = 0
        for idx, event in enumerate(events):
            time_str = event.get("time", "").split(" ")[1] # Extract just time
            category = event.get("category", "Event")
            pid = event.get("pid", 0)
            process = event.get("process", "System")
            details = event.get("details", "")
            severity = event.get("severity", "info")
            
            # 1. Map color theme based on event severity
            if severity == "danger":
                node_color = "#FF3B30"
                card_bg = ("#FDE8E8", "#2C1212")
                card_border = "#FF3B30"
                title_color = ("#DE350B", "#FF3B30")
                txt_color = ("#9B2C2C", "#FF8882")
            elif severity == "warning":
                node_color = "#FFB300"
                card_bg = ("#FFF8E1", "#251F0D")
                card_border = "#FFB300"
                title_color = ("#B7791F", "#FFB300")
                txt_color = ("#744210", "#FFD580")
            else:
                node_color = "#00FF88" if ctk.get_appearance_mode() == "Dark" else "#1E7E34"
                card_bg = ("#FFFFFF", "#121C2C")
                card_border = ("#D0D5DD", "#1E2D4A")
                title_color = ("#008B9B", "#00E5FF")
                txt_color = ("#334155", "#E2E8F0")
                
            # --- NODE ROW ---
            # Column 0: Time Label
            time_lbl = ctk.CTkLabel(
                self.timeline_grid,
                text=time_str,
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                text_color=("#5E6E82", "#8F9CAE")
            )
            time_lbl.grid(row=grid_row, column=0, padx=(0, 20), sticky="e")
            
            # Column 1: Node Symbol (●)
            node_lbl = ctk.CTkLabel(
                self.timeline_grid,
                text="●",
                font=ctk.CTkFont(size=18, weight="bold"),
                text_color=node_color
            )
            node_lbl.grid(row=grid_row, column=1, padx=10)
            
            # Column 2: Event Details Card
            card = ctk.CTkFrame(
                self.timeline_grid,
                fg_color=card_bg,
                border_color=card_border,
                border_width=1,
                corner_radius=8
            )
            card.grid(row=grid_row, column=2, sticky="ew", pady=6)
            card.grid_columnconfigure(0, weight=1)
            
            # Card Title (Category + Process pid)
            lbl_title = ctk.CTkLabel(
                card,
                text=f"{category.upper()}  »  {process} (PID: {pid})",
                font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
                text_color=title_color,
                anchor="w"
            )
            lbl_title.grid(row=0, column=0, sticky="w", padx=14, pady=(10, 4))
            
            # Card Details
            lbl_desc = ctk.CTkLabel(
                card,
                text=details,
                font=ctk.CTkFont(family="Segoe UI", size=11),
                text_color=txt_color,
                wraplength=480,
                justify="left",
                anchor="w"
            )
            lbl_desc.grid(row=1, column=0, sticky="w", padx=14, pady=(0, 10))
            
            grid_row += 1
            
            # --- CONNECTOR ROW (Only if not last element) ---
            if idx < len(events) - 1:
                # Column 1: Vertical line glyph connector (│ or ▼)
                connector_lbl = ctk.CTkLabel(
                    self.timeline_grid,
                    text="│\n▼",
                    font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                    text_color=("#D0D5DD", "#1E2D4A"),
                    height=24
                )
                connector_lbl.grid(row=grid_row, column=1, pady=2)
                
                # Column 2: Empty placeholder frame to align grid rows
                empty_placeholder = ctk.CTkFrame(self.timeline_grid, height=24, fg_color="transparent")
                empty_placeholder.grid(row=grid_row, column=2)
                
                grid_row += 1
