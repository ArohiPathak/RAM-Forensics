import customtkinter as ctk
import re
from typing import List, Dict, Any, Callable, Tuple

class CustomTable(ctk.CTkFrame):
    """
    CustomTable is a reusable grid-based spreadsheet component built on CTkScrollableFrame.
    Features:
    - Custom column scaling/weights.
    - Column-based sorting.
    - Risk-based row color coding (Light & Dark theme safe):
      - Critical/High: Deep Red background, Red outline.
      - Medium: Deep Yellow/Orange background, Yellow outline.
      - Low/Secure: Standard alternating slate/gray background.
    - Selected row highlight triggers details callbacks.
    - Smart text truncation for long paths to prevent column stretching.
    """
    def __init__(
        self,
        master,
        columns: List[Tuple[str, str, int]],  # [(data_key, Header Label, Grid Column Weight)]
        on_select_row: Callable[[Dict[str, Any]], None] = None,
        font_family: str = "Segoe UI",
        mono_columns: List[str] = None,  # Columns that should use monospace (e.g., PID, Address, IP)
        **kwargs
    ):
        super().__init__(master, fg_color="transparent", **kwargs)
        
        self.columns = columns
        self.on_select_row = on_select_row
        self.font_family = font_family
        self.mono_columns = mono_columns or []
        
        self.data: List[Dict[str, Any]] = []
        self.sort_column: str = None
        self.sort_ascending: bool = True
        self.row_widgets: List[Tuple[ctk.CTkFrame, List[ctk.CTkLabel]]] = []
        self.selected_row_idx: int = -1
        self.selected_data: Dict[str, Any] = None
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # 1. Header Frame
        hdr_bg = ("#EAECF0", "#121C2C")
        hdr_border = ("#D0D5DD", "#1E2D4A")
        self.header_frame = ctk.CTkFrame(self, fg_color=hdr_bg, height=32, corner_radius=4, border_width=1, border_color=hdr_border)
        self.header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self._configure_columns(self.header_frame)
        
        # Draw Header Labels
        self.header_labels = {}
        for idx, (key, label, weight) in enumerate(self.columns):
            lbl = ctk.CTkLabel(
                self.header_frame,
                text=label,
                font=ctk.CTkFont(family=self.font_family, size=11, weight="bold"),
                text_color=("#475569", "#8F9CAE"),
                cursor="hand2"
            )
            lbl.grid(row=0, column=idx, sticky="w", padx=12, pady=6)
            
            # Click header to sort
            lbl.bind("<Button-1>", lambda e, k=key: self.sort_by(k))
            self.header_labels[key] = lbl
            
        # 2. Scrollable Body Frame
        self.body_frame = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            corner_radius=0
        )
        self.body_frame._scrollbar.configure(
            fg_color="transparent",
            button_color=("#C1C9D2", "#1E2D4A"),
            button_hover_color=("#00B4CC", "#00E5FF")
        )
        self.body_frame.grid(row=1, column=0, sticky="nsew")
        self.body_frame.grid_columnconfigure(0, weight=1)

    def _configure_columns(self, frame: ctk.CTkFrame):
        """Applies width weights to the columns in a frame."""
        for idx, (_, _, weight) in enumerate(self.columns):
            frame.grid_columnconfigure(idx, weight=weight)

    def set_data(self, data: List[Dict[str, Any]]):
        """Sets and populates data rows into the table."""
        self.data = data.copy()
        if self.sort_column:
            self._sort_data()
        self.render_rows()

    def sort_by(self, key: str):
        """Triggers sorting by a column key."""
        if self.sort_column == key:
            self.sort_ascending = not self.sort_ascending
        else:
            self.sort_column = key
            self.sort_ascending = True
            
        # Update header arrows
        for col_key, lbl in self.header_labels.items():
            col_name = next(col[1] for col in self.columns if col[0] == col_key)
            if col_key == key:
                arrow = " ▲" if self.sort_ascending else " ▼"
                lbl.configure(text=f"{col_name}{arrow}", text_color=("#00B4CC", "#00E5FF"))
            else:
                lbl.configure(text=col_name, text_color=("#475569", "#8F9CAE"))
                
        self._sort_data()
        self.render_rows()

    def _sort_data(self):
        """Internal sorting method."""
        if not self.sort_column or not self.data:
            return
            
        def get_sort_val(item):
            val = item.get(self.sort_column, "")
            if isinstance(val, (int, float)):
                return val
            return str(val).lower()

        self.data.sort(key=get_sort_val, reverse=not self.sort_ascending)

    def render_rows(self):
        """Clears and re-renders data rows."""
        # Clean up existing widgets
        for row_frm, _ in self.row_widgets:
            try:
                row_frm.destroy()
            except Exception:
                pass
        self.row_widgets.clear()
        
        self.selected_row_idx = -1
        self.selected_data = None

        if not self.data:
            empty_lbl = ctk.CTkLabel(
                self.body_frame,
                text="No records found matching filters.",
                font=ctk.CTkFont(family=self.font_family, size=12, slant="italic"),
                text_color=("#64748B", "#627284")
            )
            empty_lbl.grid(row=0, column=0, pady=20, sticky="ew")
            self.row_widgets.append((empty_lbl, []))
            return

        for r_idx, row_data in enumerate(self.data):
            risk_level = str(row_data.get("risk", "Low")).lower()
            is_suspicious = row_data.get("suspicious", False) or risk_level in ["critical", "high"]
            
            # Color code row background and borders based on threat severity (tuples for Light/Dark mode)
            if risk_level in ["critical", "high"]:
                bg_color = ("#FDE8E8", "#260C0C")      # Light Red / Cyber Red Tint
                border_color = "#FF3B30"               # Bright Red outline
                border_w = 1
                text_color = ("#DE350B", "#FF3B30")
            elif risk_level in ["medium", "warning"]:
                bg_color = ("#FFF8E1", "#22190A")      # Light Gold / Warning Gold Tint
                border_color = "#FFB300"               # Gold outline
                border_w = 1
                text_color = ("#B7791F", "#FFB300")
            else:
                # Standard alternating background
                bg_color = ("#F8FAFC", "#0B0F19") if r_idx % 2 == 0 else ("#F1F5F9", "#0F1624")
                border_color = ("#E2E8F0", "#1E2D4A")
                border_w = 0
                text_color = ("#334155", "#E2E8F0")
                
            row_frame = ctk.CTkFrame(
                self.body_frame,
                fg_color=bg_color,
                corner_radius=4,
                border_color=border_color,
                border_width=border_w,
                height=36
            )
            row_frame.grid(row=r_idx, column=0, sticky="ew", pady=2)
            self._configure_columns(row_frame)
            
            labels = []
            for col_idx, (key, _, _) in enumerate(self.columns):
                val = row_data.get(key, "")
                
                font_w = "normal"
                font_fam = "Consolas" if key in self.mono_columns else self.font_family
                font_sz = 11 if key in self.mono_columns else 12
                
                # Check for dynamic status/risk badge renders
                if key == "risk":
                    badge_val = str(val).upper()
                    if badge_val in ["CRITICAL", "HIGH"]:
                        bg_badge = ("#FDE8E8", "#2C1212")
                        bd_color = "#FF3B30"
                        fg_badge = ("#DE350B", "#FF3B30")
                    elif badge_val in ["MEDIUM", "WARNING"]:
                        bg_badge = ("#FFF8E1", "#251F0D")
                        bd_color = "#FFB300"
                        fg_badge = ("#B7791F", "#FFB300")
                    else:
                        bg_badge = ("#E6F9F0", "#0D251C")
                        bd_color = "#00FF88"
                        fg_badge = ("#1E7E34", "#00FF88")
                        
                    cell_widget = ctk.CTkFrame(row_frame, fg_color=bg_badge, corner_radius=12, border_width=1, border_color=bd_color)
                    cell_widget.grid(row=0, column=col_idx, sticky="w", padx=12, pady=6)
                    
                    lbl = ctk.CTkLabel(
                        cell_widget,
                        text=f" {badge_val} ",
                        font=ctk.CTkFont(family=self.font_family, size=9, weight="bold"),
                        text_color=fg_badge
                    )
                    lbl.pack(padx=6, pady=1.5)
                elif key == "status":
                    status_str = str(val).upper()
                    if "SUSPICIOUS" in status_str or "ANOMALY" in status_str:
                        bg_b = ("#FDE8E8", "#2C1212")
                        bd_b = "#FF3B30"
                        fg_b = ("#DE350B", "#FF3B30")
                    else:
                        bg_b = ("#E6F9F0", "#0D251C")
                        bd_b = "#00FF88"
                        fg_b = ("#1E7E34", "#00FF88")
                        
                    cell_widget = ctk.CTkFrame(row_frame, fg_color=bg_b, corner_radius=12, border_width=1, border_color=bd_b)
                    cell_widget.grid(row=0, column=col_idx, sticky="w", padx=12, pady=6)
                    
                    lbl = ctk.CTkLabel(
                        cell_widget,
                        text=f" {status_str} ",
                        font=ctk.CTkFont(family=self.font_family, size=9, weight="bold"),
                        text_color=fg_b
                    )
                    lbl.pack(padx=6, pady=1.5)
                else:
                    curr_color = text_color
                    # If this row is suspicious, make the name/DLL column bold
                    if is_suspicious and key in ["name", "process", "dll_name", "dll"]:
                        curr_color = ("#FF3B30", "#FF3B30") if risk_level in ["critical", "high"] else ("#FFB300", "#FFB300")
                        font_w = "bold"
                    
                    # Smart path truncation for better layout alignment
                    cell_text = str(val)
                    if key == "path" and len(cell_text) > 35:
                        cell_text = "..." + cell_text[-32:]
                    elif key not in ["path", "commandline"] and len(cell_text) > 40:
                        cell_text = cell_text[:37] + "..."
                        
                    lbl = ctk.CTkLabel(
                        row_frame,
                        text=cell_text,
                        font=ctk.CTkFont(family=font_fam, size=font_sz, weight=font_w),
                        text_color=curr_color,
                        anchor="w"
                    )
                    lbl.grid(row=0, column=col_idx, sticky="w", padx=12, pady=6)
                    labels.append(lbl)
                    
            # Bind selection click events
            row_frame.bind("<Button-1>", lambda e, idx=r_idx, data=row_data: self._select_row(idx, data))
            for lbl in labels:
                lbl.bind("<Button-1>", lambda e, idx=r_idx, data=row_data: self._select_row(idx, data))
                
            self.row_widgets.append((row_frame, labels))

    def _select_row(self, row_idx: int, row_data: Dict[str, Any]):
        """Highlights the selected row and triggers selection callback."""
        if self.selected_row_idx == row_idx:
            return

        # Restore color of previous selected row
        if self.selected_row_idx != -1 and self.selected_row_idx < len(self.row_widgets):
            old_frame, _ = self.row_widgets[self.selected_row_idx]
            if old_frame.winfo_exists():
                old_risk = str(self.data[self.selected_row_idx].get("risk", "Low")).lower()
                
                if old_risk in ["critical", "high"]:
                    old_border = "#FF3B30"
                    old_bg = ("#FDE8E8", "#260C0C")
                    old_border_w = 1
                elif old_risk in ["medium", "warning"]:
                    old_border = "#FFB300"
                    old_bg = ("#FFF8E1", "#22190A")
                    old_border_w = 1
                else:
                    old_border = ("#E2E8F0", "#1E2D4A")
                    old_bg = ("#F8FAFC", "#0B0F19") if self.selected_row_idx % 2 == 0 else ("#F1F5F9", "#0F1624")
                    old_border_w = 0
                    
                old_frame.configure(fg_color=old_bg, border_color=old_border, border_width=old_border_w)

        # Highlight new selected row
        self.selected_row_idx = row_idx
        self.selected_data = row_data
        
        new_frame, _ = self.row_widgets[row_idx]
        new_frame.configure(
            fg_color=("#E2E8F0", "#1E2D4A"), 
            border_color=("#00B4CC", "#00E5FF"), 
            border_width=1
        )
        
        if self.on_select_row:
            self.on_select_row(row_data)
