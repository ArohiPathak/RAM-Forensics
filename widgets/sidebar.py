import customtkinter as ctk
from typing import Dict, Callable

class Sidebar(ctk.CTkFrame):
    """
    Sidebar provides collapsible sidebar navigation for the RAM Forensics Dashboard.
    Features:
    - Supports two states: Expanded (240px) and Collapsed (70px).
    - Toggles smoothly using the top menu button (☰).
    - Displays emojis only when collapsed, and emojis + label text when expanded.
    - Retains full visibility and navigation functionality in both states.
    """
    def __init__(
        self,
        master,
        on_navigate: Callable[[str], None],
        initial_tab: str = "dashboard",
        **kwargs
    ):
        self.expanded_width = 240
        self.collapsed_width = 70
        self.is_collapsed = False
        self.on_navigate = on_navigate
        self.active_tab = initial_tab
        self.buttons: Dict[str, ctk.CTkButton] = {}
        
        super().__init__(
            master, 
            width=self.expanded_width,
            fg_color=("#F0F4F8", "#090E17"), 
            border_color=("#D0D8E2", "#182436"), 
            border_width=1.5, 
            corner_radius=0,
            **kwargs
        )
        
        # Enforce exact width constraints by stopping auto-propagation
        self.grid_propagate(False)
        self.pack_propagate(False)
        
        # Configure layout rows:
        # Row 0: Header (Logo + Toggle Button)
        # Row 1: Nav buttons container (Scrollable to prevent overflow on small screens)
        # Row 2: Spacer
        # Row 3: Status indicator
        # Row 4: Theme control
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # Keep track of nav configurations: key -> (emoji, label_text)
        self.nav_config = {
            "dashboard": ("🏠", "Dashboard"),
            "upload": ("📂", "Upload Memory"),
            "processes": ("🖥", "Processes"),
            "network": ("🌐", "Network"),
            "dll": ("📦", "DLL Analysis"),
            "timeline": ("📜", "Timeline"),
            "report": ("📄", "Report"),
            "settings": ("⚙", "Settings")
        }
        
        # --- HEADER REGION ---
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent", height=50)
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(15, 10))
        self.header_frame.grid_columnconfigure(1, weight=1) # Middle spacer
        
        self.logo_icon = ctk.CTkLabel(
            self.header_frame,
            text="⚡",
            font=ctk.CTkFont(family="Segoe UI", size=20),
            text_color=("#00B4CC", "#00E5FF")
        )
        self.logo_icon.grid(row=0, column=0, padx=(5, 5))
        
        self.logo_text = ctk.CTkLabel(
            self.header_frame,
            text="RAM FORENSICS",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=("#0F172A", "#FFFFFF")
        )
        self.logo_text.grid(row=0, column=1, sticky="w", padx=2)
        
        self.toggle_btn = ctk.CTkButton(
            self.header_frame,
            text="☰",
            width=32,
            height=32,
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            fg_color="transparent",
            hover_color=("#EAECF0", "#121B2A"),
            text_color=("#00B4CC", "#00E5FF"),
            command=self.toggle_collapse
        )
        self.toggle_btn.grid(row=0, column=2, padx=5)
        
        self.divider = ctk.CTkFrame(self, height=1.5, fg_color=("#D0D8E2", "#182436"))
        self.divider.grid(row=0, column=0, sticky="s", padx=12)
        
        # --- NAVIGATION CONTAINER ---
        self.nav_scroll = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            height=320
        )
        self.nav_scroll.grid(row=1, column=0, sticky="nsew", padx=6, pady=10)
        self.nav_scroll.grid_columnconfigure(0, weight=1)
        
        # Generate navigation buttons
        for idx, (tab_key, (emoji, text)) in enumerate(self.nav_config.items()):
            btn = ctk.CTkButton(
                self.nav_scroll,
                text=f"{emoji}   {text}",
                font=ctk.CTkFont(family="Segoe UI", size=12),
                anchor="w",
                height=36,
                corner_radius=6,
                command=lambda k=tab_key: self.select_tab(k)
            )
            btn.grid(row=idx, column=0, pady=3, sticky="ew")
            self.buttons[tab_key] = btn
            
        self._update_button_states()
        
        # --- STATUS INDICATOR BOX ---
        self.status_box = ctk.CTkFrame(
            self,
            fg_color=("#FFFFFF", "#121C2C"),
            border_color=("#D0D8E2", "#1E2D4A"),
            border_width=1,
            corner_radius=8
        )
        self.status_box.grid(row=3, column=0, padx=12, pady=10, sticky="ew")
        self.status_box.grid_columnconfigure(0, weight=1)
        
        self.status_dot = ctk.CTkLabel(
            self.status_box,
            text="●",
            font=ctk.CTkFont(size=14),
            text_color="#00FF88"
        )
        self.status_dot.grid(row=0, column=0, sticky="w", padx=(10, 2), pady=8)
        
        self.status_text = ctk.CTkLabel(
            self.status_box,
            text="System: Ready",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#E2E8F0",
            anchor="w"
        )
        self.status_text.grid(row=0, column=1, sticky="w", padx=2, pady=8)
        
        # --- THEME SWITCH ---
        self.theme_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.theme_frame.grid(row=4, column=0, padx=12, pady=(10, 15), sticky="ew")
        self.theme_frame.grid_columnconfigure(0, weight=1)
        
        self.theme_menu = ctk.CTkOptionMenu(
            self.theme_frame,
            values=["Dark Mode", "Light Mode", "System"],
            font=ctk.CTkFont(family="Segoe UI", size=11),
            dropdown_font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="#162235",
            button_color="#1E2D4A",
            button_hover_color="#00E5FF",
            dropdown_fg_color="#121C2C",
            dropdown_hover_color="#1E2D4A",
            command=self._change_theme
        )
        self.theme_menu.grid(row=0, column=0, sticky="ew")
        self.theme_menu.set("Dark Mode")

    def toggle_collapse(self):
        """Collapses or expands the sidebar layout dimensions and labels."""
        self.is_collapsed = not self.is_collapsed
        
        if self.is_collapsed:
            # COLLAPSE STATE
            self.configure(width=self.collapsed_width)
            self.logo_text.grid_remove()  # Hide app title label
            
            # Reposition toggle button to center
            self.logo_icon.grid_remove()
            self.toggle_btn.grid(row=0, column=0, columnspan=3, padx=10)
            
            # Hide button labels, leave only emojis centered
            for key, btn in self.buttons.items():
                emoji, _ = self.nav_config[key]
                btn.configure(text=emoji, anchor="center")
                
            # Collapse status panel
            self.status_text.grid_remove()
            self.status_dot.grid(row=0, column=0, columnspan=2, padx=12)
            
            # Hide theme menu dropdown
            self.theme_frame.grid_remove()
        else:
            # EXPAND STATE
            self.configure(width=self.expanded_width)
            self.logo_icon.grid(row=0, column=0, padx=(5, 5))
            self.logo_text.grid()
            
            # Restore toggle button position
            self.toggle_btn.grid(row=0, column=2, padx=5)
            
            # Restore button labels
            for key, btn in self.buttons.items():
                emoji, text = self.nav_config[key]
                btn.configure(text=f"{emoji}   {text}", anchor="w")
                
            # Restore status panel
            self.status_dot.grid(row=0, column=0, sticky="w", padx=(10, 2), pady=8)
            self.status_text.grid()
            
            # Restore theme menu
            self.theme_frame.grid()
            
        # Re-apply active highlights to update border constraints
        self._update_button_states()

    def select_tab(self, tab_key: str):
        """Sets active tab selection and invokes page-transition coordinator."""
        if self.active_tab == tab_key:
            return
        self.active_tab = tab_key
        self._update_button_states()
        self.on_navigate(tab_key)

    def _update_button_states(self):
        """Updates color codes for selected buttons depending on collapse mode."""
        for key, btn in self.buttons.items():
            if key == self.active_tab:
                btn.configure(
                    fg_color=("#D0D8E2", "#162337"),
                    hover_color=("#C0C8D2", "#1E2D4A"),
                    text_color=("#008B9B", "#00E5FF"),
                    border_color=("#008B9B", "#00E5FF"),
                    border_width=1,
                    font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold")
                )
            else:
                btn.configure(
                    fg_color="transparent",
                    hover_color=("#E2E8F0", "#121B2A"),
                    text_color=("#475569", "#8F9CAE"),
                    border_width=0,
                    font=ctk.CTkFont(family="Segoe UI", size=12, weight="normal")
                )

    def update_status(self, text: str, status_type: str = "ready"):
        """Updates the status dot and text fields dynamically."""
        self.status_text.configure(text=text)
        
        color_map = {
            "ready": ("#1E7E34", "#00FF88"),
            "busy": ("#B7791F", "#FFB300"),
            "error": ("#D32F2F", "#FF3B30"),
            "info": ("#008B9B", "#00E5FF")
        }
        self.status_dot.configure(text_color=color_map.get(status_type, ("#008B9B", "#00E5FF")))

    def _change_theme(self, selection: str):
        """Switches display appearance settings and refreshes active pages."""
        print(f"[+] Switching appearance theme to: {selection}")
        if selection == "Dark Mode":
            ctk.set_appearance_mode("Dark")
        elif selection == "Light Mode":
            ctk.set_appearance_mode("Light")
        else:
            ctk.set_appearance_mode("System")
            
        # Force Tkinter to process appearance update events immediately
        app = self.winfo_toplevel()
        try:
            app.update_idletasks()
        except Exception as e:
            print(f"[-] Error calling update_idletasks: {e}")
            
        # Trigger page refresh to redraw any Matplotlib charts or table widgets
        if hasattr(app, "pages") and hasattr(app, "sidebar"):
            active_page = app.pages.get(app.sidebar.active_tab)
            if active_page:
                self.after(50, active_page.refresh)
