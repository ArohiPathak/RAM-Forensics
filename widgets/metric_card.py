import customtkinter as ctk

class MetricCard(ctk.CTkFrame):
    """
    MetricCard is a premium reusable dashboard card component that displays high-level metrics.
    Features:
    - Custom color themes supporting responsive light/dark appearance modes.
    - Smooth hover micro-animations (dynamically updates borders and background).
    - Grid-aligned responsive design with auto-scaling text and wrapping.
    """
    def __init__(
        self,
        master,
        title: str,
        value: str,
        subtitle: str = "",
        theme: str = "info",  # 'info', 'success', 'warning', 'danger'
        **kwargs
    ):
        # Color mapping for both Light and Dark appearance modes
        self.themes = {
            "info": {
                "border": ("#D0D8E2", "#1E2D4A"), "hover_border": ("#00B4CC", "#00E5FF"), 
                "accent": ("#008B9B", "#00E5FF"), "bg": ("#FFFFFF", "#121C2C"), "hover_bg": ("#F0F4F8", "#162337")
            },
            "success": {
                "border": ("#C3E6CB", "#123F2A"), "hover_border": ("#00C868", "#00FF88"), 
                "accent": ("#155724", "#00FF88"), "bg": ("#E8F5E9", "#0D251C"), "hover_bg": ("#C8E6C9", "#123326")
            },
            "warning": {
                "border": ("#FFEBAA", "#3F3212"), "hover_border": ("#E5A000", "#FFB300"), 
                "accent": ("#856404", "#FFB300"), "bg": ("#FFFDE7", "#251F0D"), "hover_bg": ("#FFF9C4", "#332A12")
            },
            "danger": {
                "border": ("#F5C6CB", "#471D1D"), "hover_border": ("#D32F2F", "#FF3B30"), 
                "accent": ("#721C24", "#FF3B30"), "bg": ("#FFEBEE", "#2C1212"), "hover_bg": ("#FFCDD2", "#3D1A1A")
            }
        }
        
        self.current_theme = self.themes.get(theme, self.themes["info"])
        
        super().__init__(
            master, 
            fg_color=self.current_theme["bg"],
            border_color=self.current_theme["border"],
            border_width=1.5,
            corner_radius=10,
            **kwargs
        )
        
        # Configure layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Main container to hold text
        self.content_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.content_frame.grid(row=0, column=0, padx=14, pady=14, sticky="ew")
        self.content_frame.grid_columnconfigure(0, weight=1)
        
        # Title Label
        self.title_label = ctk.CTkLabel(
            self.content_frame, 
            text=title.upper(),
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=("#5E6E82", "#8F9CAE"),
            anchor="w"
        )
        self.title_label.grid(row=0, column=0, sticky="w", pady=(0, 4))
        
        # Value Label (Auto-scales font size for long text to prevent clipping)
        val_sz = 11 if len(value) > 22 else 14 if len(value) > 16 else 18 if len(value) > 12 else 24
        self.value_label = ctk.CTkLabel(
            self.content_frame, 
            text=value,
            font=ctk.CTkFont(family="Segoe UI", size=val_sz, weight="bold"),
            text_color=self.current_theme["accent"],
            anchor="w",
            wraplength=120
        )
        self.value_label.grid(row=1, column=0, sticky="w")
        
        # Subtitle Label
        if subtitle:
            self.subtitle_label = ctk.CTkLabel(
                self.content_frame, 
                text=subtitle,
                font=ctk.CTkFont(family="Segoe UI", size=10, weight="normal"),
                text_color=("#475569", "#627284"),
                anchor="w",
                wraplength=120
            )
            self.subtitle_label.grid(row=2, column=0, sticky="w", pady=(4, 0))
            
        # Bind hover events for micro-animations
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        
        # Recursively bind children so the hover covers the entire card area
        for widget in [self.content_frame, self.title_label, self.value_label]:
            widget.bind("<Enter>", self._on_enter)
            widget.bind("<Leave>", self._on_leave)
        if subtitle:
            self.subtitle_label.bind("<Enter>", self._on_enter)
            self.subtitle_label.bind("<Leave>", self._on_leave)

    def _on_enter(self, event=None):
        self.configure(
            fg_color=self.current_theme["hover_bg"],
            border_color=self.current_theme["hover_border"]
        )

    def _on_leave(self, event=None):
        self.configure(
            fg_color=self.current_theme["bg"],
            border_color=self.current_theme["border"]
        )

    def update_value(self, new_value: str, new_subtitle: str = None):
        """Update values dynamically with auto-scaling."""
        val_sz = 16 if len(new_value) > 16 else 20 if len(new_value) > 12 else 26
        self.value_label.configure(text=new_value, font=ctk.CTkFont(family="Segoe UI", size=val_sz, weight="bold"))
        if new_subtitle and hasattr(self, 'subtitle_label'):
            self.subtitle_label.configure(text=new_subtitle)
