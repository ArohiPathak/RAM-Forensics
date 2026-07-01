import customtkinter as ctk
from services.data_service import DataService

class BasePage(ctk.CTkFrame):
    """
    BasePage is the parent class for all primary dashboard subpages.
    It guarantees consistent padding, titles, margins, and the refresh framework.
    """
    def __init__(self, master, data_service: DataService, title: str, description: str = "", **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        
        self.data_service = data_service
        self.title = title
        self.description = description
        
        # Grid settings: Column 0 stretches, Row 1 stretches (content)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # --- HEADER REGION ---
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        self.header_frame.grid_columnconfigure(0, weight=1)
        
        # Left side: Title and subtitle
        self.title_text_frame = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        self.title_text_frame.grid(row=0, column=0, sticky="w")
        
        self.title_lbl = ctk.CTkLabel(
            self.title_text_frame,
            text=self.title.upper(),
            font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"),
            text_color=("#0F172A", "#FFFFFF")
        )
        self.title_lbl.grid(row=0, column=0, sticky="w")
        
        if self.description:
            self.desc_lbl = ctk.CTkLabel(
                self.title_text_frame,
                text=self.description,
                font=ctk.CTkFont(family="Segoe UI", size=12),
                text_color=("#475569", "#8F9CAE")
            )
            self.desc_lbl.grid(row=1, column=0, sticky="w", pady=(2, 0))
            
        # Right side: Header actions (e.g. Refresh button)
        self.action_frame = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        self.action_frame.grid(row=0, column=1, sticky="e")
        
        self.refresh_btn = ctk.CTkButton(
            self.action_frame,
            text="🔄 Refresh",
            width=80,
            height=30,
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color=("#EAECF0", "#162235"),
            hover_color=("#D0D5DD", "#1E2D4A"),
            border_color=("#D0D5DD", "#1E2D4A"),
            border_width=1,
            text_color=("#00B4CC", "#00E5FF"),
            command=self.refresh
        )
        self.refresh_btn.grid(row=0, column=0, padx=(10, 0))
        
        # --- CONTENT REGION ---
        self.content_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.content_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)

    def refresh(self):
        """Should be overridden by child pages to pull fresh data from service."""
        pass
