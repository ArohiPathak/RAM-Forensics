import customtkinter as ctk
from pages.base_page import BasePage
from services.data_provider import DataProvider
from tkinter import messagebox

class SettingsPage(BasePage):
    """
    SettingsPage coordinates analysis configuration rules.
    Features:
    - Text inputs designating Volatility engine python pathways.
    - Droplist settings mapping threshold warnings.
    - Persistent updates linked to the DataProvider service.
    """
    def __init__(self, master, data_service: DataProvider, **kwargs):
        super().__init__(
            master, 
            data_service, 
            title="Settings Panel", 
            description="Adjust cybersecurity parameters, plugin paths, and threat triggers.", 
            **kwargs
        )
        
        # Configure layout (Single column centered card panel)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        # Centered options container
        self.card = ctk.CTkFrame(
            self.content_frame,
            fg_color=("#FFFFFF", "#121C2C"),
            border_color=("#D0D5DD", "#1E2D4A"),
            border_width=1.5,
            corner_radius=12,
            width=580,
            height=460
        )
        self.card.grid(row=0, column=0, padx=20, pady=20)
        self.card.grid_propagate(False)
        self.card.grid_columnconfigure(1, weight=1)
        
        # Header title
        self.card_lbl = ctk.CTkLabel(
            self.card,
            text="ENGINE PREFERENCES",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=("#008B9B", "#00E5FF"),
            anchor="w"
        )
        self.card_lbl.grid(row=0, column=0, columnspan=2, sticky="w", padx=24, pady=(24, 16))
        
        # Options list
        # 1. Volatility Path
        self.vol_lbl = ctk.CTkLabel(
            self.card,
            text="Volatility vol.py Script Path",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("#5E6E82", "#8F9CAE"),
            anchor="w"
        )
        self.vol_lbl.grid(row=1, column=0, sticky="w", padx=24, pady=10)
        
        self.vol_input = ctk.CTkEntry(
            self.card,
            fg_color=("#F8FAFC", "#0B0F19"),
            border_color=("#D0D5DD", "#1E2D4A"),
            text_color=("#0F172A", "#FFFFFF"),
            font=ctk.CTkFont(family="Consolas", size=11),
            height=30
        )
        self.vol_input.grid(row=1, column=1, sticky="ew", padx=(0, 24), pady=10)
        
        # 2. Yara rules path
        self.yara_lbl = ctk.CTkLabel(
            self.card,
            text="YARA Rules Signature Path",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("#5E6E82", "#8F9CAE"),
            anchor="w"
        )
        self.yara_lbl.grid(row=2, column=0, sticky="w", padx=24, pady=10)
        
        self.yara_input = ctk.CTkEntry(
            self.card,
            fg_color=("#F8FAFC", "#0B0F19"),
            border_color=("#D0D5DD", "#1E2D4A"),
            text_color=("#0F172A", "#FFFFFF"),
            font=ctk.CTkFont(family="Consolas", size=11),
            height=30
        )
        self.yara_input.grid(row=2, column=1, sticky="ew", padx=(0, 24), pady=10)
        
        # 3. Alert Level Threshold
        self.thr_lbl = ctk.CTkLabel(
            self.card,
            text="Minimum Alert Severity Level",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("#5E6E82", "#8F9CAE"),
            anchor="w"
        )
        self.thr_lbl.grid(row=3, column=0, sticky="w", padx=24, pady=10)
        
        self.thr_menu = ctk.CTkOptionMenu(
            self.card,
            values=["Low", "Medium", "High", "Critical"],
            font=ctk.CTkFont(family="Segoe UI", size=11),
            dropdown_font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color=("#EAECF0", "#162235"),
            button_color=("#D0D5DD", "#1E2D4A"),
            button_hover_color=("#00B4CC", "#00E5FF"),
            dropdown_fg_color=("#FFFFFF", "#121C2C"),
            dropdown_hover_color=("#EAECF0", "#1E2D4A")
        )
        self.thr_menu.grid(row=3, column=1, sticky="w", padx=(0, 24), pady=10)
        
        # 4. Enable notifications toggle
        self.notif_lbl = ctk.CTkLabel(
            self.card,
            text="Enable Live Audit Logs Popups",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("#5E6E82", "#8F9CAE"),
            anchor="w"
        )
        self.notif_lbl.grid(row=4, column=0, sticky="w", padx=24, pady=10)
        
        self.notif_toggle = ctk.CTkSwitch(
            self.card,
            text="",
            progress_color=("#00B4CC", "#00E5FF"),
            fg_color=("#EAECF0", "#1A2436")
        )
        self.notif_toggle.grid(row=4, column=1, sticky="w", padx=(0, 24), pady=10)
        
        # Save Preferences Button
        self.save_btn = ctk.CTkButton(
            self.card,
            text="💾 Save Engine Preferences",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=("#00B4CC", "#00E5FF"),
            hover_color=("#008B9B", "#00B8CC"),
            text_color=("#090E17", "#090E17"),
            height=34,
            command=self._save_preferences
        )
        self.save_btn.grid(row=5, column=0, columnspan=2, pady=(30, 24))
        
        self.refresh()

    def refresh(self):
        """Loads and updates settings fields from provider."""
        settings = self.data_service.get_settings()
        
        self.vol_input.delete(0, "end")
        self.vol_input.insert(0, settings.get("volatility_path", ""))
        
        self.yara_input.delete(0, "end")
        self.yara_input.insert(0, settings.get("yara_rules_path", ""))
        
        self.thr_menu.set(settings.get("alert_threshold", "High"))
        
        if settings.get("enable_auto_alerts", True):
            self.notif_toggle.select()
        else:
            self.notif_toggle.deselect()

    def _save_preferences(self):
        """Saves values into local settings dict."""
        updates = {
            "volatility_path": self.vol_input.get().strip(),
            "yara_rules_path": self.yara_input.get().strip(),
            "alert_threshold": self.thr_menu.get(),
            "enable_auto_alerts": self.notif_toggle.get() == 1
        }
        self.data_service.save_settings(updates)
        
        # Highlight success state
        self.save_btn.configure(text="✔ Preferences Saved Successfully!", fg_color="#00FF88", text_color="#0D251C")
        self.after(2000, lambda: self.save_btn.configure(text="💾 Save Engine Preferences", fg_color="#00E5FF", text_color="#090E17"))
