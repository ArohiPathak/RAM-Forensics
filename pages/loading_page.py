import customtkinter as ctk
import time
import threading
from pages.base_page import BasePage
from services.data_provider import DataProvider

class LoadingPage(BasePage):
    """
    LoadingPage displays a simulated command log of Volatility 3 plugins.
    Features:
    - Glowing progress bar.
    - Custom braille spinner character animation.
    - Live terminal log updates representing exact plugins:
      (windows.info, pslist, pstree, netscan, cmdline, dlllist).
    - Auto-redirects to Dashboard Overview on completion.
    """
    def __init__(self, master, data_service: DataProvider, **kwargs):
        super().__init__(
            master, 
            data_service, 
            title="Analysis Loading", 
            description="Active memory forensics scan. Executing Volatility 3 plugins...", 
            **kwargs
        )
        
        # Hide standard refresh button
        self.refresh_btn.grid_remove()
        
        self._is_running = False
        self.spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        
        # Configure layout (single centered grid frame)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        # Centered container card
        self.card = ctk.CTkFrame(
            self.content_frame,
            fg_color="#121C2C",
            border_color="#1E2D4A",
            border_width=1.5,
            corner_radius=12,
            width=650,
            height=420
        )
        self.card.grid(row=0, column=0, padx=20, pady=20)
        self.card.grid_propagate(False)
        self.card.grid_columnconfigure(0, weight=1)
        self.card.grid_rowconfigure(2, weight=1)  # Console frame stretches
        
        # Progress label
        self.prog_lbl = ctk.CTkLabel(
            self.card,
            text="ANALYSIS ACTIVE ⠋ 0%",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#00E5FF",
            anchor="w"
        )
        self.prog_lbl.grid(row=0, column=0, sticky="w", padx=24, pady=(24, 6))
        
        # Progress bar
        self.prog_bar = ctk.CTkProgressBar(
            self.card,
            fg_color="#1A2436",
            progress_color="#00E5FF",
            height=8
        )
        self.prog_bar.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 16))
        self.prog_bar.set(0.0)
        
        # Console output terminal
        self.console_frame = ctk.CTkFrame(
            self.card,
            fg_color="#0B0F19",
            border_color="#1E2D4A",
            border_width=1,
            corner_radius=8
        )
        self.console_frame.grid(row=2, column=0, sticky="nsew", padx=24, pady=(0, 24))
        self.console_frame.grid_columnconfigure(0, weight=1)
        self.console_frame.grid_rowconfigure(0, weight=1)
        
        self.console = ctk.CTkTextbox(
            self.console_frame,
            fg_color="transparent",
            text_color="#00FF88",
            font=ctk.CTkFont(family="Consolas", size=10),
            corner_radius=0,
            border_width=0
        )
        self.console.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.console.configure(state="disabled")

    def _console_log(self, text: str, replace_last: bool = False):
        """Appends logs to the console text box, optionally replacing the last line."""
        self.console.configure(state="normal")
        if replace_last:
            # Safely deletes the last line of text using tkinter index modifiers
            self.console.delete("end-2c linestart", "end-1c")
        self.console.insert("end", text + "\n")
        self.console.configure(state="disabled")
        self.console.see("end")

    def start_analysis(self, file_path: str):
        """Starts simulated backend plugin execution."""
        if self._is_running:
            return
            
        self._is_running = True
        self.prog_bar.set(0.0)
        
        # Clear logs and print header
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")
        
        self._console_log(f"[*] Analyzing target RAM image: {file_path}")
        self._console_log("[*] Engine initialized. Running Volatility 3 plugins...\n")
        
        # Start spinner animation
        self._animate_spinner(0)
        
        # Launch simulation thread
        threading.Thread(target=self._run_simulation, daemon=True).start()

    def _animate_spinner(self, index: int):
        """Recursively draws the braille spinner glyph inside progress label."""
        if not self._is_running:
            return
            
        spin = self.spinner_chars[index]
        pct = int(self.prog_bar.get() * 100)
        self.prog_lbl.configure(text=f"ANALYSIS RUNNING {spin} {pct}%")
        
        # Schedule next frame in 100ms
        self.after(100, lambda: self._animate_spinner((index + 1) % len(self.spinner_chars)))

    def _run_simulation(self):
        """Simulates sequentially running the 6 Volatility plugins."""
        plugins = [
            ("windows.info", 0.16),
            ("windows.pslist", 0.33),
            ("windows.pstree", 0.50),
            ("windows.netscan", 0.66),
            ("windows.cmdline", 0.83),
            ("windows.dlllist", 1.0)
        ]
        
        for plugin_name, target_pct in plugins:
            # 1. Print starting indicator
            self.after(0, lambda name=plugin_name: self._console_log(f"⏳ Running {name}..."))
            
            # Simulate processing delay
            time.sleep(0.8)
            
            # Update progress bar smoothly
            self.after(0, lambda p=target_pct: self.prog_bar.set(p))
            
            # 2. Overwrite line with completed checkmark
            self.after(0, lambda name=plugin_name: self._console_log(f"✔ Running {name}", replace_last=True))
            
            # Small resting pause between plugin stages
            time.sleep(0.3)
            
        # Complete stage
        self.after(0, lambda: self._console_log("\n[+] All plugins executed successfully. Reports cached."))
        time.sleep(0.8)
        
        # Trigger completed actions
        self.after(0, self._on_finish_analysis)

    def _on_finish_analysis(self):
        """Navigates back to the main dashboard panel on finish."""
        self._is_running = False
        
        app = self.winfo_toplevel()
        if hasattr(app, "show_page"):
            summary = self.data_service.get_summary()
            if hasattr(app, "sidebar"):
                import os
                app.sidebar.update_status(f"Loaded: {os.path.basename(summary.get('dump_file', ''))}", "ready")
            
            # Transition to landing dashboard overview
            app.show_page("dashboard")
            
            # Reload metrics
            if "dashboard" in app.pages:
                app.pages["dashboard"].refresh()
