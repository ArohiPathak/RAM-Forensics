import os
import customtkinter as ctk
from services.data_provider import DataProvider
from widgets.sidebar import Sidebar
from pages.dashboard_page import DashboardPage
from pages.processes_page import ProcessesPage
from pages.network_page import NetworkPage
from pages.malware_page import MalwarePage
from pages.upload_page import UploadPage
from pages.dll_page import DllPage
from pages.timeline_page import TimelinePage
from pages.report_page import ReportPage
from pages.settings_page import SettingsPage
from pages.loading_page import LoadingPage

# Set theme color defaults before loading
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")  # Uses standard blue widgets styling as baseline

class App(ctk.CTk):
    """
    App is the main window controller for the RAM Forensics Dashboard.
    It orchestrates navigation events, page switching layouts, and ties the service layer to UI pages.
    Supports collapsible sidebar window resizing.
    """
    def __init__(self, data_service: DataProvider):
        super().__init__()
        
        self.data_service = data_service
        
        # Configure Window Metadata
        self.title("RAM Forensics Dashboard - Volatility 3 UI Core")
        self.geometry("1200x720")
        self.minsize(1080, 680)
        
        # Base UI grid system (Left Sidebar: Col 0, Content Container: Col 1)
        self.grid_columnconfigure(0, weight=0)  # Sidebar does not stretch horizontally
        self.grid_columnconfigure(1, weight=1)  # Content view fills window width
        self.grid_rowconfigure(0, weight=1)
        
        # 1. Sidebar Panel
        self.sidebar = Sidebar(
            self,
            on_navigate=self.show_page,
            initial_tab="dashboard"
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew") # Stretches to fill vertical height
        
        # Update sidebar with initial status
        summary = self.data_service.get_summary()
        self.sidebar.update_status(
            f"Loaded: {os.path.basename(summary.get('dump_file', 'mem_dump.raw'))}",
            "info"
        )
        
        # 2. Main Page Container Frame (Where pages will load)
        self.container = ctk.CTkFrame(self, fg_color=("#F5F7FA", "#0B0F19"), corner_radius=0)
        self.container.grid(row=0, column=1, sticky="nsew")
        self.container.grid_columnconfigure(0, weight=1)
        self.container.grid_rowconfigure(0, weight=1)
        
        # Initialize Page objects cached in memory
        self.pages = {}
        
        self.pages["dashboard"] = DashboardPage(self.container, self.data_service)
        self.pages["upload"] = UploadPage(self.container, self.data_service)
        self.pages["processes"] = ProcessesPage(self.container, self.data_service)
        self.pages["network"] = NetworkPage(self.container, self.data_service)
        self.pages["malware"] = MalwarePage(self.container, self.data_service)
        self.pages["dll"] = DllPage(self.container, self.data_service)
        self.pages["timeline"] = TimelinePage(self.container, self.data_service)
        self.pages["report"] = ReportPage(self.container, self.data_service)
        self.pages["settings"] = SettingsPage(self.container, self.data_service)
        self.pages["loading"] = LoadingPage(self.container, self.data_service)
        
        # Grid pages in the same container cell so they overlap
        for page_name, page_frame in self.pages.items():
            page_frame.grid(row=0, column=0, sticky="nsew")
            
        # Display the upload page by default for the demo workflow
        self.show_page("upload")

    def show_page(self, page_name: str):
        """Displays the selected page and hides all other active frames."""
        if page_name not in self.pages:
            print(f"Error: View page '{page_name}' does not exist.")
            return
            
        # Hide all pages using grid_remove (preserves configuration for caching)
        for name, frame in self.pages.items():
            if name != page_name:
                frame.grid_remove()
                
        # Show selected page
        selected_page = self.pages[page_name]
        selected_page.grid()
        
        # Trigger refresh on transition to ensure any back-end change renders
        selected_page.refresh()
        
        # Sync navigation highlights if triggered externally
        if hasattr(self, 'sidebar') and self.sidebar.active_tab != page_name:
            self.sidebar.active_tab = page_name
            self.sidebar._update_button_states()
