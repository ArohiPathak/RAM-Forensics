import customtkinter as ctk
import os
from frontend.pages.base_page import BasePage
from frontend.widgets.metric_card import MetricCard
from frontend.widgets.chart_widget import ChartWidget
from frontend.services.data_provider import DataProvider
from typing import Dict, Any

class DashboardPage(BasePage):
    """
    DashboardPage provides a professional DFIR overview of a memory dump target.
    Displays:
    - 6 Top Summary Cards (Image, OS, Processes, Sockets, Hidden Procs, Risk Score).
    - Simulated Risk Gauge indicating critical alert status.
    - Reusable Donut and Bar Matplotlib chart panels.
    - Chronological Recent Activity feed.
    - Narrative Investigation Summary details.
    """
    def __init__(self, master, data_service: DataProvider, **kwargs):
        super().__init__(
            master, 
            data_service, 
            title="Overview Dashboard", 
            description="Professional DFIR memory analysis overview and threat intel indicators.", 
            **kwargs
        )
        
        self.cards = {}
        
        # Configure layout (Main content frame: 1 Column, Row 1 stretches)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(1, weight=1)  # Bottom details stretch
        
        # --- 1. TOP SUMMARY CARDS PANEL (6 Columns grid) ---
        self.stats_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.stats_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        self.stats_frame.grid_rowconfigure(0, weight=1)
        for col in range(6):
            self.stats_frame.grid_columnconfigure(col, weight=1, uniform="stats")
            
        # --- 2. BOTTOM DETAILS PANEL (Left Charts, Right Logs & Summary) ---
        self.bottom_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.bottom_frame.grid(row=1, column=0, sticky="nsew")
        self.bottom_frame.grid_columnconfigure(0, weight=3) # Left charts column
        self.bottom_frame.grid_columnconfigure(1, weight=2) # Right alerts column
        self.bottom_frame.grid_rowconfigure(0, weight=1)
        
        # --- LEFT PANEL: RISK GAUGE & CHARTS ---
        self.left_panel = ctk.CTkFrame(self.bottom_frame, fg_color="transparent")
        self.left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.left_panel.grid_columnconfigure(0, weight=1)
        self.left_panel.grid_rowconfigure(1, weight=1) # Charts subframe stretches
        
        # A. Risk Gauge Card
        self.gauge_card = ctk.CTkFrame(
            self.left_panel,
            fg_color=("#FFFFFF", "#121C2C"),
            border_color=("#D0D5DD", "#1E2D4A"),
            border_width=1.5,
            corner_radius=10,
            height=85
        )
        self.gauge_card.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        self.gauge_card.grid_propagate(False)
        self.gauge_card.grid_columnconfigure(0, weight=1)
        
        self.gauge_title = ctk.CTkLabel(
            self.gauge_card,
            text="DFIR RISK RATING METERS",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color="#FF3B30",
            anchor="w"
        )
        self.gauge_title.grid(row=0, column=0, sticky="w", padx=16, pady=(10, 4))
        
        self.gauge_bar = ctk.CTkProgressBar(
            self.gauge_card,
            fg_color=("#F1F5F9", "#1A2436"),
            progress_color="#FF3B30",
            height=10
        )
        self.gauge_bar.grid(row=1, column=0, sticky="ew", padx=16, pady=2)
        
        self.gauge_status = ctk.CTkLabel(
            self.gauge_card,
            text="CRITICAL RISK LEVEL",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("#DE350B", "#FF8882")
        )
        self.gauge_status.grid(row=2, column=0, sticky="e", padx=16, pady=2)
        
        # B. Charts Sub-Frame (Holds Pie & Bar side-by-side)
        self.charts_frame = ctk.CTkFrame(self.left_panel, fg_color="transparent")
        self.charts_frame.grid(row=1, column=0, sticky="nsew")
        self.charts_frame.grid_columnconfigure(0, weight=1)
        self.charts_frame.grid_columnconfigure(1, weight=1)
        self.charts_frame.grid_rowconfigure(0, weight=1)
        
        self.pie_chart = ChartWidget(self.charts_frame, chart_type="donut", title="Memory Space Profile Allocation")
        self.pie_chart.grid(row=0, column=0, padx=(0, 6), sticky="nsew")
        
        self.bar_chart = ChartWidget(self.charts_frame, chart_type="bar", title="Top Process Threads Consumptions")
        self.bar_chart.grid(row=0, column=1, padx=(6, 0), sticky="nsew")
        
        # --- RIGHT PANEL: RECENT ACTIVITY & INVESTIGATION SUMMARY ---
        self.right_panel = ctk.CTkFrame(self.bottom_frame, fg_color="transparent")
        self.right_panel.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self.right_panel.grid_columnconfigure(0, weight=1)
        self.right_panel.grid_rowconfigure(0, weight=4) # Activity stretches
        self.right_panel.grid_rowconfigure(1, weight=3) # Narrative summary
        
        # A. Recent Activity Box
        self.activity_box = ctk.CTkFrame(
            self.right_panel, 
            fg_color=("#FFFFFF", "#121C2C"), 
            border_color=("#D0D5DD", "#1E2D4A"), 
            border_width=1.5, 
            corner_radius=10
        )
        self.activity_box.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        self.activity_box.grid_columnconfigure(0, weight=1)
        self.activity_box.grid_rowconfigure(1, weight=1)
        
        self.activity_title = ctk.CTkLabel(
            self.activity_box,
            text="RECENT SECURITY ACTIVITY LOGS",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("#008B9B", "#00E5FF"),
            anchor="w"
        )
        self.activity_title.grid(row=0, column=0, sticky="w", padx=16, pady=(12, 6))
        
        self.activity_scroll = ctk.CTkScrollableFrame(
            self.activity_box,
            fg_color="transparent"
        )
        self.activity_scroll._scrollbar.configure(
            fg_color="transparent",
            button_color=("#C1C9D2", "#1E2D4A"),
            button_hover_color=("#00B4CC", "#00E5FF")
        )
        self.activity_scroll.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 12))
        self.activity_scroll.grid_columnconfigure(0, weight=1)
        
        # B. Investigation Summary Box
        self.summary_box = ctk.CTkFrame(
            self.right_panel, 
            fg_color=("#FFF5F5", "#1A151C"), # Inset warning color code
            border_color=("#E53E3E", "#FF3B30"), 
            border_width=1, 
            corner_radius=10
        )
        self.summary_box.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self.summary_box.grid_columnconfigure(0, weight=1)
        self.summary_box.grid_rowconfigure(1, weight=1)
        
        self.summary_title = ctk.CTkLabel(
            self.summary_box,
            text="INVESTIGATION SUMMARY REPORT",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=("#DE350B", "#FF3B30"),
            anchor="w"
        )
        self.summary_title.grid(row=0, column=0, sticky="w", padx=16, pady=(12, 4))
        
        self.summary_text = ctk.CTkTextbox(
            self.summary_box,
            fg_color="transparent",
            text_color=("#9B2C2C", "#FF8882"),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            corner_radius=0,
            border_width=0,
            wrap="word",
            height=60
        )
        self.summary_text.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.summary_text.configure(state="disabled")
        
        self.refresh()

    def refresh(self):
        """Pulls dynamic metrics and charts parameters from DataProvider without hardcoding."""
        dashboard_data = self.data_service.get_dashboard_data()
        summary = dashboard_data.get("summary", {})
        donut_data = dashboard_data.get("donut_chart", {})
        bar_data = dashboard_data.get("bar_chart", {})
        timeline_events = self.data_service.get_timeline()
        
        # 1. Clean up old top summary metric cards
        for card in self.cards.values():
            card.destroy()
        self.cards.clear()
        
        # Extract metadata metrics
        dump_path = summary.get("dump_file", "mem_dump.raw")
        filename = os.path.basename(dump_path)
        os_profile = summary.get("profile", "Unknown Profile")
        total_p = summary.get("total_processes", 0)
        net_conn = summary.get("network_connections", 0)
        hidden_p = summary.get("hidden_processes", 0)
        risk_score = summary.get("risk_score", 0)
        
        # Re-populate 6 DFIR Summary Cards
        # Card 1: Memory Dump filename
        self.cards["dump"] = MetricCard(
            self.stats_frame,
            title="Forensic Target",
            value=filename,
            subtitle=os.path.dirname(dump_path) if len(dump_path) > 30 else dump_path,
            theme="info"
        )
        self.cards["dump"].grid(row=0, column=0, padx=3, sticky="nsew")
        
        # Card 2: Operating System
        self.cards["os"] = MetricCard(
            self.stats_frame,
            title="OS Profile",
            value=os_profile.split(" ")[0],
            subtitle=" ".join(os_profile.split(" ")[1:]),
            theme="info"
        )
        self.cards["os"].grid(row=0, column=1, padx=3, sticky="nsew")
        
        # Card 3: Total Processes
        self.cards["proc"] = MetricCard(
            self.stats_frame,
            title="Processes count",
            value=str(total_p),
            subtitle="Parsed volatility pslist",
            theme="info"
        )
        self.cards["proc"].grid(row=0, column=2, padx=3, sticky="nsew")
        
        # Card 4: Network Connections
        self.cards["net"] = MetricCard(
            self.stats_frame,
            title="Network sockets",
            value=str(net_conn),
            subtitle="Active sockets netscan",
            theme="info"
        )
        self.cards["net"].grid(row=0, column=3, padx=3, sticky="nsew")
        
        # Card 5: Hidden Processes
        self.cards["hidden"] = MetricCard(
            self.stats_frame,
            title="Hidden Procs",
            value=str(hidden_p),
            subtitle="Anomalous threads tagged",
            theme="warning" if hidden_p > 0 else "success"
        )
        self.cards["hidden"].grid(row=0, column=4, padx=3, sticky="nsew")
        
        # Card 6: Risk Rating Score
        self.cards["risk"] = MetricCard(
            self.stats_frame,
            title="Threat Risk Score",
            value=f"{risk_score} / 100",
            subtitle="Critical severity alerts",
            theme="danger" if risk_score > 60 else "warning" if risk_score > 30 else "success"
        )
        self.cards["risk"].grid(row=0, column=5, padx=3, sticky="nsew")
        
        # 2. Update Risk Gauge Progress Bar
        self.gauge_bar.set(risk_score / 100.0)
        self.gauge_status.configure(text=f"CRITICAL RISK THREAT RATING: {risk_score}%")
        
        # 3. Re-render Matplotlib Chart Placeholders with data provider variables
        self.pie_chart.update_chart(donut_data)
        self.bar_chart.update_chart(bar_data)
        
        # 4. Update Narrative Investigation Summary
        self.summary_text.configure(state="normal")
        self.summary_text.delete("1.0", "end")
        self.summary_text.insert("1.0", summary.get("investigation_summary", "No analyst notes written for this snapshot."))
        self.summary_text.configure(state="disabled")
        
        # 5. Re-populate Recent Activity logs
        for widget in self.activity_scroll.winfo_children():
            widget.destroy()
            
        if not timeline_events:
            no_lbl = ctk.CTkLabel(
                self.activity_scroll,
                text="✔ No chronological logs loaded.",
                font=ctk.CTkFont(family="Segoe UI", size=12),
                text_color="#627284"
            )
            no_lbl.pack(pady=30)
        else:
            for event in timeline_events:
                sev = event.get("severity", "info")
                dot_color = "#FF3B30" if sev == "danger" else "#FFB300" if sev == "warning" else "#00FF88"
                
                if sev == "danger":
                    bg_item = ("#FFF5F5", "#1B171F")
                    border_col = ("#E53E3E", "#471D1D")
                    txt_col = ("#DE350B", "#FF8882")
                else:
                    bg_item = ("#FFFFFF", "#121C2C")
                    border_col = ("#D0D5DD", "#1E2D4A")
                    txt_col = ("#334155", "#E2E8F0")
                    
                log_box = ctk.CTkFrame(self.activity_scroll, fg_color=bg_item, border_color=border_col, border_width=1, corner_radius=6)
                log_box.pack(pady=3, fill="x")
                log_box.grid_columnconfigure(1, weight=1)
                
                # Severity Dot
                lbl_dot = ctk.CTkLabel(log_box, text="●", text_color=dot_color, font=ctk.CTkFont(size=14))
                lbl_dot.grid(row=0, column=0, padx=(10, 4), pady=6)
                
                # Category & Details
                lbl_desc = ctk.CTkLabel(
                    log_box,
                    text=f"{event.get('time')} - [{event.get('category').upper()}] {event.get('details')}",
                    font=ctk.CTkFont(family="Segoe UI", size=10),
                    text_color=txt_col,
                    wraplength=340,
                    justify="left",
                    anchor="w"
                )
                lbl_desc.grid(row=0, column=1, sticky="w", padx=4, pady=6)
