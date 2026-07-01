import customtkinter as ctk
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np

class ChartWidget(ctk.CTkFrame):
    """
    ChartWidget embeds an active Matplotlib canvas inside CustomTkinter.
    Supports rendering a Donut (pie) chart or a Bar chart, dynamically styled
    for both Light and Dark appearance modes.
    """
    def __init__(self, master, chart_type: str = "donut", title: str = "RAM Distribution Space", **kwargs):
        # Support light/dark mode border and background colors
        super().__init__(
            master, 
            fg_color=("#FFFFFF", "#121C2C"), 
            border_color=("#D0D5DD", "#1E2D4A"), 
            border_width=1.5, 
            corner_radius=10, 
            **kwargs
        )
        
        self.chart_type = chart_type
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # Title Header
        self.title_label = ctk.CTkLabel(
            self,
            text=title.upper(),
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=("#475569", "#8F9CAE"),
            anchor="w"
        )
        self.title_label.grid(row=0, column=0, sticky="w", padx=16, pady=(12, 4))
        
        # Initial facecolor determined by current appearance mode
        mode = ctk.get_appearance_mode().lower()
        bg_color = '#FFFFFF' if mode == 'light' else '#121C2C'
        
        # Matplotlib Figure configuration
        self.fig = Figure(figsize=(3, 2.3), dpi=100, facecolor=bg_color)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor(bg_color)
        
        # Adjust subplots spacing
        self.fig.tight_layout()
        self.fig.subplots_adjust(top=0.85, bottom=0.15, left=0.15, right=0.90)
        
        # Canvas creation
        self.canvas = FigureCanvasTkAgg(self.fig, self)
        self.canvas.get_tk_widget().grid(row=1, column=0, padx=12, pady=(0, 12), sticky="nsew")

    def update_chart(self, chart_data: dict):
        """Redraws the chart with updated dataset parameters and applies dynamic theme styling."""
        self.ax.clear()
        
        # Read the current active appearance mode dynamically
        mode = ctk.get_appearance_mode().lower()
        if mode == "light":
            bg_color = '#FFFFFF'
            text_color = '#475569'
            edge_color = '#FFFFFF'
            spine_color = '#D0D5DD'
            grid_color = '#000000'
            anno_color = '#1E293B'
        else:
            bg_color = '#121C2C'
            text_color = '#8F9CAE'
            edge_color = '#121C2C'
            spine_color = '#1E2D4A'
            grid_color = '#FFFFFF'
            anno_color = '#FFFFFF'
            
        self.fig.set_facecolor(bg_color)
        self.ax.set_facecolor(bg_color)
        
        if self.chart_type == "donut":
            labels = chart_data.get("labels", [])
            sizes = chart_data.get("sizes", [])
            colors = chart_data.get("colors", ["#1D4ED8", "#00E5FF", "#FF3B30", "#1E293B"])
            
            # Configure subplot spacing specifically for pie to prevent text cutting
            self.fig.subplots_adjust(top=0.90, bottom=0.05, left=0.05, right=0.95)
            
            wedges, texts, autotexts = self.ax.pie(
                sizes,
                labels=labels,
                colors=colors,
                autopct='%1.1f%%',
                startangle=90,
                pctdistance=0.75,
                textprops=dict(color=text_color, family="Segoe UI", size=7.5),
                wedgeprops=dict(width=0.35, edgecolor=edge_color, linewidth=1.5)
            )
            
            for autotext in autotexts:
                autotext.set_color('#FFFFFF' if mode == 'dark' else '#000000')
                autotext.set_fontsize(7.5)
                autotext.set_weight('bold')
                
            centre_circle = matplotlib.patches.Circle((0,0), 0.55, fc=bg_color)
            self.ax.add_artist(centre_circle)
            self.ax.axis('equal')
            
        elif self.chart_type == "bar":
            categories = chart_data.get("processes", [])
            values = chart_data.get("threads", [])
            colors = chart_data.get("colors", ["#00E5FF"])
            
            self.fig.subplots_adjust(top=0.90, bottom=0.25, left=0.20, right=0.90)
            
            bars = self.ax.bar(
                categories,
                values,
                color=colors,
                edgecolor=spine_color,
                width=0.5,
                linewidth=1
            )
            
            # Stylize spines and ticks
            self.ax.spines['top'].set_visible(False)
            self.ax.spines['right'].set_visible(False)
            self.ax.spines['left'].set_color(spine_color)
            self.ax.spines['bottom'].set_color(spine_color)
            
            self.ax.tick_params(colors=text_color, labelsize=7.5)
            self.ax.yaxis.grid(True, linestyle='--', alpha=0.1, color=grid_color)
            
            # Rotate labels to prevent overlap
            self.ax.set_xticks(range(len(categories)))
            self.ax.set_xticklabels(categories, rotation=25, ha="right")
            
            # Add labels values above bars
            for bar in bars:
                height = bar.get_height()
                self.ax.annotate(
                    f"{int(height)}",
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 2),  # 2 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom',
                    color=anno_color, fontsize=7.5, weight='bold'
                )
                
        self.fig.canvas.draw()
