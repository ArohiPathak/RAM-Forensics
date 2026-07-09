import tkinter as tk

from widgets.chart_widget import ChartWidget


def test_bar_chart_filters_invalid_process_data():
    root = tk.Tk()
    root.withdraw()

    try:
        widget = ChartWidget(root, chart_type="bar", title="Test")
        chart_data = {
            "processes": ["svchost", "", "notepad", "Unknown", "System"],
            "threads": [8, 0, 5, 3, 10],
        }

        prepared = widget._prepare_bar_chart_data(chart_data)

        assert prepared["labels"] == ["System", "svchost", "notepad"]
        assert prepared["values"] == [10, 8, 5]
    finally:
        root.destroy()
