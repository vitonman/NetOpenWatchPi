# tray/tray_manager.py - System Tray integration

import pystray
from PIL import Image
import threading
import sys
import os


class TrayManager:
    def __init__(self, monitor_app):
        self.monitor_app = monitor_app
        self.icon = None

    def create_tray(self):
        icon_path = os.path.join(os.path.dirname(__file__), "icon.ico")
        try:
            image = Image.open(icon_path)
        except Exception:
            image = Image.new("RGB", (64, 64), color="#00ff88")

        menu = pystray.Menu(
            pystray.MenuItem("Show Status", self.show_status),
            pystray.MenuItem("Check Alerts", self.check_alerts),
            pystray.MenuItem("Open Main Window", self.open_gui_direct),
            pystray.MenuItem("Open Analysis Page", self.open_analysis_page),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self.quit_app),
        )

        self.icon = pystray.Icon(
            name="NetOpenWatchPi",
            icon=image,
            title="NetOpenWatchPi - Network Monitor",
            menu=menu,
        )

        print("System Tray started.")

    def show_status(self):
        self.monitor_app.show_status()

    def check_alerts(self):
        self.monitor_app.check_alerts()

    def open_gui_direct(self):
        """Open GUI from tray menu."""
        try:
            self.monitor_app.open_gui()
        except Exception as e:
            print(f"Error opening GUI window: {e}")

    def open_analysis_page(self):
        """Open desktop snapshot/log analysis page from tray menu."""
        try:
            self.monitor_app.open_analysis_page()
        except Exception as e:
            print(f"Error opening analysis page: {e}")

    def quit_app(self):
        print("\nQuitting from tray...")
        self.monitor_app.running = False
        if self.icon:
            self.icon.stop()
        sys.exit(0)

    def run(self):
        threading.Thread(target=self.icon.run, daemon=True).start()
