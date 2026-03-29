# gui/main_window.py - Working version (do not change request_admin for now)

import tkinter as tk
from tkinter import ttk, messagebox
import ctypes
import sys
import os
from core.network_collector import NetworkCollector
from core.ignore_list import IgnoreList

class MainWindow:
    def __init__(self, monitor_app):
        self.monitor_app = monitor_app
        self.ignore_list = IgnoreList()
        self.collector = NetworkCollector()
        self.root = None
        self.tree = None
        self.is_admin = self.check_admin()
        self.check_states = {}  # Store checkbox-like state for each process

    def check_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def request_admin(self):
        if self.is_admin:
            messagebox.showinfo("Info", "Already running as Administrator")
            return

        try:
            python_exe = sys.executable
            script_path = os.path.abspath(sys.argv[0])

            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", python_exe, f'"{script_path}"', None, 1
            )

            if result > 32:
                print("Restarting with administrator privileges...")
                if self.root:
                    self.root.destroy()
                os._exit(0)               # This line was working for you
            else:
                messagebox.showerror("Error", "Failed to elevate privileges.")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to elevate privileges:\n{str(e)}")

    def create_window(self):
        self.root = tk.Tk()
        self.root.title("NetOpenWatchPi - Network Monitor")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)

        # Title
        tk.Label(self.root, text="NetOpenWatchPi", font=("Arial", 22, "bold")).pack(pady=15)

        # Admin status
        status_text = "[ADMIN] Administrator Mode" if self.is_admin else "[LIMITED] Limited Mode"
        color = "green" if self.is_admin else "orange"
        tk.Label(self.root, text=status_text, fg=color, font=("Arial", 11)).pack(pady=8)

        # Admin button
        tk.Button(self.root, text="Run as Administrator", command=self.request_admin,
                  bg="#ff9800", fg="white", font=("Arial", 10, "bold"), height=2).pack(pady=12)

        # Treeview
        columns = ("#", "PID", "Process", "Connections", "Unique IPs", "Status", "Ignore")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=25)

        
        self.tree.heading("#", text="#")
        self.tree.heading("PID", text="PID")
        self.tree.heading("Process", text="Process Name")
        self.tree.heading("Connections", text="Connections")
        self.tree.heading("Unique IPs", text="Unique IPs")
        self.tree.heading("Status", text="Status")
        self.tree.heading("Ignore", text="Ignore")
       
        self.tree.column("#", width=60)
        self.tree.column("PID", width=100)
        self.tree.column("Process", width=400)
        self.tree.column("Connections", width=140, anchor="center")
        self.tree.column("Unique IPs", width=140, anchor="center")
        self.tree.column("Status", width=160, anchor="center")
    
        self.tree.column("Ignore", width=90, anchor="center")

        self.tree.pack(pady=15, padx=25, fill="both", expand=True)
        self.tree.bind("<Button-1>", self.on_tree_click)

        # Buttons frame
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=20)

        tk.Button(btn_frame, text="Refresh", command=self.refresh_gui_list, width=15, height=2).pack(side="left", padx=15)
        tk.Button(btn_frame, text="Check Alerts", command=self.monitor_app.check_alerts, width=15, height=2).pack(side="left", padx=15)
        tk.Button(btn_frame, text="Apply Changes", command=self.apply_changes, bg="#4CAF50", fg="white", width=18, height=2).pack(side="left", padx=15)

        self.refresh_gui_list()
        self.root.mainloop()

    def refresh_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.check_states = {}
        top = self.collector.get_top_processes(limit=50)   # ÑƒÐ²ÐµÐ»Ð¸Ñ‡Ð¸Ð» Ð»Ð¸Ð¼Ð¸Ñ‚

        for i, (name, data) in enumerate(top, 1):
            conn = data["connections"]
            ips = len(data["unique_ips"])
            is_ignored = self.ignore_list.contains(name)
            pid = data.get("pid", "N/A")

            status_text = "IGNORED" if is_ignored else "TRACKING"
            checkbox_text = "[x]" if is_ignored else "[ ]"
            self.check_states[name] = is_ignored

            self.tree.insert("", "end", values=(i, pid, name, conn, ips, status_text, checkbox_text))

    def refresh_gui_list(self):
        """Refresh full process list for GUI with checkboxes"""
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.check_states = {}
        # get all processes to show in GUI (not just top)
        all_processes = self.collector.collect_network_data()

        # sort processes by connections in descending order
        sorted_processes = sorted(all_processes.items(), key=lambda x: x[1]["connections"], reverse=True)

        for i, (name, data) in enumerate(sorted_processes, 1):
            conn = data["connections"]
            ips = len(data["unique_ips"])
            is_ignored = self.ignore_list.contains(name)
            pid = data.get("pid", "N/A")

            status_text = "IGNORED" if is_ignored else "TRACKING"
            checkbox_text = "[x]" if is_ignored else "[ ]"
            self.check_states[name] = is_ignored

            self.tree.insert("", "end", values=(i, pid, name, conn, ips, status_text, checkbox_text))

    def on_tree_click(self, event):
        """Toggle ignore state when clicking the Ignore column."""
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            return

        column = self.tree.identify_column(event.x)
        if column != "#7":  # Ignore column
            return

        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return

        values = list(self.tree.item(row_id, "values"))
        if len(values) < 7:
            return

        name = values[2]
        new_state = not self.check_states.get(name, False)
        self.check_states[name] = new_state

        values[6] = "[x]" if new_state else "[ ]"
        values[5] = "IGNORED" if new_state else "TRACKING"
        self.tree.item(row_id, values=values)

    def apply_changes(self):
        """Apply ignore changes from checkboxes"""
        changed = False
        for name, should_ignore in self.check_states.items():
            currently_ignored = self.ignore_list.contains(name)

            if should_ignore and not currently_ignored:
                self.ignore_list.add(name)
                changed = True
            elif not should_ignore and currently_ignored:
                self.ignore_list.remove(name)
                changed = True

        if changed:
            messagebox.showinfo("Success", "Ignore list updated successfully!")
        else:
            messagebox.showinfo("Info", "No changes were made.")

        self.refresh_gui_list()

