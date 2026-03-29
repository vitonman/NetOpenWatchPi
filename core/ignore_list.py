# core/ignore_list.py - Management of ignored processes (white list)

import json
import os
from typing import Set

class IgnoreList:
    """Manages the list of processes to ignore"""

    def __init__(self):
        self.config_path = "config/config.json"
        self.ignored_processes: Set[str] = set()
        self.default_ignored = {
            "System Idle Process", "System", "svchost.exe", "Registry", "Idle",
            "csrss.exe", "wininit.exe", "smss.exe", "lsass.exe", "services.exe",
            "python.exe", "Code.exe", "vmware-authd.exe"
        }
        self.load()

    def load(self):
        """Load ignore list from config"""
        os.makedirs("config", exist_ok=True)
        
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.ignored_processes = set(data.get("ignored_processes", []))
            except:
                self.ignored_processes = set()
        else:
            self.ignored_processes = set(self.default_ignored)
            self.save()

    def save(self):
        """Save ignore list to config"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump({"ignored_processes": list(self.ignored_processes)}, f, indent=4)
        except Exception as e:
            print(f"Error saving ignore list: {e}")

    def add(self, process_name: str):
        """Add process to ignore list"""
        if process_name and process_name not in self.ignored_processes:
            self.ignored_processes.add(process_name)
            self.save()
            print(f"Added to ignore list: {process_name}")

    def remove(self, process_name: str):
        """Remove process from ignore list"""
        if process_name in self.ignored_processes:
            self.ignored_processes.remove(process_name)
            self.save()
            print(f"Removed from ignore list: {process_name}")

    def contains(self, process_name: str) -> bool:
        """Check if process is ignored"""
        return process_name in self.ignored_processes

    def get_all(self) -> list:
        """Return all ignored processes"""
        return sorted(self.ignored_processes)