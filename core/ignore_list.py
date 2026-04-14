# core/ignore_list.py - Management of ignored processes (white list)

import json
import os
from typing import Set, List
from core.user_settings import load_settings, save_settings

class IgnoreList:
    """Manages the list of processes to ignore.
    By default almost nothing is ignored - user has full control."""

    def __init__(self):
        self.config_path = "config/settings.json"
        self.ignored_processes: Set[str] = set()

        # Minimal default - only critical noise that almost never should be monitored
        self.default_ignored = {
            "System Idle Process",
            "System",
            "Registry",
            "Idle"
        }
        self.load()

    def load(self):
        """Load ignore list from config file"""
        os.makedirs("config", exist_ok=True)

        try:
            data = load_settings()
            self.ignored_processes = set(data.get("ignored_processes", []))
        except Exception:
            self.ignored_processes = set(self.default_ignored)

    def save(self):
        """Save current ignore list"""
        try:
            data = load_settings()
            data["ignored_processes"] = sorted(list(self.ignored_processes))
            save_settings(data)
        except Exception as e:
            print(f"Error saving ignore list: {e}")

    def add(self, process_name: str) -> bool:
        """Add process to ignore list"""
        if process_name and process_name not in self.ignored_processes:
            self.ignored_processes.add(process_name)
            self.save()
            print(f"✓ Added to ignore list: {process_name}")
            return True
        return False

    def remove(self, process_name: str) -> bool:
        """Remove process from ignore list"""
        if process_name in self.ignored_processes:
            self.ignored_processes.remove(process_name)
            self.save()
            print(f"✓ Removed from ignore list: {process_name}")
            return True
        return False

    def contains(self, process_name: str) -> bool:
        """Check if process is ignored"""
        return process_name in self.ignored_processes

    def get_all(self) -> List[str]:
        """Return sorted list of ignored processes"""
        return sorted(self.ignored_processes)

    def is_minimal(self) -> bool:
        """Check if only default minimal ignores are present"""
        return self.ignored_processes == self.default_ignored
