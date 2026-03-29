# monitor.py - Command-driven quiet mode for debugging

import time
import threading
from core.metrics import metrics
from core.network_collector import NetworkCollector
from core.alert_manager import AlertManager
from core.ignore_list import IgnoreList
from core.display import print_startup_info

class MonitorApp:
    def __init__(self):
        self.ignore_list = IgnoreList()
        self.collector = NetworkCollector()
        self.alert_manager = AlertManager(self.ignore_list)
        self.running = True
        self.last_top_processes = []   # сохраняем последний статус для добавления по номеру

    def background_monitor(self):
        """Silent background thread"""
        while self.running:
            try:
                self.collector.collect_network_data()
            except:
                pass
            time.sleep(2)

    def run(self):
        print_startup_info()
        print("Command-Driven Quiet Mode activated.\n")

        threading.Thread(target=self.background_monitor, daemon=True).start()

        print("Available commands:")
        print("  status          → show system info + numbered top processes")
        print("  alerts          → check anomalies now")
        print("  add <name|number> → add process to ignore list (by name or number from status)")
        print("  list / ignore   → show ignore list")
        print("  clear           → clear screen")
        print("  quit            → exit program\n")

        try:
            while self.running:
                cmd = input("> ").strip()

                if cmd.lower() == "quit":
                    break
                elif cmd.lower() == "status":
                    self.show_status()
                elif cmd.lower() in ["alerts"]:
                    self.check_alerts()
                elif cmd.lower() in ["list", "ignore"]:
                    self.show_ignore_list()
                elif cmd.startswith("add "):
                    self.add_to_ignore(cmd[4:].strip())
                elif cmd.lower() == "clear":
                    print("\n" * 40)
                else:
                    print("Unknown command. Use: status, alerts, add <name|number>, list, clear, quit")

        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            print("\nProgram stopped.")

    def show_status(self):
        """Show system metrics and numbered top processes with ignore status"""
        print("\n" + "="*80)
        print(f" STATUS at {time.strftime('%H:%M:%S')}")
        print("="*80)

        sys_data = metrics.get_all_metrics()
        temp_str = f"{sys_data['cpu_temp']}°C" if sys_data['cpu_temp'] is not None else "N/A"

        print(f"CPU Usage : {sys_data['cpu_percent']:5.1f}%")
        print(f"RAM Usage : {sys_data['ram_percent']:5.1f}%")
        print(f"CPU Temp  : {temp_str}")
        print("-" * 80)

        print("TOP ACTIVE PROCESSES:")
        self.last_top_processes = self.collector.get_top_processes(limit=15)

        for i, (name, data) in enumerate(self.last_top_processes, 1):
            conn = data["connections"]
            ips = len(data["unique_ips"])
            color = "\033[91m" if conn > 25 else "\033[93m" if conn > 12 else "\033[92m"
            reset = "\033[0m"
            ignored_mark = " [IGNORED]" if self.ignore_list.contains(name) else ""
            print(f"  {i:2}. {color}{name:<25}{reset}{ignored_mark} | 🔗 {conn:3} conn | 🌐 {ips:3} IPs")

        print("="*80)

    def check_alerts(self):
        print("\n" + "="*65)
        print(f" ALERT CHECK at {time.strftime('%H:%M:%S')}")
        print("="*65)

        processes = self.collector.collect_network_data()
        alerts = self.alert_manager.check_anomalies(processes)

        if alerts:
            for alert in alerts:
                print(f"  {alert}")
        else:
            print("  No alerts right now.")
        print("="*65)

    def show_ignore_list(self):
        ignored = self.ignore_list.get_all()
        print(f"Ignored processes ({len(ignored)} total):")
        for p in ignored:
            print(f"   • {p}")

    def add_to_ignore(self, arg: str):
        """Add process by name or by number from last status"""
        if not arg:
            print("Usage: add <name> or add <number>")
            return

        # Try to add by number
        if arg.isdigit():
            num = int(arg)
            if 1 <= num <= len(self.last_top_processes):
                process_name = self.last_top_processes[num-1][0]
                self.ignore_list.add(process_name)
            else:
                print(f"Error: Number {num} is out of range.")
        else:
            # Add by name
            self.ignore_list.add(arg)

    def remove_from_ignore(self, arg: str):
        """Remove process from ignore list by name or number"""
        if not arg:
            print("Usage: remove <name> or remove <number>")
            return

        if arg.isdigit():
            num = int(arg)
            if 1 <= num <= len(self.last_top_processes):
                process_name = self.last_top_processes[num-1][0]
                self.ignore_list.remove(process_name)
            else:
                print(f"Error: Number {num} is out of range.")
        else:
            self.ignore_list.remove(arg)


if __name__ == "__main__":
    app = MonitorApp()
    app.run()