# monitor.py - Command-driven quiet mode for debugging (final clean version)

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
        print("Command-Driven Quiet Mode activated.")
        print("All output only on command. No spam.\n")

        # Start background data collection
        threading.Thread(target=self.background_monitor, daemon=True).start()

        print("Available commands:")
        print("  status     → show system info + top processes")
        print("  alerts     → check anomalies now")
        print("  add <name> → add process to ignore list")
        print("  list       → show ignore list")
        print("  clear      → clear screen")
        print("  quit       → exit program\n")

        try:
            while self.running:
                cmd = input("> ").strip()

                if cmd.lower() == "quit":
                    break

                elif cmd.lower() == "status":
                    self.show_status()

                elif cmd.lower() == "alerts":
                    self.check_alerts()

                elif cmd.lower() == "list":
                    self.show_ignore_list()

                elif cmd.startswith("add "):
                    process_name = cmd[4:].strip()
                    if process_name:
                        self.ignore_list.add(process_name)
                        print(f"✓ Added to ignore list: {process_name}")

                elif cmd.lower() == "clear":
                    print("\n" * 40)

                else:
                    print("Unknown command. Use: status, alerts, add <name>, list, clear, quit")

        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            print("\nProgram stopped.")

    def show_status(self):
        print("\n" + "="*75)
        print(f" STATUS at {time.strftime('%H:%M:%S')}")
        print("="*75)

        sys_data = metrics.get_all_metrics()
        temp_str = f"{sys_data['cpu_temp']}°C" if sys_data['cpu_temp'] is not None else "N/A"

        print(f"CPU Usage : {sys_data['cpu_percent']:5.1f}%")
        print(f"RAM Usage : {sys_data['ram_percent']:5.1f}%")
        print(f"CPU Temp  : {temp_str}")
        print("-" * 75)

        print("TOP ACTIVE PROCESSES:")
        top = self.collector.get_top_processes(limit=12)
        for i, (name, data) in enumerate(top, 1):
            conn = data["connections"]
            ips = len(data["unique_ips"])
            color = "\033[91m" if conn > 25 else "\033[93m" if conn > 12 else "\033[92m"
            reset = "\033[0m"
            print(f"  {i:2}. {color}{name:<25}{reset} | 🔗 {conn:3} conn | 🌐 {ips:3} IPs")
        print("="*75)

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
        print(f"Ignored processes ({len(ignored)}):")
        for p in ignored:
            print(f"   • {p}")


if __name__ == "__main__":
    app = MonitorApp()
    app.run()