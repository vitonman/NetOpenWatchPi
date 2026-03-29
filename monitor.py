# monitor.py - Main application with System Tray

import os
import time
import threading
import psutil
import socket

from core.metrics import metrics
from core.network_collector import NetworkCollector
from core.alert_manager import AlertManager
from core.ignore_list import IgnoreList
from core.display import print_startup_info
from tray.tray_manager import TrayManager


class MonitorApp:
    def __init__(self):
        self.ignore_list = IgnoreList()
        self.collector = NetworkCollector()
        self.alert_manager = AlertManager(self.ignore_list)
        self.running = True
        self.last_top_processes = []

    def background_monitor(self):
        """Silent background thread"""
        while self.running:
            try:
                self.collector.collect_network_data()
            except Exception:
                pass
            time.sleep(2)

    def _parse_arg(self, raw_cmd: str, usage: str):
        parts = raw_cmd.split(maxsplit=1)
        if len(parts) < 2 or not parts[1].strip():
            print(f"Usage: {usage}")
            return None
        return parts[1].strip()

    def run(self):
        print_startup_info()
        print("Starting NetOpenWatchPi with System Tray...\n")

        threading.Thread(target=self.background_monitor, daemon=True).start()

        self.tray = TrayManager(self)
        self.tray.create_tray()
        self.tray.run()

        print("System Tray is active. Right-click the tray icon to open menu.")

        try:
            while self.running:
                raw_cmd = input("> ").strip()
                cmd = raw_cmd.lower()

                if cmd == "quit":
                    break
                elif cmd == "status":
                    self.show_status()
                elif cmd == "top":
                    self.top()
                elif cmd == "network processes":
                    self.network_processes_list()
                elif cmd.startswith("processinfo"):
                    arg = self._parse_arg(raw_cmd, "processinfo <name.exe>")
                    if arg is not None:
                        self.process_info(arg)
                elif cmd.startswith("pidinfo"):
                    arg = self._parse_arg(raw_cmd, "pidinfo <pid>")
                    if arg is not None:
                        self.process_info(arg)
                elif cmd == "hwinfo":
                    self._print_hwinfo(metrics.get_hardware_info())
                elif cmd == "cpuinfo":
                    self._print_cpu_info(metrics.get_hardware_info().get("cpu", {}))
                elif cmd == "raminfo":
                    hw = metrics.get_hardware_info()
                    self._print_memory_info(hw.get("ram", {}), hw.get("swap", {}))
                elif cmd == "diskinfo":
                    self._print_disk_info(metrics.get_hardware_info().get("disk", {}))
                elif cmd == "netinfo":
                    self._print_network_info(metrics.get_hardware_info().get("network", {}))
                elif cmd == "gpuinfo":
                    self._print_gpu_info(metrics.get_hardware_info().get("gpu", {}))
                elif cmd == "temps":
                    self._print_temps_info(metrics.get_hardware_info().get("temperatures", {}))
                elif cmd == "alerts":
                    self.check_alerts()
                elif cmd in ["list", "ignore"]:
                    self.show_ignore_list()
                elif cmd.startswith("add "):
                    arg = self._parse_arg(raw_cmd, "add <name|number>")
                    if arg is not None:
                        self.add_ignore(arg)
                elif cmd.startswith("remove "):
                    arg = self._parse_arg(raw_cmd, "remove <name>")
                    if arg is not None:
                        self.remove_ignore(arg)
                elif cmd == "clear":
                    os.system("cls" if os.name == "nt" else "clear")
                elif cmd == "gui":
                    self.open_gui()
                elif cmd == "help":
                    self.show_help()
                else:
                    print("Unknown command. Type 'help'.")
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            print("\nProgram stopped.")

    def show_status(self):
        print("\n" + "=" * 80)
        print(f" STATUS at {time.strftime('%H:%M:%S')}")
        print("=" * 80)

        sys_data = metrics.get_all_metrics()
        temp_str = f"{sys_data['cpu_temp']} C" if sys_data["cpu_temp"] is not None else "N/A"

        print(f"CPU Usage : {sys_data['cpu_percent']:5.1f}%")
        print(f"RAM Usage : {sys_data['ram_percent']:5.1f}%")
        print(f"CPU Temp  : {temp_str}")
        print("-" * 80)

        self.top(limit=10, with_header=False)
        print("=" * 80)

    def network_processes_list(self):
        print("\n" + "=" * 80)
        print(f" Processes with external connections at {time.strftime('%H:%M:%S')}")
        print("=" * 80)
        proc_stats = {}

        for conn in psutil.net_connections(kind="inet"):
            if conn.pid is None or not conn.raddr:
                continue

            remote_ip = getattr(conn.raddr, "ip", None)
            if not remote_ip:
                continue

            pid = conn.pid
            try:
                name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            key = (pid, name)
            if key not in proc_stats:
                proc_stats[key] = {"connections": 0, "unique_ips": set()}

            proc_stats[key]["connections"] += 1
            proc_stats[key]["unique_ips"].add(remote_ip)

        if not proc_stats:
            print("No active external connections found.")
            return

        sorted_stats = sorted(proc_stats.items(), key=lambda item: item[1]["connections"], reverse=True)

        for (pid, name), data in sorted_stats:
            ext_conn = data["connections"]
            ips = len(data["unique_ips"])
            color = "\033[91m" if ext_conn > 25 else "\033[93m" if ext_conn > 12 else "\033[92m"
            reset = "\033[0m"
            ignored_mark = " [IGNORED]" if self.ignore_list.contains(name) else ""
            print(f"  {color}{pid:<8}{name:<25}{reset}{ignored_mark} | {ext_conn:3} ext conn | {ips:3} IPs")

    def processes_count(self):
        print("\n" + "=" * 80)
        print(f" Processes count at {time.strftime('%H:%M:%S')}")
        print("=" * 80)

        processes = self.collector.collect_network_data()
        print(f"Total processes with network activity: {len(processes)}")

    def _print_hwinfo(self, hw):
        system = hw.get("system", {})
        cpu = hw.get("cpu", {})
        ram = hw.get("ram", {})
        swap = hw.get("swap", {})
        disk = hw.get("disk", {})
        network = hw.get("network", {})
        gpu = hw.get("gpu", {})
        temps = hw.get("temperatures", {})

        print("\n" + "=" * 80)
        print(f" HARDWARE INFO at {time.strftime('%H:%M:%S')}")
        print("=" * 80)

        self._print_system_info(system)
        self._print_cpu_info(cpu)
        self._print_memory_info(ram, swap)
        self._print_disk_info(disk)
        self._print_network_info(network)
        self._print_gpu_info(gpu)
        self._print_temps_info(temps)

        print("=" * 80)

    def _print_system_info(self, system):
        print("SYSTEM")
        print(f"  OS           : {system.get('os', 'N/A')} {system.get('os_release', '')}")
        print(f"  Hostname     : {system.get('hostname', 'N/A')}")
        print(f"  Machine      : {system.get('machine', 'N/A')}")
        print(f"  Processor    : {system.get('processor', 'N/A')}")
        print(f"  Uptime (sec) : {system.get('uptime_sec', 'N/A')}")
        print("-" * 80)

    def _print_cpu_info(self, cpu):
        freq = cpu.get("frequency_mhz", {})
        print("CPU")
        print(f"  Cores        : {cpu.get('physical_cores', 'N/A')} physical / {cpu.get('logical_cores', 'N/A')} logical")
        print(f"  Usage        : {cpu.get('usage_percent_total', 'N/A')} %")
        print(
            f"  Frequency    : current={freq.get('current', 'N/A')} MHz, "
            f"min={freq.get('min', 'N/A')} MHz, max={freq.get('max', 'N/A')} MHz"
        )
        per_core = cpu.get("usage_percent_per_core", [])
        if per_core:
            print("  Per-core     : " + ", ".join(f"{v:.1f}%" for v in per_core))
        print("-" * 80)

    def _print_memory_info(self, ram, swap):
        print("MEMORY")
        print(f"  RAM          : {ram.get('used_mb', 'N/A')} / {ram.get('total_mb', 'N/A')} MB ({ram.get('percent', 'N/A')}%)")
        print(f"  RAM Avail    : {ram.get('available_mb', 'N/A')} MB")
        print(f"  SWAP         : {swap.get('used_mb', 'N/A')} / {swap.get('total_mb', 'N/A')} MB ({swap.get('percent', 'N/A')}%)")
        print("-" * 80)

    def _print_disk_info(self, disk):
        print("DISK")
        parts = disk.get("partitions", [])
        if parts:
            for p in parts:
                print(
                    f"  {p.get('device', 'N/A')} ({p.get('fstype', 'N/A')}) "
                    f"{p.get('used_gb', 'N/A')} / {p.get('total_gb', 'N/A')} GB ({p.get('percent', 'N/A')}%)"
                )
        else:
            print("  N/A")
        print("-" * 80)

    def _print_network_info(self, network):
        print("NETWORK")
        io_total = network.get("io_total", {})
        if io_total:
            print(f"  Sent bytes   : {io_total.get('bytes_sent', 'N/A')}")
            print(f"  Recv bytes   : {io_total.get('bytes_recv', 'N/A')}")
            print(f"  Sent packets : {io_total.get('packets_sent', 'N/A')}")
            print(f"  Recv packets : {io_total.get('packets_recv', 'N/A')}")
        else:
            print("  N/A")
        print("-" * 80)

    def _print_gpu_info(self, gpu):
        print("GPU")
        devices = gpu.get("devices", [])
        if devices:
            for g in devices:
                print(f"  Name         : {g.get('name', 'N/A')} ({g.get('vendor', 'N/A')})")
                print(f"  Usage        : {g.get('usage_percent', 'N/A')} %")
                print(f"  Memory       : {g.get('memory_used_mb', 'N/A')} / {g.get('memory_total_mb', 'N/A')} MB")
                print(f"  Temperature  : {g.get('temperature_c', 'N/A')} C")
                print(f"  Source       : {g.get('source', 'N/A')}")
        else:
            print("  N/A")
        print("-" * 80)

    def _print_temps_info(self, temps):
        print("TEMPERATURES")
        print(f"  CPU Temp     : {temps.get('cpu_temp_c', 'N/A')}")
        print(f"  GPU Temp     : {temps.get('gpu_temp_c', 'N/A')}")
        print(f"  Source       : {temps.get('source', 'N/A')}")
        print("-" * 80)

    def top(self, limit=15, with_header=True):
        if with_header:
            print("\n" + "=" * 80)
            print(f" TOP at {time.strftime('%H:%M:%S')}")
            print("=" * 80)

        print("Top processes by network connections:")
        self.last_top_processes = self.collector.get_top_processes(limit=limit)

        for i, (name, data) in enumerate(self.last_top_processes, 1):
            conn = data["connections"]
            ips = len(data["unique_ips"])
            pid = data.get("pid", "N/A")
            color = "\033[91m" if conn > 25 else "\033[93m" if conn > 12 else "\033[92m"
            reset = "\033[0m"
            ignored_mark = " [IGNORED]" if self.ignore_list.contains(name) else ""
            print(f"  {i:2}. {color}{pid:<8}{name:<25}{reset}{ignored_mark} | {conn:3} conn | {ips:3} IPs")

        if with_header:
            print("=" * 80)

    def check_alerts(self):
        print("\n" + "=" * 65)
        print(f" ALERT CHECK at {time.strftime('%H:%M:%S')}")
        print("=" * 65)

        processes = self.collector.collect_network_data()
        alerts = self.alert_manager.check_anomalies(processes)

        if alerts:
            for alert in alerts:
                print(f"  {alert}")
        else:
            print("  No alerts right now.")
        print("=" * 65)

    def show_ignore_list(self):
        ignored = self.ignore_list.get_all()
        print(f"Ignored processes ({len(ignored)}):")
        for p in ignored:
            print(f"  - {p}")

    def add_ignore(self, value):
        """Add ignored process by name or by number from last TOP output."""
        if value.isdigit():
            idx = int(value)
            if not self.last_top_processes:
                print("No cached TOP list. Run 'top' first.")
                return
            if idx < 1 or idx > len(self.last_top_processes):
                print(f"Invalid number. Choose 1..{len(self.last_top_processes)}")
                return
            name = self.last_top_processes[idx - 1][0]
        else:
            name = value

        if self.ignore_list.add(name):
            print(f"Added: {name}")
        else:
            print(f"Already ignored or invalid: {name}")

    def remove_ignore(self, value):
        """Remove ignored process by name."""
        name = value
        if self.ignore_list.remove(name):
            print(f"Removed: {name}")
        else:
            print(f"Not in ignore list: {name}")

    def open_gui(self):
        """Open GUI window"""
        from gui.main_window import MainWindow

        gui = MainWindow(self)
        gui.create_window()

    def process_info(self, name_or_pid):
        """Show detailed info for specific process by name or PID"""
        print("\n" + "=" * 80)
        print(f" PROCESS INFO for '{name_or_pid}' at {time.strftime('%H:%M:%S')}")
        print("=" * 80)

        query = str(name_or_pid).strip()
        is_pid_query = query.isdigit()
        target_pid = int(query) if is_pid_query else None
        target_name = query.lower()

        matched_rows = []
        matched_pids = set()
        matched_names = set()
        protocols = {"TCP": 0, "UDP": 0}
        states = {}
        unique_ips = set()

        for c in psutil.net_connections(kind="inet"):
            if c.pid is None:
                continue

            try:
                pname = psutil.Process(c.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            if is_pid_query:
                if c.pid != target_pid:
                    continue
            else:
                if pname.lower() != target_name:
                    continue

            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            state = c.status or "-"
            local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
            remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"

            matched_rows.append((c.pid, pname, proto, state, local, remote))
            matched_pids.add(c.pid)
            matched_names.add(pname)
            protocols[proto] += 1
            states[state] = states.get(state, 0) + 1
            if c.raddr and getattr(c.raddr, "ip", None):
                unique_ips.add(c.raddr.ip)

        if not matched_rows:
            print("Process not found or has no inet connections.")
            return

        print(f"Name(s)      : {', '.join(sorted(matched_names))}")
        print(f"PID(s)       : {', '.join(str(p) for p in sorted(matched_pids))}")
        print(f"Connections  : {len(matched_rows)}")
        print(f"Unique IPs   : {len(unique_ips)}")
        print(f"Protocols    : TCP={protocols['TCP']} UDP={protocols['UDP']}")
        print("States       : " + ", ".join(f"{k}={v}" for k, v in sorted(states.items())))

        print("-" * 100)
        print(f"{'PID':<8} {'Proto':<6} {'State':<13} {'Local':<30} {'Remote':<30}")
        print("-" * 100)

        matched_rows.sort(key=lambda row: (row[0], row[2], row[3], row[4], row[5]))
        for pid, pname, proto, state, local, remote in matched_rows:
            print(f"{pid:<8} {proto:<6} {state:<13} {local:<30} {remote:<30}")

    def show_help(self):
        """Show help message with available commands"""
        print("\n" + "=" * 60)
        print(" AVAILABLE COMMANDS")
        print("=" * 60)
        print("  status                     show system metrics + top list")
        print("  top                        show top processes")
        print("  network processes          show external connections summary")
        print("  processinfo <name.exe>     show connections for process name")
        print("  pidinfo <pid>              show connections for exact PID")
        print("  hwinfo                     show full hardware overview")
        print("  cpuinfo                    show CPU info")
        print("  raminfo                    show RAM/SWAP info")
        print("  diskinfo                   show disk info")
        print("  netinfo                    show network info")
        print("  gpuinfo                    show GPU info")
        print("  temps                      show temperatures info")
        print("  alerts                     run anomaly check now")
        print("  list | ignore              show ignore list")
        print("  add <name|number>          add ignore by process name or top index")
        print("  remove <name>              remove ignore by process name")
        print("  gui                        open GUI window")
        print("  clear                      clear terminal")
        print("  help                       show this help message")
        print("  quit                       exit program")
        print("=" * 60)


if __name__ == "__main__":
    app = MonitorApp()
    app.run()
