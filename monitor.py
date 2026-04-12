# monitor.py - Main application with System Tray

import os
import time
import threading
import sys
import json
import psutil
import socket
from collections import defaultdict
from core.metrics import metrics
from core.network_collector import NetworkCollector
from core.alert_manager import AlertManager
from core.ignore_list import IgnoreList
from core.display import print_startup_info
from tray.tray_manager import TrayManager
from api.server import run_api_server


class MonitorApp:
    def __init__(self):
        self.ignore_list = IgnoreList()
        self.collector = NetworkCollector()
        self.alert_manager = AlertManager(self.ignore_list)
        self.running = True
        self.last_top_processes = []
        self.api_host = "0.0.0.0"
        self.api_port = 8765
        self.monitor_interval_sec = 2
        self.current_processes = {}
        self.live_feed = []
        self.live_feed_seen = set()
        self.live_feed_limit = 40
        self.live_feed_ttl_sec = 300
        self.live_feed_revision = 0
        self.risk_memory = {}
        self.risk_ttl_sec = 90
     

    def background_monitor(self):
        """Silent background thread"""
        while self.running:
            try:
                now = time.time()
                processes = self.collector.collect_network_data()
                self.current_processes = processes
                alerts = self.alert_manager.check_anomalies(processes)
                self._store_live_alerts(alerts, now=now)
                self._refresh_risks_snapshot(processes=processes, now=now)
            except Exception:
                pass
            time.sleep(self.monitor_interval_sec)

    def _store_live_alerts(self, new_items, now=None):
        """Update in-memory live alert feed from freshly detected items."""
        now = now if isinstance(now, (int, float)) else time.time()

        for item in new_items:
            if not isinstance(item, dict):
                continue

            key = item.get("event_key") or (
                f"{item.get('type')}|{item.get('process')}|{item.get('pid')}|"
                f"{item.get('remote_ip')}|{item.get('remote_port')}|{item.get('ts')}"
            )
            if key in self.live_feed_seen:
                continue

            self.live_feed_revision += 1
            item["_rev"] = self.live_feed_revision
            self.live_feed_seen.add(key)
            self.live_feed.append(item)

        fresh_items = []
        fresh_seen = set()

        for item in self.live_feed:
            ts = item.get("ts", now)
            if not isinstance(ts, (int, float)):
                continue
            if (now - ts) > self.live_feed_ttl_sec:
                continue

            key = item.get("event_key") or (
                f"{item.get('type')}|{item.get('process')}|{item.get('pid')}|"
                f"{item.get('remote_ip')}|{item.get('remote_port')}|{item.get('ts')}"
            )
            if key in fresh_seen:
                continue

            fresh_seen.add(key)
            fresh_items.append(item)

        fresh_items.sort(key=lambda x: x.get("ts", 0), reverse=True)
        self.live_feed = fresh_items[: self.live_feed_limit]
        self.live_feed_seen = {
            item.get("event_key")
            or (
                f"{item.get('type')}|{item.get('process')}|{item.get('pid')}|"
                f"{item.get('remote_ip')}|{item.get('remote_port')}|{item.get('ts')}"
            )
            for item in self.live_feed
        }

    def build_live_alerts_feed(self, since_rev=None):
        """Return recent live alerts already collected by background monitoring."""
        self._store_live_alerts([], now=time.time())
        items = list(self.live_feed)
        if isinstance(since_rev, int) and since_rev > 0:
            items = [item for item in items if item.get("_rev", 0) > since_rev]
        return {
            "revision": self.live_feed_revision,
            "items": items,
        }

    def _refresh_risks_snapshot(self, processes=None, now=None):
        from core.threat_engine import threat_engine
        import psutil

        now = now if isinstance(now, (int, float)) else time.time()
        processes = processes if isinstance(processes, dict) else self.current_processes or self.collector.collect_network_data()
        current_risks = {}
        severity_rank = {"INFO": 1, "WARN": 2, "CRITICAL": 3}
        noisy_processes = {"System Idle Process", "System"}

        for conn in psutil.net_connections(kind="inet4"):
            if conn.pid is None:
                continue

            try:
                name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            if name in noisy_processes:
                continue

            remote_ip = getattr(conn.raddr, "ip", None) if conn.raddr else None
            remote_port = getattr(conn.raddr, "port", None) if conn.raddr else None

            flags = threat_engine.analyze_connection(name, remote_ip, remote_port)
            if not flags:
                continue

            severity = "INFO"
            reason = flags[0]["reason"]

            for f in flags:
                if f["severity"] == "CRITICAL":
                    severity = "CRITICAL"
                    reason = f["reason"]
                    break
                elif f["severity"] == "WARN" and severity != "CRITICAL":
                    severity = "WARN"
                    reason = f["reason"]

            if severity == "INFO":
                continue

            proc_key = (conn.pid, name)
            process_data = processes.get(name, {})
            item = current_risks.get(proc_key)
            if item is None:
                item = {
                    "process": name,
                    "pid": conn.pid,
                    "connections": process_data.get("connections", 0),
                    "severity": severity,
                    "risk_count": 0,
                    "risky_ips": set(),
                    "top_reason": reason,
                    "last_seen_ts": now,
                }
                current_risks[proc_key] = item

            item["connections"] = process_data.get("connections", item["connections"])
            item["risk_count"] += 1
            item["last_seen_ts"] = now

            if remote_ip:
                item["risky_ips"].add(remote_ip)

            if severity_rank[severity] > severity_rank[item["severity"]]:
                item["severity"] = severity
                item["top_reason"] = reason
            elif severity == item["severity"] and item["top_reason"] == "NORMAL":
                item["top_reason"] = reason

        # Refresh session memory with current risks and keep recent ones for a short time
        for proc_key, item in current_risks.items():
            self.risk_memory[proc_key] = item

        expired = []
        for proc_key, item in self.risk_memory.items():
            if (now - item.get("last_seen_ts", now)) > self.risk_ttl_sec:
                expired.append(proc_key)

        for proc_key in expired:
            self.risk_memory.pop(proc_key, None)

    def build_risks_snapshot(self):
        self._refresh_risks_snapshot(now=time.time())
        severity_rank = {"INFO": 1, "WARN": 2, "CRITICAL": 3}
        items = []
        for item in self.risk_memory.values():
            items.append(
                {
                    "process": item["process"],
                    "pid": item["pid"],
                    "connections": item["connections"],
                    "severity": item["severity"],
                    "risk_count": item["risk_count"],
                    "risky_ips_count": len(item["risky_ips"]),
                    "top_reason": item["top_reason"],
                    "last_seen_ts": item["last_seen_ts"],
                }
            )

        items.sort(
            key=lambda x: (
                severity_rank.get(x["severity"], 0),
                x["connections"],
                x["risk_count"],
                x["last_seen_ts"],
            ),
            reverse=True,
        )
        return items

    def build_alerts_stats_summary(self):
        """Return compact alert-center stats for the UI."""
        stats = self.alert_manager.get_alert_stats()
        risks = self.build_risks_snapshot()
        total_connections = sum(
            data.get("connections", 0) for data in self.current_processes.values()
        )

        recent_live = self.live_feed[0] if self.live_feed else None
        recent_critical = next((item for item in self.live_feed if item.get("severity") == "CRITICAL"), None)

        return {
            "last_hour": stats.get("last_hour", {}),
            "last_day": stats.get("last_day", {}),
            "active_total": len(self.alert_manager.active_alert_keys),
            "live_feed_total": len(self.live_feed),
            "live_revision": self.live_feed_revision,
            "processes_with_network": len(self.current_processes),
            "connections_total": total_connections,
            "risk_total": len(risks),
            "risk_critical": sum(1 for item in risks if item.get("severity") == "CRITICAL"),
            "risk_warn": sum(1 for item in risks if item.get("severity") == "WARN"),
            "last_alert": {
                "severity": recent_live.get("severity"),
                "process": recent_live.get("process"),
                "type": recent_live.get("type"),
                "ts": recent_live.get("ts"),
            } if recent_live else None,
            "last_critical": {
                "process": recent_critical.get("process"),
                "type": recent_critical.get("type"),
                "ts": recent_critical.get("ts"),
            } if recent_critical else None,
        }


    def start_api(self):
        """Start HTTP API in a background daemon thread using shared app state."""
        def _api_runner():
            try:
                run_api_server(host=self.api_host, port=self.api_port, app=self)
            except Exception as exc:
                print(f"[WARN] API server failed to start: {exc}")

        threading.Thread(target=_api_runner, daemon=True).start()

    def run(self):
        print_startup_info()
        print("Starting NetOpenWatchPi with System Tray...\n")

        threading.Thread(target=self.background_monitor, daemon=True).start()
        self.start_api()

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
                elif cmd in ["threats", "threats info"]:
                    self.show_threats()
                elif cmd == "stats":
                    self.show_stats()
                elif cmd == "risks":
                    self.show_risks()
                elif cmd.startswith("processinfo "):
                    _, name = raw_cmd.split(" ", 1)
                    self.process_info(name.strip())
                elif cmd.startswith("pidinfo "):
                    _, pid = raw_cmd.split(" ", 1)
                    self.process_info(pid.strip())
                elif cmd == "temps":
                    temps = metrics.get_hardware_info().get("temperatures", {})
                    self._print_temps_info(temps)
                elif cmd == "hwinfo":
                    hw = metrics.get_hardware_info()
                    self._print_hwinfo(hw)
                elif cmd == "alerts":
                    self.check_alerts()
                elif cmd == "alertswatch":
                    self.alerts_watch()
                elif cmd.startswith("alertswatch "):
                    _, raw_interval = raw_cmd.split(" ", 1)
                    self.alerts_watch(raw_interval.strip())
                elif cmd == "alertslog":
                    self.show_alerts_log()
                elif cmd.startswith("alertslog "):
                    _, raw_limit = raw_cmd.split(" ", 1)
                    self.show_alerts_log(raw_limit.strip())
                elif cmd in ["list", "ignore"]:
                    self.show_ignore_list()
                elif cmd.startswith("add "):
                    _, value = raw_cmd.split(" ", 1)
                    self.add_ignore(value.strip())
                elif cmd.startswith("remove "):
                    _, value = raw_cmd.split(" ", 1)
                    self.remove_ignore(value.strip())
                elif cmd == "clear":
                    os.system("cls" if os.name == "nt" else "clear")
                elif cmd == "gui":
                    self.open_gui()
                elif cmd == "help":
                    self.show_help()
                elif cmd == "permdiag":
                    self.permissions_diag()
                else:
                    print("Unknown command. Type 'help'.")
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            print("\nProgram stopped.")

    def show_threats(self):
        from core.threat_engine import threat_engine

        print("\n" + "=" * 80)
        print(f" THREAT DATABASE & WHITELIST at {time.strftime('%H:%M:%S')}")
        print("=" * 80)

        print("MALICIOUS IPs:")
        for ip in threat_engine.threats.get("malicious_ips", []):
            print(f"  - {ip}")

        print("\nSUSPICIOUS PORTS:")
        print("  " + ", ".join(map(str, threat_engine.threats.get("suspicious_ports", []))))

        print("\nKNOWN MALWARE PROCESSES:")
        for p in threat_engine.threats.get("known_malware_processes", []):
            print(f"  - {p}")

        print("\nWHITELIST - TRUSTED PROCESSES:")
        for p in threat_engine.whitelist.get("trusted_processes", []):
            print(f"  - {p}")

        print("\nWHITELIST - TRUSTED IPs:")
        for ip in threat_engine.whitelist.get("trusted_ips", []):
            print(f"  - {ip}")
        print("=" * 80)

        print()
    def show_risks(self):
        """Show global risk summary for all active network processes"""
        from core.threat_engine import threat_engine
        from collections import defaultdict
        import psutil

        print("\n" + "=" * 90)
        print(" GLOBAL RISK SUMMARY - ALL ACTIVE CONNECTIONS")
        print("=" * 90)

        processes = self.collector.collect_network_data()

        total_critical = 0
        total_warn = 0
        total_info = 0
        risky_found = False

        for name, data in sorted(processes.items(), key=lambda x: x[1]["connections"], reverse=True):
            if data["connections"] == 0:
                continue

            conn_list = []
            has_risk = False

            seen = set()

            for conn in psutil.net_connections(kind="inet4"):
                if conn.pid is None:
                    continue
                try:
                    pname = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                if pname != name:
                    continue

                remote_ip = getattr(conn.raddr, "ip", None) if conn.raddr else None
                remote_port = getattr(conn.raddr, "port", None) if conn.raddr else None

                if remote_ip is None or (name, remote_ip) in seen:
                    continue
                seen.add((name, remote_ip))

                flags = threat_engine.analyze_connection(name, remote_ip, remote_port)

                severity = "INFO"
                reason = "NORMAL"
                for f in flags:
                    if f["severity"] == "CRITICAL":
                        severity = "CRITICAL"
                        reason = f["reason"]
                        break
                    elif f["severity"] == "WARN" and severity != "CRITICAL":
                        severity = "WARN"
                        reason = f["reason"]

                if severity == "CRITICAL":
                    total_critical += 1
                elif severity == "WARN":
                    total_warn += 1
                else:
                    total_info += 1

                if severity != "INFO" or data["connections"] > 10:
                    has_risk = True
                    ip_str = remote_ip if remote_ip else "N/A"
                    conn_list.append(f"  - {ip_str:<18} -> {severity:8}  {reason}")

            if has_risk or data["connections"] >= 5:
                color = "\033[91m" if total_critical > 0 else "\033[93m" if total_warn > 0 else "\033[92m"
                reset = "\033[0m"
                print(f"\n{color}{name}{reset}  ({data['connections']} connections)")

                if conn_list:
                    for line in conn_list:
                        print(line)
                else:
                    print("  - All connections NORMAL")

                risky_found = True

        if not risky_found:
            print("\nNo risky connections detected at the moment.")
            print("All active processes look clean.")

        print("\n" + "-" * 90)
        print(f"TOTAL RISK COUNT -> CRITICAL: {total_critical} | WARN: {total_warn} | INFO: {total_info}")
        print("=" * 90)

    def show_stats(self):
        stats = self.alert_manager.get_alert_stats()
        print("\n" + "=" * 60)
        print(" ALERT STATISTICS")
        print("=" * 60)
        print(f"Last hour : INFO={stats['last_hour'].get('INFO',0)}  WARN={stats['last_hour'].get('WARN',0)}  CRITICAL={stats['last_hour'].get('CRITICAL',0)}")
        print(f"Last day  : INFO={stats['last_day'].get('INFO',0)}  WARN={stats['last_day'].get('WARN',0)}  CRITICAL={stats['last_day'].get('CRITICAL',0)}")
        print("=" * 60)

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

        sorted_stats = sorted(
            proc_stats.items(),
            key=lambda item: item[1]["connections"],
            reverse=True,
        )

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

    def hardware_info(self):
        print("\n" + "=" * 80)
        print(f" HARDWARE INFO at {time.strftime('%H:%M:%S')}")
        print("=" * 80)
        print(metrics.get_hardware_info())

    def cpu_temps(self):
        print("\n" + "=" * 80)
        print(f" CPU TEMPERATURES at {time.strftime('%H:%M:%S')}")
        print("=" * 80)
        temps = metrics.get_hardware_info().get("temperatures", {})
        self._print_temps_info(temps)

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

        # System
        print("SYSTEM")
        print(f"  OS           : {system.get('os', 'N/A')} {system.get('os_release', '')}")
        print(f"  Hostname     : {system.get('hostname', 'N/A')}")
        print(f"  Machine      : {system.get('machine', 'N/A')}")
        print(f"  Processor    : {system.get('processor', 'N/A')}")
        print(f"  Uptime (sec) : {system.get('uptime_sec', 'N/A')}")
        print("-" * 80)

        # CPU
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

        # Memory
        print("MEMORY")
        print(f"  RAM          : {ram.get('used_mb', 'N/A')} / {ram.get('total_mb', 'N/A')} MB ({ram.get('percent', 'N/A')}%)")
        print(f"  RAM Avail    : {ram.get('available_mb', 'N/A')} MB")
        print(f"  SWAP         : {swap.get('used_mb', 'N/A')} / {swap.get('total_mb', 'N/A')} MB ({swap.get('percent', 'N/A')}%)")
        print("-" * 80)

        # Disk
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

        # Network
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

        # GPU
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

        # Temperatures
        print("TEMPERATURES")
        print(f"  CPU Temp     : {temps.get('cpu_temp_c', 'N/A')}")
        print(f"  GPU Temp     : {temps.get('gpu_temp_c', 'N/A')}")
        print(f"  Source       : {temps.get('source', 'N/A')}")
        print("=" * 80)

    def _print_temps_info(self, temps):
        """Compact temperatures output for `temps` command."""
        cpu_temp = temps.get("cpu_temp_c", None)
        gpu_temp = temps.get("gpu_temp_c", None)
        source = temps.get("source", "none")

        print("\n" + "=" * 80)
        print(f" TEMPERATURES at {time.strftime('%H:%M:%S')}")
        print("=" * 80)
        print(f"CPU Temp  : {cpu_temp if cpu_temp is not None else 'N/A'}")
        print(f"GPU Temp  : {gpu_temp if gpu_temp is not None else 'N/A'}")
        print(f"Source    : {source}")
        print("=" * 80)


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
                if isinstance(alert, dict):
                    event_time = time.strftime("%H:%M:%S", time.localtime(alert["ts"]))

                    proc = alert.get("process", "N/A")
                    pid = alert.get("pid")
                    ip = alert.get("remote_ip")
                    port = alert.get("remote_port")

                    extra = []
                    if pid is not None:
                        extra.append(f"pid={pid}")
                    if ip:
                        extra.append(f"ip={ip}")
                    if port:
                        extra.append(f"port={port}")
                    extra_str = f" ({', '.join(extra)})" if extra else ""

                    print(
                        f"[{alert.get('severity','INFO')}] "
                        f"[{event_time}] "
                        f"{alert.get('type','event')} -> {proc}{extra_str} | "
                        f"{alert.get('reason','')}"
                    )
                else:
                    print(f"  {alert}")
        else:
            print("  No alerts right now.")
        print("=" * 65)

    def alerts_watch(self, interval=2):
        """Realtime alerts watcher. Stop with Ctrl+C."""
        try:
            sec = float(interval)
            if sec <= 0:
                raise ValueError
        except (TypeError, ValueError):
            print("Usage: alertswatch [seconds], where seconds > 0 (example: alertswatch 2)")
            return

        print("\n" + "=" * 80)
        print(f" ALERT WATCH started at {time.strftime('%H:%M:%S')} (interval={sec}s)")
        print(" Press Ctrl+C to stop.")
        print("=" * 80)

        errors_in_row = 0
        last_idle_print = 0.0

        try:
            while True:
                try:
                    processes = self.collector.collect_network_data()
                    alerts = self.alert_manager.check_anomalies(processes)
                    errors_in_row = 0
                except Exception as exc:
                    errors_in_row += 1
                    print(
                        f"[WARN] [{time.strftime('%H:%M:%S')}] watch_cycle_error "
                        f"-> collector | {type(exc).__name__}: {exc}"
                    )
                    # Small backoff on repeated runtime errors.
                    time.sleep(min(sec * max(errors_in_row, 1), 5.0))
                    continue

                for alert in alerts:
                    if not isinstance(alert, dict):
                        print(f"  {alert}")
                        continue

                    event_time = time.strftime("%H:%M:%S", time.localtime(alert["ts"]))
                    proc = alert.get("process", "N/A")
                    pid = alert.get("pid")
                    ip = alert.get("remote_ip")
                    port = alert.get("remote_port")
                    extra = []
                    if pid is not None:
                        extra.append(f"pid={pid}")
                    if ip:
                        extra.append(f"ip={ip}")
                    if port:
                        extra.append(f"port={port}")
                    extra_str = f" ({', '.join(extra)})" if extra else ""

                    print(
                        f"[{alert.get('severity','INFO')}] "
                        f"[{event_time}] "
                        f"{alert.get('type','event')} -> {proc}{extra_str} | "
                        f"{alert.get('reason','')}"
                    )

                # Keep watch mode "alive" even when no new alerts.
                if not alerts:
                    now = time.time()
                    if (now - last_idle_print) >= max(sec * 5, 5):
                        print(f"[INFO] [{time.strftime('%H:%M:%S')}] no_new_alerts")
                        last_idle_print = now

                time.sleep(sec)
        except KeyboardInterrupt:
            print("\nALERT WATCH stopped.")

    def show_ignore_list(self):
        ignored = self.ignore_list.get_all()
        print(f"Ignored processes ({len(ignored)}):")
        for p in ignored:
            print(f"  - {p}")

    def show_alerts_log(self, limit=20):
        """Show last N alerts from JSONL log."""
        try:
            n = int(limit)
            if n <= 0:
                raise ValueError
        except (TypeError, ValueError):
            print("Usage: alertslog [N], where N is a positive number.")
            return

        log_path = os.path.join("logs", "alerts.jsonl")
        if not os.path.exists(log_path):
            print("No alert log file yet.")
            return

        try:
            with open(log_path, "r", encoding="utf-8") as f:
                lines = [ln.strip() for ln in f if ln.strip()]
        except Exception as exc:
            print(f"Failed to read alert log: {exc}")
            return

        if not lines:
            print("Alert log is empty.")
            return

        print("\n" + "=" * 100)
        print(f" ALERT LOG (last {n}) at {time.strftime('%H:%M:%S')}")
        print("=" * 100)

        shown = 0
        for row in lines[-n:]:
            try:
                alert = json.loads(row)
            except Exception:
                continue

            ts = alert.get("ts")
            if isinstance(ts, (int, float)):
                event_time = time.strftime("%H:%M:%S", time.localtime(ts))
            else:
                event_time = "N/A"

            proc = alert.get("process", "N/A")
            sev = alert.get("severity", "INFO")
            typ = alert.get("type", "event")
            reason = alert.get("reason", "")

            pid = alert.get("pid")
            ip = alert.get("remote_ip")
            port = alert.get("remote_port")
            extra = []
            if pid is not None:
                extra.append(f"pid={pid}")
            if ip:
                extra.append(f"ip={ip}")
            if port:
                extra.append(f"port={port}")
            extra_str = f" ({', '.join(extra)})" if extra else ""

            print(f"[{sev}] [{event_time}] {typ} -> {proc}{extra_str} | {reason}")
            shown += 1

        if shown == 0:
            print("No valid JSON entries found in alert log.")
        print("=" * 100)

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

    def permissions_diag(self):
        print("\n" + "=" * 80)
        print(f" PERMISSIONS DIAG at {time.strftime('%H:%M:%S')}")
        print("=" * 80)

        try:
            import ctypes
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_admin = False

        conns = psutil.net_connections(kind="inet")
        total = len(conns)
        no_pid = sum(1 for c in conns if c.pid is None)
        with_pid = total - no_pid
        external_total = sum(1 for c in conns if c.raddr)
        external_with_pid = sum(1 for c in conns if c.raddr and c.pid is not None)

        print(f"Admin mode           : {is_admin}")
        print(f"Total inet sockets   : {total}")
        print(f"With PID             : {with_pid}")
        print(f"Without PID          : {no_pid}")
        print(f"External sockets     : {external_total}")
        print(f"External with PID    : {external_with_pid}")
        print("=" * 80)


    def process_info(self, name_or_pid):
        """Show detailed info for specific process by name or PID + risk flags"""
        print("\n" + "=" * 100)
        print(f" PROCESS INFO + RISK ANALYSIS for '{name_or_pid}' at {time.strftime('%H:%M:%S')}")
        print("=" * 100)

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
        risk_summary = defaultdict(list)

        from core.threat_engine import threat_engine

        for c in psutil.net_connections(kind="inet4"):
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

            remote_ip = getattr(c.raddr, "ip", None) if c.raddr else None
            remote_port = getattr(c.raddr, "port", None) if c.raddr else None

            # === RISK ANALYSIS ===
            flags = threat_engine.analyze_connection(pname, remote_ip, remote_port)

            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            state = c.status or "-"
            local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
            remote = f"{remote_ip}:{remote_port}" if remote_ip else "-"

            matched_rows.append((c.pid, pname, proto, state, local, remote, flags))

            matched_pids.add(c.pid)
            matched_names.add(pname)
            protocols[proto] += 1
            states[state] = states.get(state, 0) + 1
            if remote_ip:
                unique_ips.add(remote_ip)

            # summarize risk reasons by severity for summary section
            for f in flags:
                risk_summary[f["severity"]].append(f["reason"])

        if not matched_rows:
            print("Process not found or has no inet connections.")
            return

        # === BASIC INFO ===
        print(f"Name(s)      : {', '.join(sorted(matched_names))}")
        print(f"PID(s)       : {', '.join(str(p) for p in sorted(matched_pids))}")
        print(f"Connections  : {len(matched_rows)}")
        print(f"Unique IPs   : {len(unique_ips)}")
        print(f"Protocols    : TCP={protocols['TCP']} UDP={protocols['UDP']}")
        print("States       : " + ", ".join(f"{k}={v}" for k, v in sorted(states.items())))

        print("-" * 100)

        # === RISK FLAGS SUMMARY ===
        print("RISK FLAGS SUMMARY:")
        for severity in ["CRITICAL", "WARN", "INFO"]:
            if severity in risk_summary:
                reasons = sorted(set(risk_summary[severity]))
                color = "\033[91m" if severity == "CRITICAL" else "\033[93m" if severity == "WARN" else "\033[92m"
                reset = "\033[0m"
                print(f"  {color}{severity:8} -> {', '.join(reasons)}{reset}")

        print("-" * 100)

        # === DETAILED TABLE ===
        print(f"{'PID':<8} {'Proto':<6} {'State':<13} {'Local':<30} {'Remote':<35} {'Risk Flags'}")
        print("-" * 120)

        matched_rows.sort(key=lambda row: (row[0], row[2], row[3], row[4], row[5]))

        for pid, pname, proto, state, local, remote, flags in matched_rows:
            risk_str = " | ".join([f["reason"] for f in flags])
            print(f"{pid:<8} {proto:<6} {state:<13} {local:<30} {remote:<35} {risk_str}")

        print("=" * 100)

    def show_help(self):
        """Show help message with available commands"""
        print("\n" + "=" * 60)
        print(" AVAILABLE COMMANDS")
        print("=" * 60)
        print("  status                     show system metrics + top list")
        print("  top                        show top processes")
        print("  network processes          show external connections summary")
        print("  threats                    show current threat database and whitelist")
        print("  risks                      show global risk summary for all active connections")
        print("  stats                      show alert statistics")
        print("  processinfo <name.exe>     show connections for process name")
        print("  pidinfo <pid>              show connections for exact PID")
        print("  temps                      show CPU temperature (if available)")
        print("  hwinfo                     show hardware information")
        print("  alerts                     run anomaly check now")
        print("  alertswatch [sec]          realtime alerts stream (Ctrl+C to stop)")
        print("  alertslog [N]              show last N alerts from log file")
        print("  list | ignore              show ignore list")
        print("  add <name|number>          add ignore by process name or top index")
        print("  remove <name>              remove ignore by process name")
        print("  gui                        open GUI window")
        print("  permdiag                   show socket/permissions diagnostics")
        print("  clear                      clear terminal")
        print("  help                       show this help message")
        print("  quit                       exit program")
        print("=" * 60)


if __name__ == "__main__":
    app = MonitorApp()
    app.run()
