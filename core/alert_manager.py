# core/alert_manager.py - Anomaly detection and alerts

import json
import os
import time
from collections import defaultdict
from typing import Dict, List, Optional

from core.threat_engine import threat_engine


class AlertManager:
    """Detects suspicious network activity and generates structured alert events."""

    def __init__(self, ignore_list):
        self.last_alert_time = {}
        self.alert_cooldown = 15
        self.ignore_list = ignore_list

        # Per-alert-type cooldown policy
        self.alert_cooldown_by_type = {
            "high_connections": 15,
            "many_unique_ips": 15,
            "heavy_traffic": 15,
            "new_process_on_network": 120,
            "new_remote_ip_for_process": 120,
            "watchlist_ip_match": 30,
            "suspicious_port": 30,
            "known_malware_process": 10,
        }

        # Session memory
        self.seen_processes = set()
        self.seen_remote_ip_by_process = defaultdict(set)

        # Previous cycle snapshot for diff/spike rules
        self.prev_snapshot = {}

        # Alert counters (rolling hour/day)
        self.stats_hour = defaultdict(int)
        self.stats_day = defaultdict(int)
        self.last_hour_reset = time.time()
        self.last_day_reset = time.time()
        self.alert_log_path = "logs/alerts.jsonl"
        self.state_path = "logs/alert_state.json"
        self.active_alert_keys = set()
        self._load_state()

    def _rotate_stats_windows(self, now: float) -> None:
        if now - self.last_hour_reset > 3600:
            self.stats_hour = defaultdict(int)
            self.last_hour_reset = now

        if now - self.last_day_reset > 86400:
            self.stats_day = defaultdict(int)
            self.last_day_reset = now

    def _make_event_key(
        self,
        event_type: str,
        process: str,
        pid: Optional[int] = None,
        remote_ip: Optional[str] = None,
        remote_port: Optional[int] = None,
    ) -> str:
        return f"{event_type}|{process}|{pid}|{remote_ip}|{remote_port}"

    def _load_state(self) -> None:
        """Load persisted runtime state to reduce startup noise."""
        try:
            if not os.path.exists(self.state_path):
                return

            with open(self.state_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.seen_processes = set(data.get("seen_processes", []))

            loaded_seen_ip = data.get("seen_remote_ip_by_process", {})
            self.seen_remote_ip_by_process = defaultdict(set)
            for proc, ips in loaded_seen_ip.items():
                self.seen_remote_ip_by_process[proc] = set(ips or [])

            self.active_alert_keys = set(data.get("active_alert_keys", []))
        except Exception:
            # State load issues should not break monitoring
            pass

    def _save_state(self) -> None:
        """Persist runtime state between restarts."""
        try:
            os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
            data = {
                "seen_processes": sorted(self.seen_processes),
                "seen_remote_ip_by_process": {
                    proc: sorted(list(ips))
                    for proc, ips in self.seen_remote_ip_by_process.items()
                },
                "active_alert_keys": sorted(self.active_alert_keys),
            }
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            # State save issues should not break monitoring
            pass

    def emit_event(
        self,
        event_type: str,
        severity: str,
        process: str,
        pid: Optional[int] = None,
        remote_ip: Optional[str] = None,
        remote_port: Optional[int] = None,
        reason: str = "",
    ) -> Optional[Dict]:
        now = time.time()
        event_key = self._make_event_key(event_type, process, pid, remote_ip, remote_port)
        cooldown = self.alert_cooldown_by_type.get(event_type, self.alert_cooldown)

        last_ts = self.last_alert_time.get(event_key)
        if last_ts is not None and (now - last_ts) < cooldown:
            return None

        self.last_alert_time[event_key] = now

        self._rotate_stats_windows(now)

        sev = severity.upper()
        self.stats_hour[sev] += 1
        self.stats_day[sev] += 1

        event = {
            "type": event_type,
            "severity": sev,
            "process": process,
            "pid": pid,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "reason": reason,
            "ts": now,
            "event_key": event_key,
        }
        self._append_alert_log(event)
        return event

    def get_alert_stats(self) -> Dict:
        """Return rolling alert counters."""
        now = time.time()
        self._rotate_stats_windows(now)
        return {
            "last_hour": dict(self.stats_hour),
            "last_day": dict(self.stats_day),
        }

    def _append_alert_log(self, event: Dict) -> None:
        """Append one alert event as JSONL row."""
        try:
            os.makedirs(os.path.dirname(self.alert_log_path), exist_ok=True)
            with open(self.alert_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:
            # Logging must never break monitoring runtime
            pass

    def check_anomalies(self, processes: Dict) -> List[Dict]:
        """Check suspicious behavior and return structured alert events."""
        alerts: List[Dict] = []
        current_active_keys = set()
        state_changed = False

        malware_list = {p.lower() for p in threat_engine.threats.get("known_malware_processes", [])}
        suspicious_ports = set(threat_engine.threats.get("suspicious_ports", []))

        def raise_stateful_alert(
            event_type: str,
            severity: str,
            process: str,
            pid: Optional[int] = None,
            remote_ip: Optional[str] = None,
            remote_port: Optional[int] = None,
            reason: str = "",
        ) -> None:
            nonlocal state_changed
            key = self._make_event_key(event_type, process, pid, remote_ip, remote_port)
            current_active_keys.add(key)
            if key in self.active_alert_keys:
                return

            event = self.emit_event(
                event_type=event_type,
                severity=severity,
                process=process,
                pid=pid,
                remote_ip=remote_ip,
                remote_port=remote_port,
                reason=reason,
            )
            if event:
                alerts.append(event)
                state_changed = True

        def parse_event_key(event_key: str):
            parts = event_key.split("|", 4)
            if len(parts) != 5:
                return None
            etype, proc, pid_raw, ip_raw, port_raw = parts
            try:
                pid_val = None if pid_raw in ("None", "", "null") else int(pid_raw)
            except ValueError:
                pid_val = None
            ip_val = None if ip_raw in ("None", "", "null") else ip_raw
            try:
                port_val = None if port_raw in ("None", "", "null") else int(port_raw)
            except ValueError:
                port_val = None
            return etype, proc, pid_val, ip_val, port_val

        for name, data in processes.items():
            if self.ignore_list.contains(name):
                continue

            pid = data.get("pid")
            conn_count = data.get("connections", 0)
            unique_ips = set(data.get("unique_ips", set()))
            unique_ips_count = len(unique_ips)
            established = data.get("states", {}).get("ESTABLISHED", 0)
            remote_ports = set(data.get("remote_ports", set()))
            remote_endpoints = set(data.get("remote_endpoints", set()))

            # New process seen in network activity
            if name not in self.seen_processes:
                self.seen_processes.add(name)
                event = self.emit_event(
                    event_type="new_process_on_network",
                    severity="INFO",
                    process=name,
                    pid=pid,
                    reason=f"Process first seen on network: {name}",
                )
                if event:
                    alerts.append(event)
                    state_changed = True

            # New remote IP for this process
            for ip in unique_ips:
                if ip not in self.seen_remote_ip_by_process[name]:
                    self.seen_remote_ip_by_process[name].add(ip)
                    event = self.emit_event(
                        event_type="new_remote_ip_for_process",
                        severity="INFO",
                        process=name,
                        pid=pid,
                        remote_ip=ip,
                        reason=f"New remote IP for {name}: {ip}",
                    )
                    if event:
                        alerts.append(event)
                        state_changed = True

            # Threshold rules
            if conn_count > 20:
                raise_stateful_alert(
                    event_type="high_connections",
                    severity="WARN",
                    process=name,
                    pid=pid,
                    reason=f"Connections={conn_count} > threshold=20",
                )

            if unique_ips_count > 8:
                raise_stateful_alert(
                    event_type="many_unique_ips",
                    severity="WARN",
                    process=name,
                    pid=pid,
                    reason=f"Unique IPs={unique_ips_count} > threshold=8",
                )

            if established > 12:
                raise_stateful_alert(
                    event_type="heavy_traffic",
                    severity="WARN",
                    process=name,
                    pid=pid,
                    reason=f"ESTABLISHED={established} > threshold=12",
                )

            # Threat list rules
            if name.lower() in malware_list:
                if unique_ips:
                    for ip in unique_ips:
                        raise_stateful_alert(
                            event_type="known_malware_process",
                            severity="CRITICAL",
                            process=name,
                            pid=pid,
                            remote_ip=ip,
                            reason=f"Known malware process: {name} (remote_ip={ip})",
                        )
                else:
                    raise_stateful_alert(
                        event_type="known_malware_process",
                        severity="CRITICAL",
                        process=name,
                        pid=pid,
                        reason=f"Known malware process: {name}",
                    )

            for ip in unique_ips:
                if threat_engine._is_malicious_ip(ip):
                    raise_stateful_alert(
                        event_type="watchlist_ip_match",
                        severity="CRITICAL",
                        process=name,
                        pid=pid,
                        remote_ip=ip,
                        reason=f"Remote IP in watchlist: {ip}",
                    )

            if remote_endpoints:
                for ip, port in remote_endpoints:
                    if port in suspicious_ports:
                        raise_stateful_alert(
                            event_type="suspicious_port",
                            severity="WARN",
                            process=name,
                            pid=pid,
                            remote_ip=ip,
                            remote_port=port,
                            reason=f"Connection to suspicious endpoint: {ip}:{port}",
                        )
            else:
                for port in remote_ports:
                    if port in suspicious_ports:
                        raise_stateful_alert(
                            event_type="suspicious_port",
                            severity="WARN",
                            process=name,
                            pid=pid,
                            remote_port=port,
                            reason=f"Connection to suspicious port: {port}",
                        )

        resolved_keys = self.active_alert_keys - current_active_keys
        for key in resolved_keys:
            parsed = parse_event_key(key)
            if not parsed:
                continue
            prev_type, proc, pid_val, ip_val, port_val = parsed
            resolved_event = self.emit_event(
                event_type="alert_resolved",
                severity="INFO",
                process=proc,
                pid=pid_val,
                remote_ip=ip_val,
                remote_port=port_val,
                reason=f"Resolved alert: {prev_type}",
            )
            if resolved_event:
                alerts.append(resolved_event)

        if current_active_keys != self.active_alert_keys:
            self.active_alert_keys = current_active_keys
            state_changed = True

        # Keep lightweight snapshot for next-step diff rules
        snapshot = {}
        for name, data in processes.items():
            snapshot[name] = {
                "pid": data.get("pid"),
                "connections": data.get("connections", 0),
                "unique_ips": set(data.get("unique_ips", set())),
            }
        self.prev_snapshot = snapshot

        if state_changed:
            self._save_state()

        return alerts
