# core/threat_engine.py - Local Rule-based Threat Engine (mini VirusTotal style)

import json
import os
import ipaddress
import time
from collections import defaultdict
from typing import Dict, List, Tuple
from core.user_settings import load_settings


class ThreatEngine:
    """Simple local threat detection engine with rules and whitelists."""

    def __init__(self):
        self.config_dir = "config"
        os.makedirs(self.config_dir, exist_ok=True)

        self.settings = load_settings()
        self.threats = self._load_threats()
        self.whitelist = self._load_whitelist()

        # Alert statistics
        self.alert_stats = {
            "hour": defaultdict(int),
            "day": defaultdict(int),
            "last_hour_reset": time.time(),
            "last_day_reset": time.time()
        }

        # History for "NEW" detections
        self.seen_processes = set()
        self.seen_ips = set()

    def _private_networks(self):
        network_cfg = self.settings.get("network", {})
        return network_cfg.get("private_networks", [])

    def _load_threats(self) -> Dict:
        """Load or create default threat database."""
        path = os.path.join(self.config_dir, "threats.json")
        if not os.path.exists(path):
            default = {
                "malicious_ips": [],
                "suspicious_ports": [4444, 1337, 31337, 6666],
                "known_malware_processes": [
                    "powershell.exe", "cmd.exe", "wscript.exe",
                    "cscript.exe", "regsvr32.exe", "mshta.exe"
                ],
                "high_risk_countries": []
            }
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(default, f, indent=4)
            return default

        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def _load_whitelist(self) -> Dict:
        """Load or create default whitelist."""
        path = os.path.join(self.config_dir, "whitelist.json")
        if not os.path.exists(path):
            default = {
                "trusted_ips": [],
                "trusted_processes": []
            }
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(default, f, indent=4)
            return default

        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def _is_malicious_ip(self, ip: str) -> bool:
        """Check if IP is in malicious list (supports CIDR)."""
        if not ip:
            return False
        network_cfg = self.settings.get("network", {})
        if network_cfg.get("skip_private_ips_for_threat_checks", True):
            try:
                ip_obj = ipaddress.ip_address(ip)
                for network in self._private_networks():
                    try:
                        if ip_obj in ipaddress.ip_network(network, strict=False):
                            return False
                    except ValueError:
                        continue
            except ValueError:
                return False

        for bad in self.threats.get("malicious_ips", []):
            try:
                if '/' in bad:  # CIDR notation
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(bad, strict=False):
                        return True
                elif bad == ip:
                    return True
            except Exception:
                continue
        return False

    def analyze_connection(self, process_name: str, remote_ip: str = None, remote_port: int = None) -> List[Dict]:
        """Analyze one connection and return list of risk flags."""
        flags = []

        # 1. Whitelist check (highest priority)
        if process_name in self.whitelist.get("trusted_processes", []):
            return [{"severity": "INFO", "reason": "TRUSTED_PROCESS", "explanation": "Process is in whitelist"}]

        if remote_ip and remote_ip in self.whitelist.get("trusted_ips", []):
            return [{"severity": "INFO", "reason": "TRUSTED_IP", "explanation": "IP is in whitelist"}]

        # 2. NEW Process detection
        if process_name not in self.seen_processes:
            self.seen_processes.add(process_name)
            flags.append({
                "severity": "WARN",
                "reason": "NEW_PROCESS",
                "explanation": f"First time seen process: {process_name}"
            })

        # 3. NEW Remote IP detection
        if remote_ip and remote_ip not in self.seen_ips:
            self.seen_ips.add(remote_ip)
            flags.append({
                "severity": "WARN",
                "reason": "NEW_IP",
                "explanation": f"New remote IP detected: {remote_ip}"
            })

        # 4. Malicious IP
        if remote_ip and self._is_malicious_ip(remote_ip):
            flags.append({
                "severity": "CRITICAL",
                "reason": "MALICIOUS_IP",
                "explanation": f"IP {remote_ip} is in malicious database"
            })

        # 5. Suspicious port
        if remote_port and remote_port in self.threats.get("suspicious_ports", []):
            flags.append({
                "severity": "WARN",
                "reason": "SUSPICIOUS_PORT",
                "explanation": f"Connection to suspicious port {remote_port}"
            })

        # 6. Known malware process
        malware_list = [p.lower() for p in self.threats.get("known_malware_processes", [])]
        if process_name.lower() in malware_list:
            flags.append({
                "severity": "CRITICAL",
                "reason": "KNOWN_MALWARE_PROCESS",
                "explanation": f"Process {process_name} is known malware"
            })

        # Default if nothing suspicious
        if not flags:
            flags.append({
                "severity": "INFO",
                "reason": "NORMAL",
                "explanation": "Normal connection"
            })

        return flags

    def update_alert_stats(self, severity: str):
        """Update hourly and daily alert counters."""
        now = time.time()

        # Reset hour counter
        if now - self.alert_stats["last_hour_reset"] > 3600:
            self.alert_stats["hour"] = defaultdict(int)
            self.alert_stats["last_hour_reset"] = now

        # Reset day counter
        if now - self.alert_stats["last_day_reset"] > 86400:
            self.alert_stats["day"] = defaultdict(int)
            self.alert_stats["last_day_reset"] = now

        self.alert_stats["hour"][severity] += 1
        self.alert_stats["day"][severity] += 1

    def get_alert_stats(self) -> Dict:
        """Return current alert statistics."""
        return {
            "last_hour": dict(self.alert_stats["hour"]),
            "last_day": dict(self.alert_stats["day"])
        }


# Global instance
threat_engine = ThreatEngine()
