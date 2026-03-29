# core/alert_manager.py - Anomaly detection and alerts

import time
from typing import Dict, List

class AlertManager:
    """Detects suspicious network activity and generates alerts"""

    def __init__(self, ignore_list):
        self.last_alert_time = {}
        self.alert_cooldown = 15
        self.ignore_list = ignore_list

    def check_anomalies(self, processes: Dict) -> List[str]:
        """Check for suspicious behavior, respecting ignore list"""
        alerts = []

        for name, data in processes.items():
            if self.ignore_list.contains(name):
                continue

            conn_count = data["connections"]
            unique_ips = len(data["unique_ips"])
            established = data["states"].get("ESTABLISHED", 0)

            if conn_count > 20:
                if self._can_send_alert(f"high_conn_{name}"):
                    alerts.append(f"⚠️ HIGH CONNECTIONS → {name} ({conn_count} connections)")

            if unique_ips > 8:
                if self._can_send_alert(f"many_ips_{name}"):
                    alerts.append(f"⚠️ SUSPICIOUS IPS → {name} ({unique_ips} IPs)")

            if established > 12:
                if self._can_send_alert(f"heavy_{name}"):
                    alerts.append(f"⚠️ HEAVY TRAFFIC → {name} ({established} established)")

        return alerts

    def _can_send_alert(self, alert_key: str) -> bool:
        now = time.time()
        if alert_key in self.last_alert_time:
            if now - self.last_alert_time[alert_key] < self.alert_cooldown:
                return False
        self.last_alert_time[alert_key] = now
        return True