# core/network_collector.py - Network and process monitoring

import psutil
from collections import defaultdict
import time
from typing import Dict, List


class NetworkCollector:
    """Collects network connections and process statistics"""

    def __init__(self):
        self.process_history = defaultdict(list)  # Store history for anomaly detection
        self.last_check_time = time.time()

    def collect_network_data(self) -> Dict:
        """Collect detailed information about processes and their network connections"""
        connections = psutil.net_connections(kind='all')
        
        processes: Dict[str, Dict] = defaultdict(lambda: {
            "connections": 0,
            "unique_ips": set(),
            "remote_ports": set(),
            "remote_endpoints": set(),
            "protocols": {"TCP": 0, "UDP": 0},
            "states": defaultdict(int),
            "pid": None
        })

        for conn in connections:
            if conn.pid is None:
                continue
            try:
                proc = psutil.Process(conn.pid)
                name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            data = processes[name]
            data["connections"] += 1
            data["pid"] = conn.pid

            if conn.raddr:
                if conn.raddr.ip:
                    data["unique_ips"].add(conn.raddr.ip)
                if conn.raddr.port:
                    data["remote_ports"].add(conn.raddr.port)
                if conn.raddr.ip and conn.raddr.port:
                    data["remote_endpoints"].add((conn.raddr.ip, conn.raddr.port))

            proto = "TCP" if "tcp" in str(conn.type).lower() else "UDP"
            data["protocols"][proto] += 1

            if conn.status:
                data["states"][conn.status] += 1

        # Save history for anomaly detection (keep last 10 samples)
        current_time = time.time()
        for name, data in processes.items():
            self.process_history[name].append({
                "time": current_time,
                "connections": data["connections"]
            })
            if len(self.process_history[name]) > 10:
                self.process_history[name].pop(0)

        return dict(processes)

    def get_top_processes(self, limit: int = 12) -> List:
        """Return top processes sorted by number of connections, excluding system noise"""
        data = self.collect_network_data()
        
        # Exclude common system noise
        exclude_list = {
            "System Idle Process", "System", "svchost.exe", "Registry", 
            "Idle", "csrss.exe", "wininit.exe", "smss.exe"
        }
        
        filtered = [(name, info) for name, info in data.items() 
                if name not in exclude_list and info["connections"] > 2]
        
        sorted_procs = sorted(
            filtered,
            key=lambda x: x[1]["connections"],
            reverse=True
        )
        return sorted_procs[:limit]
