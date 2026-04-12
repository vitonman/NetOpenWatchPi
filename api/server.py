# api/server.py
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from core.metrics import metrics
from core.network_collector import NetworkCollector
from core.ignore_list import IgnoreList
from core.alert_manager import AlertManager


_fallback_collector = NetworkCollector()
_fallback_alert_manager = AlertManager(IgnoreList())


def _json_response(handler: BaseHTTPRequestHandler, payload: dict, status: int = 200):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    try:
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Access-Control-Allow-Origin", "*")
        handler.end_headers()
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
        # Browsers/dev servers may cancel in-flight requests during reloads.
        return


def _load_alert_log_items():
    items = []
    try:
        with open("logs/alerts.jsonl", "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    a = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                items.append(a)
    except FileNotFoundError:
        return []

    items.sort(key=lambda x: x.get("ts", 0))  # old -> new
    return items


def _read_alert_logs(limit: int = 50, since_ts=None, offset: int = 0):
    items = _load_alert_log_items()
    if since_ts is not None:
        filtered = []
        for a in items:
            ts = a.get("ts")
            if not isinstance(ts, (int, float)) or ts <= since_ts:
                continue
            filtered.append(a)
        return filtered[:limit], len(filtered)

    total = len(items)
    if total == 0:
        return [], 0

    try:
        offset = int(offset)
    except (TypeError, ValueError):
        offset = 0
    if offset < 0:
        offset = 0

    end = max(total - offset, 0)
    start = max(end - limit, 0)
    window = items[start:end]
    return window, total


def make_api_handler(app=None):
    """Create API handler bound to shared app state when available."""

    class ApiHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            req_path = parsed.path
            query = parse_qs(parsed.query)

            collector = app.collector if app is not None else _fallback_collector
            alert_manager = app.alert_manager if app is not None else _fallback_alert_manager

            if req_path == "/api/status":
                hw = metrics.get_hardware_info()

                system = hw.get("system", {})
                cpu = hw.get("cpu", {})
                ram = hw.get("ram", {})
                disk = hw.get("disk", {})
                temps = hw.get("temperatures", {})
                net = hw.get("network", {})
                gpu = hw.get("gpu", {})
                gpu_devices = gpu.get("devices") or []
                primary_gpu = gpu_devices[0] if gpu_devices else {}
                disk_items = []
                for part in disk.get("partitions", []):
                    if part.get("total_gb") is None:
                        continue
                    disk_items.append(
                        {
                            "device": part.get("device"),
                            "mountpoint": part.get("mountpoint"),
                            "used_gb": part.get("used_gb"),
                            "total_gb": part.get("total_gb"),
                            "percent": part.get("percent"),
                        }
                    )

                payload = {
                    "version": "1.0",
                    "generated_at": hw.get("timestamp"),
                    "system": {
                        "hostname": system.get("hostname"),
                        "os": f"{system.get('os', '')} {system.get('os_release', '')}".strip(),
                        "uptime_sec": system.get("uptime_sec"),
                    },
                    "metrics": {
                        "cpu_percent": cpu.get("usage_percent_total"),
                        "cpu_name": system.get("processor"),
                        "cpu_mhz": cpu.get("frequency_mhz", {}).get("current"),
                        "cpu_cores": cpu.get("physical_cores"),
                        "cpu_threads": cpu.get("logical_cores"),
                        "ram_percent": ram.get("percent"),
                        "ram_used_mb": ram.get("used_mb"),
                        "ram_total_mb": ram.get("total_mb"),
                        "cpu_temp_c": temps.get("cpu_temp_c"),
                        "gpu_temp_c": temps.get("gpu_temp_c"),
                    },
                    "network": {
                        "bytes_sent": net.get("io_total", {}).get("bytes_sent"),
                        "bytes_recv": net.get("io_total", {}).get("bytes_recv"),
                        "packets_sent": net.get("io_total", {}).get("packets_sent"),
                        "packets_recv": net.get("io_total", {}).get("packets_recv"),
                    },
                    "gpu": {
                        "available": gpu.get("available", False),
                        "name": primary_gpu.get("name"),
                        "usage_percent": primary_gpu.get("usage_percent"),
                        "memory_used_mb": primary_gpu.get("memory_used_mb"),
                        "memory_total_mb": primary_gpu.get("memory_total_mb"),
                    },
                    "disk": {
                        "items": disk_items[:2],
                    }
                }
                return _json_response(self, payload)

            if req_path in ("/api/processes", "/api/network/processes"):
                if app is not None and getattr(app, "current_processes", None):
                    data = app.current_processes
                else:
                    data = collector.collect_network_data()
                items = []
                for name, d in data.items():
                    items.append(
                        {
                            "name": name,
                            "pid": d.get("pid"),
                            "connections": d.get("connections", 0),
                            "unique_ips": len(d.get("unique_ips", set())),
                            "established": d.get("states", {}).get("ESTABLISHED", 0),
                        }
                    )
                items.sort(key=lambda x: x["connections"], reverse=True)
                return _json_response(self, {"version": "1.0", "generated_at": time.time(), "items": items})

            if req_path == "/api/alerts/stats":
                if app is not None:
                    stats = app.build_alerts_stats_summary()
                else:
                    stats = alert_manager.get_alert_stats()
                return _json_response(self, {"version": "1.0", "generated_at": time.time(), "stats": stats})

            if req_path == "/api/alerts/live":
                since_rev_raw = query.get("since_rev", [None])[0]
                try:
                    since_rev = int(since_rev_raw) if since_rev_raw not in (None, "") else None
                except ValueError:
                    since_rev = None

                if app is not None:
                    live_payload = app.build_live_alerts_feed(since_rev=since_rev)
                else:
                    live_payload = {"revision": 0, "items": []}

                return _json_response(
                    self,
                    {
                        "version": "1.0",
                        "generated_at": time.time(),
                        "revision": live_payload.get("revision", 0),
                        "items": live_payload.get("items", []),
                    },
                )

            if req_path == "/api/alerts/check":
                processes = collector.collect_network_data()
                items = alert_manager.check_anomalies(processes)
                # Keep deterministic order for UI output
                items.sort(key=lambda x: x.get("ts", 0), reverse=True)
                return _json_response(self, {"version": "1.0", "generated_at": time.time(), "items": items})

            if req_path == "/api/snapshots/create":
                if app is None:
                    return _json_response(
                        self,
                        {"error": "snapshot_unavailable", "message": "Snapshots require shared app state."},
                        status=503,
                    )

                snapshot = app.make_network_snapshot()
                return _json_response(
                    self,
                    {"version": "1.0", "generated_at": time.time(), "snapshot": snapshot},
                )

            if req_path == "/api/snapshots/list":
                if app is not None:
                    limit = int(query.get("limit", ["8"])[0])
                    items = app.list_network_snapshots(limit=limit)
                else:
                    items = []
                return _json_response(
                    self,
                    {"version": "1.0", "generated_at": time.time(), "items": items},
                )

            if req_path == "/api/snapshots/get":
                if app is None:
                    return _json_response(
                        self,
                        {"error": "snapshot_unavailable", "message": "Snapshots require shared app state."},
                        status=503,
                    )

                filename = query.get("file", [""])[0]
                safe_name = os.path.basename(filename)
                if not safe_name or safe_name != filename or not safe_name.lower().endswith(".json"):
                    return _json_response(
                        self,
                        {"error": "invalid_snapshot_file", "path": filename},
                        status=400,
                    )

                path = os.path.join(app.snapshot_dir, safe_name)
                if not os.path.isfile(path):
                    return _json_response(
                        self,
                        {"error": "snapshot_not_found", "path": safe_name},
                        status=404,
                    )

                try:
                    with open(path, "r", encoding="utf-8") as f:
                        payload = json.load(f)
                except (OSError, json.JSONDecodeError):
                    return _json_response(
                        self,
                        {"error": "snapshot_read_failed", "path": safe_name},
                        status=500,
                    )

                return _json_response(
                    self,
                    {"version": "1.0", "generated_at": time.time(), "snapshot": payload},
                )

            if req_path in ("/api/alerts/logs", "/api/alerts"):
                limit = int(query.get("limit", ["50"])[0])
                try:
                    offset = int(query.get("offset", ["0"])[0])
                except (TypeError, ValueError):
                    offset = 0
                since_raw = query.get("since_ts", [None])[0]
                since_ts = float(since_raw) if since_raw not in (None, "") else None
                items, total = _read_alert_logs(limit=limit, since_ts=since_ts, offset=offset)
                return _json_response(
                    self,
                    {
                        "version": "1.0",
                        "generated_at": time.time(),
                        "items": items,
                        "total": total,
                        "offset": offset,
                        "limit": limit,
                    },
                )
            
            if req_path == "/api/alerts/risks":
                items = app.build_risks_snapshot() if app is not None else []
                return _json_response(
                    self,
                    {
                        "version": "1.0",
                        "generated_at": time.time(),
                        "items": items
                    },

                )


            return _json_response(self, {"error": "not_found", "path": req_path}, status=404)

        def log_message(self, format, *args):
            return

    return ApiHandler


def run_api_server(host="0.0.0.0", port=8765, app=None):
    handler = make_api_handler(app=app)
    server = ThreadingHTTPServer((host, port), handler)
    print(f"API server started: http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_api_server()
