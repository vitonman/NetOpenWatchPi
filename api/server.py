# api/server.py
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from core.metrics import metrics
from core.network_collector import NetworkCollector
from core.ignore_list import IgnoreList
from core.alert_manager import AlertManager


_fallback_collector = NetworkCollector()
_fallback_alert_manager = AlertManager(IgnoreList())


def _json_response(handler: BaseHTTPRequestHandler, payload: dict, status: int = 200):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()
    handler.wfile.write(body)


def _read_alert_logs(limit: int = 50, since_ts=None):
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
                ts = a.get("ts")
                if since_ts is not None:
                    if not isinstance(ts, (int, float)) or ts <= since_ts:
                        continue
                items.append(a)
    except FileNotFoundError:
        return []

    items.sort(key=lambda x: x.get("ts", 0))  # old -> new
    return items[-limit:] if since_ts is None else items[:limit]


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
                temps = hw.get("temperatures", {})
                net = hw.get("network", {})
                gpu = hw.get("gpu", {})

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
                        "ram_percent": ram.get("percent"),
                        "ram_used_mb": ram.get("used_mb"),
                        "ram_total_mb": ram.get("total_mb"),
                        "cpu_temp_c": temps.get("cpu_temp_c"),
                        "gpu_temp_c": temps.get("gpu_temp_c"),
                    },
                    "network": {
                        "bytes_sent": net.get("io_total", {}).get("bytes_sent"),
                        "bytes_recv": net.get("io_total", {}).get("bytes_recv"),
                    },
                    "gpu": {
                        "available": gpu.get("available", False),
                        "name": (gpu.get("devices", [{}])[0].get("name") if gpu.get("devices") else None),
                        "usage_percent": (gpu.get("devices", [{}])[0].get("usage_percent") if gpu.get("devices") else None),
                    },
                }
                return _json_response(self, payload)

            if req_path in ("/api/processes", "/api/network/processes"):
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
                stats = alert_manager.get_alert_stats()
                return _json_response(self, {"version": "1.0", "generated_at": time.time(), "stats": stats})

            if req_path in ("/api/alerts/check", "/api/alerts/live"):
                processes = collector.collect_network_data()
                items = alert_manager.check_anomalies(processes)
                # Keep deterministic order for UI output
                items.sort(key=lambda x: x.get("ts", 0))
                return _json_response(self, {"version": "1.0", "generated_at": time.time(), "items": items})

            if req_path in ("/api/alerts/logs", "/api/alerts"):
                limit = int(query.get("limit", ["50"])[0])
                since_raw = query.get("since_ts", [None])[0]
                since_ts = float(since_raw) if since_raw not in (None, "") else None
                items = _read_alert_logs(limit=limit, since_ts=since_ts)
                return _json_response(self, {"version": "1.0", "generated_at": time.time(), "items": items})

            return _json_response(self, {"error": "not_found", "path": req_path}, status=404)

        def log_message(self, format, *args):
            return

    return ApiHandler


def run_api_server(host="0.0.0.0", port=8765, app=None):
    handler = make_api_handler(app=app)
    server = HTTPServer((host, port), handler)
    print(f"API server started: http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_api_server()
