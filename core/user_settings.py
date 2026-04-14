import copy
import json
import os


SETTINGS_PATH = os.path.join("config", "settings.json")
LEGACY_IGNORE_PATH = os.path.join("config", "config.json")


DEFAULT_SETTINGS = {
    "ignored_processes": [
        "System Idle Process",
        "System",
        "Registry",
        "Idle",
    ],
    "app": {
        "api_host": "0.0.0.0",
        "api_port": 8765,
        "monitor_interval_sec": 2,
        "analysis_page_url": "http://localhost:8080/snapshot.html",
    },
    "alerts": {
        "default_cooldown_sec": 15,
        "cooldowns_by_type": {
            "high_connections": 15,
            "many_unique_ips": 15,
            "heavy_traffic": 15,
            "new_process_on_network": 120,
            "new_remote_ip_for_process": 120,
            "watchlist_ip_match": 30,
            "suspicious_port": 30,
            "known_malware_process": 10,
        },
        "thresholds": {
            "high_connections_warn": 20,
            "many_unique_ips_warn": 8,
            "heavy_traffic_established_warn": 12,
        },
    },
    "risk": {
        "memory_ttl_sec": 90,
        "noisy_processes": [
            "System Idle Process",
            "System",
        ],
    },
    "network": {
        "skip_private_ips_for_threat_checks": True,
        "private_networks": [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
        ],
    },
}


def _deep_merge(base, incoming):
    result = copy.deepcopy(base)
    for key, value in (incoming or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_settings():
    os.makedirs("config", exist_ok=True)

    user_data = {}
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                user_data = json.load(f)
        except Exception:
            user_data = {}

    if os.path.exists(LEGACY_IGNORE_PATH):
        try:
            with open(LEGACY_IGNORE_PATH, "r", encoding="utf-8") as f:
                legacy = json.load(f)
            legacy_ignored = legacy.get("ignored_processes")
            if isinstance(legacy_ignored, list) and "ignored_processes" not in user_data:
                user_data["ignored_processes"] = legacy_ignored
        except Exception:
            pass

    settings = _deep_merge(DEFAULT_SETTINGS, user_data)

    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    return settings


def save_settings(settings):
    os.makedirs("config", exist_ok=True)
    merged = _deep_merge(DEFAULT_SETTINGS, settings or {})
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)
