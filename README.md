# NetOpenWatchPi

CLI/GUI monitor for process network activity and core system metrics.  
The project is designed to collect data on the host machine (Windows/Linux) and later display it on a Raspberry Pi screen.

## Implemented Features

- Process list with network activity and connection counters.
- Detailed process view (`processinfo`, `pidinfo`) with IP/port/state data.
- Local alert engine:
  - `INFO/WARN/CRITICAL` severities
  - cooldown support
  - stateful alert memory (reduced repeated noise)
  - `alert_resolved` events when a condition disappears
- Alert logging to `logs/alerts.jsonl`.
- Alert history view (`alertslog [N]`).
- Realtime alert stream (`alertswatch [sec]`).
- Hardware overview (`hwinfo`) and temperatures (`temps`) with fallbacks.

## Requirements

- Python 3.10+
- OS: Windows (primary current target), Linux (partial support)
- Dependencies from `requirements.txt`

## Quick Start (Windows)

```powershell
cd D:\Repos\NetOpenWatchPi
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python monitor.py
```

## Quick Start (Linux / Raspberry Pi)

```bash
cd /path/to/NetOpenWatchPi
bash start.sh
```

## Temperatures on Windows

For stable `temps` output on Windows, LibreHardwareMonitor is recommended:

1. Start LibreHardwareMonitor.
2. Enable `Options -> Remote Web Server -> Run`.
3. Verify JSON endpoint:

```powershell
Invoke-WebRequest http://127.0.0.1:8085/data.json | Select-Object -ExpandProperty Content
```

If JSON is reachable, `temps` should show values (or `N/A` if a specific sensor is unavailable).

## Main CLI Commands

- `status` - show system metrics + top list
- `top` - show top processes by connections
- `network processes` - show processes with external connections
- `threats` - show local threat/whitelist database
- `risks` - show global risk summary for active connections
- `stats` - show alert statistics (hour/day)
- `processinfo <name.exe>` - detailed view by process name
- `pidinfo <pid>` - detailed view by PID
- `temps` - show temperatures
- `hwinfo` - show hardware information
- `alerts` - run one-time anomaly check
- `alertswatch [sec]` - realtime alert stream, stop with `Ctrl+C`
- `alertslog [N]` - show last N alerts from log
- `list` / `ignore` - show ignore list
- `add <name|number>` - add process to ignore list
- `remove <name>` - remove process from ignore list
- `gui` - open GUI window
- `permdiag` - permission/socket visibility diagnostics
- `help` - show command help
- `quit` - exit

## Config and Data Files

- `config/config.json` - ignored processes
- `logs/alerts.jsonl` - alert history (JSONL)
- `logs/alert_state.json` - persisted alert engine state

### Reset Alert State

Stop the app and delete:

- `logs/alert_state.json` - reset seen/active state memory
- `logs/alerts.jsonl` - reset history (optional)

## Project Structure

- `monitor.py` - CLI app, command routing, output formatting
- `core/network_collector.py` - per-process network data collection
- `core/alert_manager.py` - anomaly rules and alert lifecycle
- `core/threat_engine.py` - local threat rules
- `core/metrics.py` - system/hardware metrics
- `gui/main_window.py` - GUI window
- `tray/tray_manager.py` - system tray integration

## Current Status

Backend/CLI is close to feature-complete. The next major step is Raspberry Pi frontend/UX integration and dashboard flow.
