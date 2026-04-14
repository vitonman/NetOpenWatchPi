# NetOpenWatchPi

NetOpenWatchPi is a host-side network and system monitor with:

- a CLI for diagnostics and investigation
- an embedded HTTP API
- a Raspberry Pi style frontend for a 640x480 display
- snapshot-based forensic views for desktop analysis

The host machine runs the monitoring engine. The Pi screen acts as a compact dashboard and control surface.

## What It Does

- Monitors processes with network activity
- Tracks connection counts, unique IPs, ports, states, and remote endpoints
- Generates local `INFO / WARN / CRITICAL` alerts
- Keeps alert state with cooldowns and `alert_resolved` events
- Logs alerts to daily JSONL files
- Builds live alert feeds for the frontend
- Builds current risk summaries for suspicious processes
- Creates point-in-time network snapshots for later analysis
- Exposes a lightweight API used by the frontend

## Architecture

There is now one main runtime:

- `monitor.py`

It starts:

- the background monitoring loop
- the embedded API server
- the CLI
- tray integration

Important: the frontend should talk to the API started by `monitor.py`.
Do not run a second standalone API process unless you explicitly want separate state.

## Main Runtime Flow

Background loop in `monitor.py`:

1. Collect current process/network data
2. Run anomaly detection through `AlertManager`
3. Update live alert feed
4. Refresh current risk snapshot
5. Expose read-only state to the API/UI

This keeps the frontend read-only. Polling the UI does not drive the alert engine.

## Frontend Screens

The Pi UI lives in `netopenwatchpi-ui/`.

- `index.html` -> `F1 CLOCK`
- `overview.html` -> `F2 PC OVERVIEW`
- `alerts.html` -> `F3 ALERTS`
- `processes.html` -> `F4 PROCESSES`
- `snapshot.html` -> desktop analysis page for `SNAPSHOTS` and `LOGS`

### F1 CLOCK

- Large clock/date
- Critical alert indicator
- Home screen for the device

### F2 PC OVERVIEW

- CPU load / temp / frequency
- Memory usage
- GPU load / temp / VRAM
- Network totals
- Storage summary

### F3 ALERTS

Modes:

- `STATS` -> alert overview
- `LIVE` -> realtime alert feed
- `SNAPSHOT` -> create network snapshots
- `RISKS` -> current suspicious process summary
- `LOGS` -> scrollable alert history

### F4 PROCESSES

- Current process list with connection counts
- Hardware-style navigation
- Live process detail view with endpoints, IPs, protocols, and states

## Snapshot Model

Snapshots are created from the device UI, but analyzed on a normal browser page.

Device side:

- `F3 -> SNAPSHOT -> MAKE SNAPSHOT`

Desktop side:

- `snapshot.html`

Desktop analysis page modes:

- `SNAPSHOTS` -> browse saved snapshots and inspect process/network details
- `LOGS` -> browse daily alert logs and inspect individual alert events

Each snapshot stores:

- timestamp / label / hostname
- process list
- connections total
- established total
- unique IP totals
- remote endpoint totals
- current risks
- active alerts at the time of capture

Snapshots are written to:

- `logs/snapshots/`

## Alert Logs

Alert history is stored as daily files:

- `logs/alerts/alerts_YYYY-MM-DD.jsonl`

This is the long-term history.

Device side:

- `F3 -> LOGS`

acts as a compact recent-history browser for quick review on the Pi display.

Desktop side:

- `snapshot.html` -> `LOGS`

acts as the fuller day-by-day log browser.

## Controls / Navigation Model

The UI is being optimized for hardware controls rather than mouse-first navigation.

Planned control model:

- `MODE` -> cycle `F1/F2/F3/F4`
- `UP`
- `DOWN`
- `SELECT`
- `BACK`
- `LONG PRESS BACK` -> go to `CLOCK`

Current keyboard emulation:

- `Tab` or `M` -> `MODE`
- `ArrowUp` -> `UP`
- `ArrowDown` -> `DOWN`
- `Enter` -> `SELECT`
- `Escape` or `Backspace` -> `BACK`
- hold `Escape` / `Backspace` -> `CLOCK`

## Requirements

- Python 3.10+
- Windows is the main current target
- Linux / Raspberry Pi are supported for frontend hosting / deployment flow
- Dependencies from `requirements.txt`

## Quick Start (Windows Host)

```powershell
cd D:\Repos\NetOpenWatchPi
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python monitor.py
```

Frontend dev server:

```powershell
cd D:\Repos\NetOpenWatchPi\netopenwatchpi-ui
python -m http.server 8080
```

Open locally:

- `http://localhost:8080/index.html`
- `http://localhost:8080/overview.html`
- `http://localhost:8080/alerts.html`
- `http://localhost:8080/processes.html`
- `http://localhost:8080/snapshot.html`

Tray shortcut:

- right-click the tray icon
- choose `Open Analysis Page`
- this opens the desktop analysis page in the default browser

## Raspberry Pi Frontend

On the Pi:

```bash
cd ~/Repos/NetOpenWatchPi/netopenwatchpi-ui
python3 -m http.server 8080 --bind 0.0.0.0
```

Then open:

- `http://<pi-ip>:8080/index.html`

Important:

- Pi frontend is just static HTML/CSS/JS
- host monitoring/API still runs on the monitored PC
- UI pages use the host API base URL, for example:
  - `http://192.168.0.54:8765`

## Temperatures on Windows

For stable temperature data on Windows, LibreHardwareMonitor is recommended.

1. Start LibreHardwareMonitor
2. Enable `Options -> Remote Web Server -> Run`
3. Verify:

```powershell
Invoke-WebRequest http://127.0.0.1:8085/data.json | Select-Object -ExpandProperty Content
```

## Main CLI Commands

- `status` - show compact system status
- `top` - top processes by connections
- `network processes` - external connection summary
- `threats` - current threat database / whitelist
- `risks` - global risk summary for active connections
- `stats` - alert statistics
- `processinfo <name.exe>` - detailed process info by name
- `pidinfo <pid>` - detailed process info by PID
- `temps` - show temperatures
- `hwinfo` - show hardware information
- `alerts` - run one-shot anomaly check
- `alertswatch [sec]` - realtime alert stream
- `alertslog [N]` - show alert history from log
- `list` / `ignore` - show ignore list
- `add <name|number>` - add ignored process
- `remove <name>` - remove ignored process
- `gui` - open GUI window
- `permdiag` - socket/permission diagnostics
- `help` - show help
- `quit` - exit

## API Overview

Current important endpoints:

- `/api/status`
- `/api/processes`
- `/api/network/processes`
- `/api/alerts/stats`
- `/api/alerts/live`
- `/api/alerts/risks`
- `/api/alerts/logs`
- `/api/logs/days`
- `/api/logs/day?file=...`
- `/api/snapshots/create`
- `/api/snapshots/list`
- `/api/snapshots/get?file=...`

## Config and Data Files

- `config/settings.json` - main user-facing settings
- `config/threats.json` - threat database rules
- `config/whitelist.json` - trusted IPs and trusted processes
- `logs/alert_state.json` - persisted alert state
- `logs/alerts/` - daily alert history files
- `logs/snapshots/` - saved network snapshots

### Main Settings

Most user tuning should happen in `config/settings.json`.

Important sections:

- `ignored_processes`
- `app.api_host`
- `app.api_port`
- `app.monitor_interval_sec`
- `app.analysis_page_url`
- `alerts.cooldowns_by_type`
- `alerts.thresholds`
- `risk.memory_ttl_sec`
- `risk.noisy_processes`
- `network.skip_private_ips_for_threat_checks`
- `network.private_networks`

## Resetting State

Stop the app and delete what you need:

- `logs/alert_state.json` - reset seen/active alert state
- `logs/alerts/` - reset alert history
- `logs/snapshots/` - clear saved snapshots

## Project Structure

- `monitor.py` - main runtime, CLI, background loop, embedded API startup
- `api/server.py` - HTTP API
- `core/network_collector.py` - per-process network collection
- `core/alert_manager.py` - alert lifecycle and anomaly rules
- `core/threat_engine.py` - threat/risk rules
- `core/user_settings.py` - merged user settings loader/defaults
- `core/metrics.py` - hardware/system metrics
- `gui/main_window.py` - GUI window
- `tray/tray_manager.py` - tray integration
- `netopenwatchpi-ui/` - Pi UI + desktop analysis page

## Current Status

Working now:

- unified host runtime (`monitor.py`)
- live alerts
- stats
- snapshots
- risks
- device log browsing
- desktop snapshot/log analysis
- tray shortcut to analysis page
- live process detail view
- keyboard/device navigation foundation

Still in progress:

- tighter hardware control integration with the final encoder/button wiring
