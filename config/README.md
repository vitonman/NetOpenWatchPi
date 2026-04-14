NetOpenWatchPi config files:

- `settings.json`
  Main user-facing settings file.
  Change alert thresholds, cooldowns, API host/port, monitor interval,
  ignored processes, risk memory TTL, and private-network behavior here.

- `threats.json`
  Threat database:
  malicious IPs, suspicious ports, known malware process names.

- `whitelist.json`
  Trusted IPs and trusted processes.

Notes:

- Most day-to-day tuning should happen in `settings.json`.
- Changes to config files are applied after restarting `monitor.py`.
