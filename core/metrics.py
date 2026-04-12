# core/metrics.py - System metrics collection

import platform
import subprocess
import time
import json
from urllib.request import urlopen
import re
from typing import Dict, Optional

import psutil


class SystemMetrics:
    """Main class responsible for collecting all system information."""

    def _get_cpu_name(self) -> str:
        """Return a human-readable CPU name when available."""
        if platform.system() == "Windows":
            out = self._run_command(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name",
                ],
                timeout=4,
            )
            if out:
                line = out.splitlines()[0].strip()
                if line:
                    return line

        processor = (platform.processor() or "").strip()
        if processor:
            return processor

        return "Unknown CPU"

    def get_cpu_temperature(self) -> Optional[float]:
        """Returns CPU temperature or None if not available."""
        system = platform.system()

        if system == "Linux":
            # Method 1: gpiozero (good for Raspberry Pi)
            try:
                from gpiozero import CPUTemperature

                temp = CPUTemperature().temperature
                return round(temp, 1)
            except Exception:
                pass

            # Method 2: sysfs
            try:
                with open("/sys/class/thermal/thermal_zone0/temp", encoding="utf-8") as f:
                    return round(int(f.read().strip()) / 1000.0, 1)
            except Exception:
                pass

            # Method 3: vcgencmd
            try:
                output = subprocess.check_output(["vcgencmd", "measure_temp"], timeout=2).decode().strip()
                return float(output.split("=")[1].split("'")[0])
            except Exception:
                pass

        # Windows and unknown platforms: no reliable built-in source here.
        return None

    def get_hardware_info(self) -> Dict:
        """Returns full hardware/system snapshot."""
        return {
            "timestamp": time.time(),
            "system": self._get_system_info(),
            "cpu": self._get_cpu_info(),
            "ram": self._get_memory_info(),
            "swap": self._get_swap_info(),
            "disk": self._get_disk_info(),
            "network": self._get_network_info(),
            "gpu": self._get_gpu_info(),
            "temperatures": self._get_temperatures_info(),
        }

    def _get_system_info(self) -> Dict:
        boot_ts = psutil.boot_time()
        return {
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "hostname": platform.node(),
            "machine": platform.machine(),
            "processor": self._get_cpu_name(),
            "python_version": platform.python_version(),
            "boot_time": boot_ts,
            "uptime_sec": int(time.time() - boot_ts),
        }

    def _get_cpu_info(self) -> Dict:
        freq = psutil.cpu_freq()
        return {
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "usage_percent_total": round(psutil.cpu_percent(interval=0.3), 1),
            "usage_percent_per_core": [round(v, 1) for v in psutil.cpu_percent(interval=0.3, percpu=True)],
            "frequency_mhz": {
                "current": round(freq.current, 1) if freq else None,
                "min": round(freq.min, 1) if freq else None,
                "max": round(freq.max, 1) if freq else None,
            },
        }

    def _get_memory_info(self) -> Dict:
        ram = psutil.virtual_memory()
        return {
            "total_mb": ram.total // (1024 ** 2),
            "used_mb": ram.used // (1024 ** 2),
            "available_mb": ram.available // (1024 ** 2),
            "percent": round(ram.percent, 1),
        }

    def _get_swap_info(self) -> Dict:
        swp = psutil.swap_memory()
        return {
            "total_mb": swp.total // (1024 ** 2),
            "used_mb": swp.used // (1024 ** 2),
            "free_mb": swp.free // (1024 ** 2),
            "percent": round(swp.percent, 1),
        }

    def _get_disk_info(self) -> Dict:
        partitions = []
        for part in psutil.disk_partitions(all=False):
            entry = {
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total_gb": None,
                "used_gb": None,
                "free_gb": None,
                "percent": None,
            }
            try:
                usage = psutil.disk_usage(part.mountpoint)
                entry.update(
                    {
                        "total_gb": round(usage.total / (1024 ** 3), 2),
                        "used_gb": round(usage.used / (1024 ** 3), 2),
                        "free_gb": round(usage.free / (1024 ** 3), 2),
                        "percent": round(usage.percent, 1),
                    }
                )
            except Exception:
                pass
            partitions.append(entry)

        io = psutil.disk_io_counters()
        io_info = None
        if io:
            io_info = {
                "read_bytes": io.read_bytes,
                "write_bytes": io.write_bytes,
                "read_count": io.read_count,
                "write_count": io.write_count,
            }

        return {
            "partitions": partitions,
            "io_counters": io_info,
        }

    def _get_network_info(self) -> Dict:
        interfaces = {}
        for iface, addrs in psutil.net_if_addrs().items():
            interfaces[iface] = []
            for a in addrs:
                interfaces[iface].append(
                    {
                        "family": str(a.family),
                        "address": a.address,
                        "netmask": a.netmask,
                        "broadcast": a.broadcast,
                    }
                )

        io_total = psutil.net_io_counters()
        io_per_nic_raw = psutil.net_io_counters(pernic=True)
        io_per_nic = {}
        for nic, counters in io_per_nic_raw.items():
            io_per_nic[nic] = {
                "bytes_sent": counters.bytes_sent,
                "bytes_recv": counters.bytes_recv,
                "packets_sent": counters.packets_sent,
                "packets_recv": counters.packets_recv,
            }

        return {
            "interfaces": interfaces,
            "io_total": {
                "bytes_sent": io_total.bytes_sent,
                "bytes_recv": io_total.bytes_recv,
                "packets_sent": io_total.packets_sent,
                "packets_recv": io_total.packets_recv,
            }
            if io_total
            else None,
            "io_per_nic": io_per_nic,
        }

    def _run_command(self, args: list[str], timeout: int = 3) -> Optional[str]:
        try:
            output = subprocess.check_output(args, stderr=subprocess.DEVNULL, timeout=timeout)
            return output.decode(errors="ignore").strip()
        except Exception:
            return None

    def _parse_json_output(self, text: Optional[str]) -> Optional[object]:
        if not text:
            return None
        try:
            return json.loads(text)
        except Exception:
            return None

    def _as_list(self, obj: object) -> list:
        if obj is None:
            return []
        if isinstance(obj, list):
            return obj
        return [obj]

    def _get_windows_video_controllers(self) -> list[Dict]:
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            (
                "Get-CimInstance Win32_VideoController | "
                "Select-Object Name,AdapterRAM | ConvertTo-Json -Compress"
            ),
        ]
        data = self._parse_json_output(self._run_command(cmd, timeout=4))
        devices = []
        for row in self._as_list(data):
            if not isinstance(row, dict):
                continue
            name = str(row.get("Name") or "").strip()
            if not name:
                continue
            vendor = "Unknown"
            lname = name.lower()
            if "nvidia" in lname:
                vendor = "NVIDIA"
            elif "amd" in lname or "radeon" in lname:
                vendor = "AMD"
            elif "intel" in lname:
                vendor = "Intel"
            devices.append(
                {
                    "vendor": vendor,
                    "name": name,
                    "usage_percent": None,
                    "memory_used_mb": None,
                    "memory_total_mb": int(row.get("AdapterRAM", 0) / (1024 ** 2)) if row.get("AdapterRAM") else None,
                    "temperature_c": None,
                    "source": "win32_videocontroller",
                }
            )
        return devices

    def _get_linux_pci_gpus(self) -> list[Dict]:
        out = self._run_command(["lspci"], timeout=3)
        if not out:
            return []
        devices = []
        for line in out.splitlines():
            ll = line.lower()
            if "vga compatible controller" not in ll and "3d controller" not in ll and "display controller" not in ll:
                continue
            name = line.split(": ", 1)[-1].strip()
            vendor = "Unknown"
            if "nvidia" in ll:
                vendor = "NVIDIA"
            elif "amd" in ll or "advanced micro devices" in ll or "radeon" in ll:
                vendor = "AMD"
            elif "intel" in ll:
                vendor = "Intel"
            devices.append(
                {
                    "vendor": vendor,
                    "name": name,
                    "usage_percent": None,
                    "memory_used_mb": None,
                    "memory_total_mb": None,
                    "temperature_c": None,
                    "source": "lspci",
                }
            )
        return devices

    def _get_gpu_info(self) -> Dict:
        # 1) NVIDIA detailed stats
        nvidia_out = self._run_command(
            [
                "nvidia-smi",
                "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
                "--format=csv,noheader,nounits",
            ],
            timeout=3,
        )
        if nvidia_out:
            devices = []
            for line in nvidia_out.splitlines():
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 5:
                    continue
                devices.append(
                    {
                        "vendor": "NVIDIA",
                        "name": parts[0],
                        "usage_percent": float(parts[1]) if parts[1] else None,
                        "memory_used_mb": float(parts[2]) if parts[2] else None,
                        "memory_total_mb": float(parts[3]) if parts[3] else None,
                        "temperature_c": float(parts[4]) if parts[4] else None,
                        "source": "nvidia-smi",
                    }
                )
            if devices:
                return {"available": True, "source": "nvidia-smi", "devices": devices}

        # 2) AMD (ROCm) best-effort stats
        amd_json = self._parse_json_output(
            self._run_command(
                ["rocm-smi", "--showproductname", "--showuse", "--showtemp", "--showmemuse", "--json"],
                timeout=4,
            )
        )
        if isinstance(amd_json, dict) and amd_json:
            devices = []
            for gpu_key, values in amd_json.items():
                if not isinstance(values, dict):
                    continue
                name = None
                temp = None
                usage = None
                mem_used = None
                mem_total = None
                for k, v in values.items():
                    lk = str(k).lower()
                    if "series" in lk or "product" in lk:
                        name = str(v)
                    elif "temp" in lk:
                        try:
                            temp = float(str(v).split()[0].replace("C", "").replace("c", ""))
                        except Exception:
                            pass
                    elif "gpu use" in lk or "use (%)" in lk:
                        try:
                            usage = float(str(v).replace("%", "").strip())
                        except Exception:
                            pass
                    elif "vram total" in lk:
                        try:
                            mem_total = round(float(v) / (1024 ** 2), 1)
                        except Exception:
                            pass
                    elif "vram total used" in lk:
                        try:
                            mem_used = round(float(v) / (1024 ** 2), 1)
                        except Exception:
                            pass
                devices.append(
                    {
                        "vendor": "AMD",
                        "name": name or str(gpu_key),
                        "usage_percent": usage,
                        "memory_used_mb": mem_used,
                        "memory_total_mb": mem_total,
                        "temperature_c": temp,
                        "source": "rocm-smi",
                    }
                )
            if devices:
                return {"available": True, "source": "rocm-smi", "devices": devices}

        # 3) Generic device listing fallback (no live stats)
        system = platform.system()
        devices = self._get_windows_video_controllers() if system == "Windows" else self._get_linux_pci_gpus()
        return {
            "available": len(devices) > 0,
            "source": devices[0]["source"] if devices else "none",
            "devices": devices,
        }

    def _read_windows_temperature_sensors(self, namespace: str) -> list[Dict]:
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            (
                f"Get-CimInstance -Namespace '{namespace}' -ClassName Sensor | "
                "Where-Object { $_.SensorType -eq 'Temperature' } | "
                "Select-Object Name,Value,Identifier | ConvertTo-Json -Compress"
            ),
        ]
        data = self._parse_json_output(self._run_command(cmd, timeout=4))
        rows = []
        for row in self._as_list(data):
            if not isinstance(row, dict):
                continue
            name = str(row.get("Name") or "")
            try:
                value = float(row.get("Value"))
            except Exception:
                continue
            rows.append(
                {
                    "name": name,
                    "value_c": round(value, 1),
                    "identifier": str(row.get("Identifier") or ""),
                }
            )
        return rows

    def _get_temperatures_info(self) -> Dict:
        data = self._get_lhm_json()
        if data:
            cpu_vals, gpu_vals = [], []

            for n in self._walk_lhm_nodes(data):
                text = str(n.get("Text", ""))
                value = str(n.get("Value", ""))

                # Берем только строки с °C
                if "°C" not in value and "C" not in value:
                    continue

                m = re.search(r"(-?\d+(?:\.\d+)?)", value)
                if not m:
                    continue
                t = float(m.group(1))

                ltxt = text.lower()
                if "cpu" in ltxt or "package" in ltxt or "tdie" in ltxt or "tctl" in ltxt:
                    cpu_vals.append(t)
                if "gpu" in ltxt or "graphics" in ltxt:
                    gpu_vals.append(t)

            if cpu_vals or gpu_vals:
                return {
                    "cpu_temp_c": max(cpu_vals) if cpu_vals else None,
                    "gpu_temp_c": max(gpu_vals) if gpu_vals else None,
                    "source": "lhm_web",
                }

        cpu_temp = self.get_cpu_temperature()
        if cpu_temp is not None:
            return {"cpu_temp_c": cpu_temp, "gpu_temp_c": None, "source": "builtin_linux"}

        return {"cpu_temp_c": None, "gpu_temp_c": None, "source": "none"}


        return {"cpu_temp_c": None, "gpu_temp_c": None, "source": "none"}

    def get_all_metrics(self) -> Dict:
        """Returns compact metrics for status output."""
        cpu_percent = psutil.cpu_percent(interval=0.5)
        ram = psutil.virtual_memory()
        temp = self.get_cpu_temperature()

        return {
            "cpu_percent": round(cpu_percent, 1),
            "cpu_temp": temp,
            "ram_percent": round(ram.percent, 1),
            "ram_used_mb": ram.used // (1024 ** 2),
            "ram_total_mb": ram.total // (1024 ** 2),
            "platform": platform.system(),
            "timestamp": time.time(),
        }

    def _get_lhm_json(self, url="http://127.0.0.1:8085/data.json"):
        try:
            with urlopen(url, timeout=2) as r:
                return json.loads(r.read().decode("utf-8", errors="ignore"))
        except Exception:
            return None

    def _walk_lhm_nodes(self, node):
        yield node
        for ch in node.get("Children", []) or []:
            yield from self._walk_lhm_nodes(ch)

# Create single instance
metrics = SystemMetrics()
