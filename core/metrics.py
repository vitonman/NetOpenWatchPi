# core/metrics.py - System metrics collection

import time
import psutil
import platform
import subprocess
from typing import Dict, Optional


class SystemMetrics:
    """Main class responsible for collecting all system information"""

    def get_cpu_temperature(self) -> Optional[float]:
        """Returns CPU temperature or None if not available"""
        system = platform.system()

        # Raspberry Pi (Linux)
        if system == "Linux":
            # Method 1: gpiozero
            try:
                from gpiozero import CPUTemperature
                temp = CPUTemperature().temperature
                return round(temp, 1)
            except:
                pass

            # Method 2: /sys
            try:
                with open('/sys/class/thermal/thermal_zone0/temp') as f:
                    return round(int(f.read().strip()) / 1000.0, 1)
            except:
                pass

            # Method 3: vcgencmd
            try:
                output = subprocess.check_output(['vcgencmd', 'measure_temp'], timeout=2).decode().strip()
                return float(output.split('=')[1].split("'")[0])
            except:
                pass

        # Windows - currently not supported without external tool
        return None

    def get_all_metrics(self) -> Dict:
        """Returns all system metrics in one dictionary"""
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
            "timestamp": time.time()
        }


# Create single instance (this line is very important!)
metrics = SystemMetrics()