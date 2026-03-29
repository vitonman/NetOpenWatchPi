# core/display.py - Colored console output for Retro CRT style

from datetime import datetime
from typing import Dict
import os
import platform


# ANSI color codes
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'


def clear_screen():
    """Clear console screen for clean monitor look"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_header():
    """Print retro-style header"""
    print(f"\n{Colors.CYAN}{'=' * 80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}   RETRO CRT MONITOR   |   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}   {Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 80}{Colors.RESET}")


def get_temp_color(temp: float) -> str:
    if temp is None:
        return Colors.RED
    if temp < 60:
        return Colors.GREEN
    elif temp < 75:
        return Colors.YELLOW
    else:
        return Colors.RED


def print_metrics(metrics_dict: Dict):
    """Print all metrics with nice colors"""
    cpu = metrics_dict["cpu_percent"]
    temp = metrics_dict["cpu_temp"]
    ram_percent = metrics_dict["ram_percent"]
    ram_used = metrics_dict["ram_used_mb"]
    ram_total = metrics_dict["ram_total_mb"]
    platform_name = metrics_dict["platform"]

    # CPU Usage
    if cpu > 80:
        cpu_color = Colors.RED
    elif cpu > 50:
        cpu_color = Colors.YELLOW
    else:
        cpu_color = Colors.GREEN

    print(f" {Colors.WHITE}CPU Usage       :{Colors.RESET} {cpu_color}{cpu:6.1f} %{Colors.RESET}   "
          f"[{cpu_color}{'HIGH' if cpu > 80 else 'MEDIUM' if cpu > 50 else 'LOW'}{Colors.RESET}]")

    # CPU Temperature
    if temp is not None:
        temp_color = get_temp_color(temp)
        status = "NORMAL" if temp < 65 else "WARM" if temp < 80 else "HOT"
        print(f" {Colors.WHITE}CPU Temperature :{Colors.RESET} {temp_color}{status:6}  {temp:5.1f} °C{Colors.RESET}")
    else:
        if platform_name == "Windows":
            print(f" {Colors.WHITE}CPU Temperature :{Colors.RESET} {Colors.RED}N/A (Windows needs external tool){Colors.RESET}")
        else:
            print(f" {Colors.WHITE}CPU Temperature :{Colors.RESET} {Colors.RED}N/A{Colors.RESET}")

    # RAM Usage
    if ram_percent > 85:
        ram_color = Colors.RED
    elif ram_percent > 70:
        ram_color = Colors.YELLOW
    else:
        ram_color = Colors.GREEN

    print(f" {Colors.WHITE}RAM Usage       :{Colors.RESET} {ram_color}{ram_percent:6.1f} %{Colors.RESET}   "
          f"({ram_used:5d} MB / {ram_total:5d} MB)")

    print(f"{Colors.CYAN}{'-' * 80}{Colors.RESET}")
    print(f"{Colors.GRAY} Next update in 3 seconds...{Colors.RESET}\n")


def print_startup_info():
    """Print startup banner"""
    print(f"{Colors.CYAN}=== Retro CRT System Monitor Started ==={Colors.RESET}")
    print(f"{Colors.WHITE}Running on: {platform.system()} {platform.release()}{Colors.RESET}\n")