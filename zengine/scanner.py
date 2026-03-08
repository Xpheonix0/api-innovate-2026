"""
System scanning utilities
"""

import datetime
import socket
import subprocess
import re
from typing import Dict, Any


def check_internet_connection(timeout=3):
    """Check internet connection with timeout (non-blocking)"""
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
        return True
    except OSError:
        return False
    finally:
        socket.setdefaulttimeout(None)


def system_scanner() -> Dict[str, Any]:
    snapshot = {
        "timestamp": datetime.datetime.now().isoformat(),
        "error": None,
        "system": {},
        "cpu": {},
        "memory": {},
        "storage": [],
        "processes": [],
        "power_plan": {}
    }
    
    try:
        import psutil
        import platform
        
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.datetime.now() - boot_time
        
        snapshot["system"] = {
            "os": f"{platform.system()} {platform.release()}",
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "hostname": platform.node(),
            "boot_time": boot_time.strftime("%Y-%m-%d %H:%M:%S"),
            "uptime_days": round(uptime.total_seconds() / 86400, 1)
        }
        
        cpu_freq = psutil.cpu_freq()
        snapshot["cpu"] = {
            "name": platform.processor(),
            "cores_physical": psutil.cpu_count(logical=False) or 0,
            "cores_logical": psutil.cpu_count(logical=True) or 0,
            "usage_percent": round(psutil.cpu_percent(interval=1), 1),
            "frequency_mhz": round(cpu_freq.current, 0) if cpu_freq else 0,
            "max_frequency_mhz": round(cpu_freq.max, 0) if cpu_freq else 0
        }
        
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        snapshot["memory"] = {
            "total_gb": round(mem.total / (1024**3), 1),
            "available_gb": round(mem.available / (1024**3), 1),
            "used_gb": round(mem.used / (1024**3), 1),
            "usage_percent": mem.percent,
            "swap_total_gb": round(swap.total / (1024**3), 1) if swap.total else 0,
            "swap_used_gb": round(swap.used / (1024**3), 1) if swap.used else 0,
            "swap_percent": swap.percent if swap.total else 0
        }
        
        for part in psutil.disk_partitions():
            if 'cdrom' in part.opts or part.fstype == '':
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
                snapshot["storage"].append({
                    "drive": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total": round(usage.total / (1024**3), 1),
                    "used": round(usage.used / (1024**3), 1),
                    "free": round(usage.free / (1024**3), 1),
                    "percent": usage.percent
                })
            except:
                continue
        
        processes = []
        for proc in sorted(psutil.process_iter(['name', 'memory_percent']), 
                          key=lambda x: x.info.get('memory_percent', 0), reverse=True)[:10]:
            try:
                processes.append({
                    "name": proc.info.get('name', 'Unknown'),
                    "mem": round(proc.info.get('memory_percent', 0), 1)
                })
            except:
                pass
        snapshot["processes"] = processes
        
        try:
            result = subprocess.run(['powercfg', '/getactivescheme'], 
                                   capture_output=True, text=True, timeout=2)
            match = re.search(r'\((.*?)\)', result.stdout)
            snapshot["power_plan"] = {"name": match.group(1) if match else "Balanced"}
        except:
            snapshot["power_plan"] = {"name": "Unknown"}
        
    except Exception as e:
        snapshot["error"] = str(e)
    
    return snapshot
