"""
Backup and restore functionality
"""

import os
import subprocess
import json
import datetime
import threading
import re
from pathlib import Path
from typing import Optional, Tuple


class BackupManager:
    """Manages system backups for reverse/undo functionality"""
    
    def __init__(self):
        self._lock = threading.Lock()
        self.backup_dir = Path.home() / "Z-Engine_Backups"
        self.current_backup = None
        self.backup_history = []
        self.load_history()
    
    def load_history(self):
        with self._lock:
            if self.backup_dir.exists():
                self.backup_history = sorted([
                    d for d in self.backup_dir.iterdir() 
                    if d.is_dir() and d.name.startswith("backup_")
                ], reverse=True)
                if self.backup_history:
                    self.current_backup = self.backup_history[0]
    
    def _validate_backup_path(self, path: Path) -> bool:
        """Validate that a backup path is within the backup directory"""
        try:
            return str(path.resolve()).startswith(str(self.backup_dir.resolve()))
        except Exception:
            return False
    
    def create_backup(self, description: str = "Pre-optimization state") -> Optional[Path]:
        try:
            with self._lock:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = self.backup_dir / f"backup_{timestamp}"
                backup_path.mkdir(parents=True, exist_ok=True)
                
                if not self._validate_backup_path(backup_path):
                    print("Error: Invalid backup path")
                    return None
                
                # Backup services state (read-only)
                services_backup = backup_path / "services.csv"
                subprocess.run(
                    ['powershell', '-Command', 
                     f'Get-Service | Select Name, Status, StartType | Export-Csv "{services_backup}"'],
                    capture_output=True, timeout=30, check=False
                )
                
                # Backup startup items (read-only)
                startup_backup = backup_path / "startup.txt"
                subprocess.run(
                    ['powershell', '-Command', 
                     f'Get-CimInstance Win32_StartupCommand | Select Name, Command, Location | Out-File "{startup_backup}"'],
                    capture_output=True, timeout=30, check=False
                )
                
                metadata = {
                    "timestamp": timestamp,
                    "description": description,
                    "files": ["services.csv", "startup.txt"]
                }
                
                with open(backup_path / "metadata.json", 'w') as f:
                    json.dump(metadata, f, indent=2)
                
                self.current_backup = backup_path
                self.backup_history.insert(0, backup_path)
                return backup_path
            
        except Exception as e:
            print(f"Backup failed: {e}")
            return None
    
    def restore_backup(self, backup_path: Path = None) -> bool:
        with self._lock:
            if backup_path is None:
                backup_path = self.current_backup
            
            if not backup_path or not backup_path.exists():
                return False
            
            if not self._validate_backup_path(backup_path):
                print("Error: Invalid backup path for restore")
                return False
            
            try:
                # Validate registry file before importing
                registry_backup = backup_path / "registry.reg"
                if registry_backup.exists():
                    if registry_backup.suffix.lower() != '.reg':
                        print("Error: Invalid registry file extension")
                        return False
                    
                    with open(registry_backup, 'rb') as f:
                        header = f.read(4)
                        if not header.startswith(b'REGEDIT'):
                            print("Error: Invalid registry file format")
                            return False
                    
                    subprocess.run(
                        ['reg', 'import', str(registry_backup)],
                        capture_output=True, timeout=30, check=False
                    )
                
                metadata_path = backup_path / "metadata.json"
                if metadata_path.exists():
                    with open(metadata_path, 'r') as f:
                        metadata = json.load(f)
                        print(f"Restored from backup: {metadata.get('description', 'Unknown')}")
                
                return True
                
            except Exception as e:
                print(f"Restore failed: {e}")
                return False
    
    def get_latest_backup(self) -> Optional[Path]:
        with self._lock:
            if self.backup_history:
                return self.backup_history[0]
            return None


class RestorePointCreator:
    """Creates Windows system restore points safely"""
    
    @staticmethod
    def create_restore_point(description: str = "Z-Engine Optimization") -> Tuple[bool, str]:
        if os.name != 'nt':
            return False, "Restore points are only supported on Windows"
        
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            
            if not is_admin:
                return False, "Restore points require Administrator privileges"
            
            safe_description = re.sub(r'[^a-zA-Z0-9\s\-_]', '', description)[:100]
            
            subprocess.run(
                ['powershell', '-Command', 
                 'Enable-ComputerRestore -Drive "C:\\" -ErrorAction SilentlyContinue'],
                capture_output=True, timeout=10, check=False
            )
            
            result = subprocess.run(
                ['powershell', '-Command', 
                 f'Checkpoint-Computer -Description "{safe_description}" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop'],
                capture_output=True, text=True, timeout=30, check=False
            )
            
            if result.returncode == 0:
                return True, "Restore point created successfully"
            else:
                return False, f"Failed: {result.stderr}"
        except subprocess.TimeoutExpired:
            return False, "Restore point creation timed out"
        except Exception as e:
            return False, str(e)
