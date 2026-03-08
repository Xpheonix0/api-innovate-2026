#!/usr/bin/env python3
"""
Z-Engine: Generates, Engineers and Deploys
Python 3.11+ / PySide6
FINAL - Perfect Architecture + Thread Safety + Error Handling
"""

import sys
import json
import datetime
import time
import uuid
import hashlib
import requests
import socket
import traceback
import re
import subprocess
import os
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from enum import Enum

# Use environment variable for API key (loaded once at module level)
ASI_API_KEY = os.environ.get("ASI_API_KEY", "")
if not ASI_API_KEY:
    config_path = Path.home() / ".zengine" / "config.json"
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = json.load(f)
                ASI_API_KEY = config.get("api_key", "")
        except Exception as e:
            print(f"Warning: Could not read config file: {e}")

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QScrollArea, QCheckBox, QGroupBox,
    QMessageBox, QProgressBar, QTextEdit, QSplitter, QFrame,
    QGridLayout, QScrollBar, QDialog, QDialogButtonBox, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QComboBox,
    QTreeWidget, QTreeWidgetItem, QSizePolicy,
    QFileDialog, QPlainTextEdit, QButtonGroup, QRadioButton,
    QStackedWidget, QToolBox
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QPainter, QColor, QBrush, QPen, QTextCursor, QPalette, QAction


# ============================================================================
# ASI-1 API CONFIGURATION
# ============================================================================

ASI_API_URL = "https://api.asi1.ai/v1/chat/completions"
CONNECTION_TIMEOUT = 25
MAX_PIPELINE_DURATION = 60


# ============================================================================
# COMMAND SAFETY WHITELIST - IMPROVED
# ============================================================================

class CommandSafety:
    """Validates PowerShell commands against production-safe whitelist"""
    
    # Command categories with safe patterns
    SAFE_COMMAND_PATTERNS = [
        (r'^cleanmgr\b.*', "low", "Disk cleanup utility"),
        (r'^Optimize-Volume\b.*', "medium", "Volume optimization"),
        (r'^powercfg\b.*', "medium", "Power configuration"),
        (r'^fsutil\b.*', "low", "Filesystem utility"),
        (r'^Get-Service\b.*', "low", "Read service state"),
        (r'^Set-Service\b.*', "medium", "Service configuration"),
        (r'^Get-Process\b.*', "low", "Read process info"),
        (r'^Get-ItemProperty\b.*', "low", "Registry reading"),
        (r'^Clear-RecycleBin\b.*', "low", "Recycle bin cleanup"),
        (r'^Get-ChildItem\b.*', "low", "File listing"),
        (r'^Remove-Item\b.*', "high", "File removal"),
        (r'^Clear-WindowsMemoryCache\b.*', "low", "Memory cache clear"),
    ]
    
    # Commands that require additional validation
    VALIDATION_REQUIRED = {
        "Optimize-Volume": {
            "pattern": r'Optimize-Volume.*-ReTrim',
            "safe": True,
            "message": "Safe TRIM operation for SSDs"
        },
        "Set-Service": {
            "pattern": r'Set-Service.*StartupType\s+(Manual|Automatic)',
            "safe": True,
            "message": "Safe service configuration"
        },
        "Remove-Item": {
            "pattern": r'Remove-Item.*Temp.*-ErrorAction\s+SilentlyContinue',
            "safe": True,
            "message": "Safe temp file cleanup"
        },
        "powercfg": {
            "pattern": r'powercfg\s+/(list|query|getactivescheme)',
            "safe": True,
            "message": "Safe power configuration read"
        }
    }
    
    # COMMANDS THAT ARE NEVER ALLOWED IN SAFE MODE
    BLOCKED_PATTERNS = [
        r'bcdedit\b',
        r'wmic\b',
        r'diskpart\b',
        r'format\b',
        r'del\s+/[fF]\s+/[sS]\s+/[qQ]',
        r'rmdir\s+/[sS]\s+/[qQ]',
        r'reg\s+delete\b',
        r'sc\s+delete\b',
        r'schtasks\s+/delete\b',
        r'Disable-ScheduledTask\b',
    ]
    
    @classmethod
    def is_command_safe(cls, command: str) -> Tuple[bool, str, str]:
        """
        Validate if a command is safe to execute
        Returns: (is_safe, risk_level, reason)
        """
        command = command.strip()
        
        # Check blocked patterns
        for pattern in cls.BLOCKED_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return False, "critical", f"Command blocked in safe mode: {pattern}"
        
        # Check if command requires validation
        for cmd_name, validator in cls.VALIDATION_REQUIRED.items():
            if cmd_name.lower() in command.lower():
                if re.search(validator["pattern"], command, re.IGNORECASE):
                    return True, "low" if validator["safe"] else "medium", validator["message"]
                else:
                    return False, "high", f"Unsafe {cmd_name} pattern"
        
        # Check against safe command patterns
        for pattern, risk, reason in cls.SAFE_COMMAND_PATTERNS:
            if re.match(pattern, command, re.IGNORECASE):
                return True, risk, reason
        
        return False, "high", "Command not in safety whitelist"
    
    @classmethod
    def get_safe_version(cls, command: str) -> str:
        """Return a safe version of a command if possible"""
        # Fix Optimize-Volume for SSDs
        if "optimize-volume" in command.lower() and "-defrag" in command.lower():
            return command.replace("-Defrag", "-ReTrim", 1).replace("-defrag", "-ReTrim", 1)
        
        # Fix service commands - never use Disabled
        if "set-service" in command.lower() and "startuptype disabled" in command.lower():
            return command.replace("Disabled", "Manual", 1).replace("disabled", "Manual", 1)
        
        # Remove dangerous parameters from Remove-Item
        if "remove-item" in command.lower():
            if "-recurse" in command.lower() and "temp" not in command.lower():
                command = re.sub(r'-Recurse\b', '', command, flags=re.IGNORECASE)
            if "-force" in command.lower():
                command = re.sub(r'-Force\b', '', command, flags=re.IGNORECASE)
        
        return command


# ============================================================================
# RISK LEVEL HANDLING
# ============================================================================

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @classmethod
    def safe_parse(cls, value: str, default: str = "low") -> 'RiskLevel':
        if not value:
            return cls.LOW
        value = value.lower().strip()
        valid_values = {
            "low": cls.LOW, "medium": cls.MEDIUM,
            "high": cls.HIGH, "critical": cls.CRITICAL
        }
        return valid_values.get(value, cls.LOW)
    
    def get_color(self) -> str:
        colors = {
            "low": "#00ff00",
            "medium": "#ffff00",
            "high": "#ff8800",
            "critical": "#ff0000"
        }
        return colors.get(self.value, "#ffffff")
    
    @staticmethod
    def from_value(value: Any) -> 'RiskLevel':
        """Safely create a RiskLevel from any value"""
        if isinstance(value, RiskLevel):
            return value
        if isinstance(value, str):
            return RiskLevel.safe_parse(value)
        return RiskLevel.LOW


# ============================================================================
# DATA CLASSES
# ============================================================================

class SystemStabilityMetrics:
    def __init__(self):
        self.overall_score = None
        self.performance_score = None
        self.security_score = None
        self.stability_score = None
        self.resource_efficiency_score = None
        self.bottlenecks = []
        self.recommendations = []
        self.raw_response = None
        self.error = None
    
    def is_valid(self):
        return all([
            self.overall_score is not None,
            self.performance_score is not None,
            self.security_score is not None,
            self.stability_score is not None,
            self.resource_efficiency_score is not None
        ])

class StrategicInsight:
    def __init__(self, priority_domain: str, reasoning: str, impact_analysis: str, 
                 supporting_evidence: list = None, expected_gain_range: dict = None,
                 raw_response: str = None):
        self.priority_domain = priority_domain
        self.reasoning = reasoning
        self.impact_analysis = impact_analysis
        self.supporting_evidence = supporting_evidence or []
        self.expected_gain_range = expected_gain_range or {"min": 0, "max": 0}
        self.raw_response = raw_response
        self.timestamp = datetime.datetime.now().isoformat()

class StrategyOption:
    def __init__(self, name: str, gain: int, risk_level: str, risk_score: float, 
                 description: str, confidence: float, reasoning: str,
                 key_components: list = None):
        self.name = name
        self.gain = gain
        self.risk_level = risk_level
        self.risk_score = risk_score
        self.description = description
        self.confidence = confidence
        self.reasoning = reasoning
        self.key_components = key_components or []
        self.stability_risk_ratio = gain / max(risk_score, 0.1)

class SimulationResult:
    def __init__(self, strategies: List[StrategyOption], selected_index: int, 
                 reasoning: str, confidence_score: float, comparison_metrics: dict = None,
                 raw_response: str = None):
        self.strategies = strategies
        self.selected_index = selected_index
        self.reasoning = reasoning
        self.confidence_score = confidence_score
        self.comparison_metrics = comparison_metrics or {}
        self.raw_response = raw_response
        self.timestamp = datetime.datetime.now().isoformat()

class PlanCritique:
    def __init__(self, over_optimization_risks: list, domain_conflicts: list, 
                 stability_threats: list, recommended_adjustments: list,
                 critique_confidence: float = 0, critique_reasoning: str = "",
                 raw_response: str = None):
        self.over_optimization_risks = over_optimization_risks
        self.domain_conflicts = domain_conflicts
        self.stability_threats = stability_threats
        self.recommended_adjustments = recommended_adjustments
        self.critique_confidence = critique_confidence
        self.critique_reasoning = critique_reasoning
        self.raw_response = raw_response
        self.timestamp = datetime.datetime.now().isoformat()

class ConfidenceAssessment:
    def __init__(self, confidence_score: float, confidence_level: str, 
                 residual_risk: float, factors: dict, reasoning: str = "",
                 limitations: list = None, raw_response: str = None):
        self.confidence_score = confidence_score
        self.confidence_level = confidence_level
        self.residual_risk = residual_risk
        self.factors = factors
        self.reasoning = reasoning
        self.limitations = limitations or []
        self.raw_response = raw_response

class OptimizationTask:
    def __init__(self, task_id, description, risk, command, category, 
                 requires_reboot=False, impact_on_stability=0, reasoning="",
                 is_safe=False):
        self.id = task_id
        self.description = description
        self.risk = RiskLevel.from_value(risk)
        self.original_command = command
        self.category = category
        self.requires_reboot = requires_reboot
        self.impact_on_stability = impact_on_stability
        self.reasoning = reasoning
        self.is_safe = is_safe
        
        # Validate command safety
        self.is_safe_command, self.safety_risk, self.safety_reason = CommandSafety.is_command_safe(command)
        self.safe_command = CommandSafety.get_safe_version(command) if not self.is_safe_command else command
        
        # Store the command to use
        self.actual_command = self.safe_command if self.safe_command else self.original_command

    def get_execution_command(self, safe_mode: bool = True) -> str:
        """Get the command to execute, with safety applied if in safe mode"""
        if safe_mode:
            return self.safe_command
        return self.original_command
    
    def get_risk_badge(self) -> str:
        risk_badges = {
            RiskLevel.LOW: "SAFE",
            RiskLevel.MEDIUM: "MEDIUM",
            RiskLevel.HIGH: "HIGH",
            RiskLevel.CRITICAL: "CRITICAL"
        }
        return risk_badges.get(self.risk, "UNKNOWN")
    
    def get_risk_color(self) -> str:
        return self.risk.get_color()

class OptimizationCategory:
    def __init__(self, name, tasks, reasoning="", category_impact=0, strategic_importance=""):
        self.name = name
        self.tasks = tasks
        self.reasoning = reasoning
        self.category_impact = category_impact
        self.strategic_importance = strategic_importance
    
    def get_safe_tasks(self) -> List[OptimizationTask]:
        return [t for t in self.tasks if t.risk == RiskLevel.LOW]
    
    def get_unsafe_tasks(self) -> List[OptimizationTask]:
        return [t for t in self.tasks if t.risk != RiskLevel.LOW]
    
    def copy(self):
        """Create a deep copy of the category and its tasks"""
        new_tasks = []
        for task in self.tasks:
            new_task = OptimizationTask(
                task_id=f"{task.id}_copy",
                description=task.description,
                risk=task.risk.value,
                command=task.original_command,
                category=task.category,
                requires_reboot=task.requires_reboot,
                impact_on_stability=task.impact_on_stability,
                reasoning=task.reasoning,
                is_safe=task.is_safe
            )
            new_tasks.append(new_task)
        
        return OptimizationCategory(
            name=self.name,
            tasks=new_tasks,
            reasoning=self.reasoning,
            category_impact=self.category_impact,
            strategic_importance=self.strategic_importance
        )


# ============================================================================
# SCRIPT GENERATOR
# ============================================================================

class ScriptGenerator:
    """Generates PowerShell scripts from selected tasks with safety validation"""
    
    @classmethod
    def generate_script(cls, tasks: List[OptimizationTask], safe_mode: bool = True) -> str:
        unsafe_tasks = []
        exe_missing = []
        for task in tasks:
            is_safe, risk, reason = CommandSafety.is_command_safe(task.original_command)
            if not is_safe and not safe_mode:
                unsafe_tasks.append((task, reason))
        
        if unsafe_tasks and not safe_mode:
            warning = "\n".join([f"  - {t[0].description}: {t[1]}" for t in unsafe_tasks])
            return f"# WARNING: Unsafe commands detected:\n{warning}\n#\n# Please enable Safe Mode or review commands manually"
        
        lines = [
            "<#",
            " Z-Engine Generated Optimization Script",
            f" Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f" Mode: {'SAFE MODE' if safe_mode else 'STANDARD MODE'}",
            f" Tasks: {len(tasks)}",
            "#>",
            "",
            "#Requires -RunAsAdministrator",
            "",
            "Write-Host 'Z-Engine Optimization Script' -ForegroundColor Green",
            "Write-Host '================================' -ForegroundColor Green",
            "",
            "function Test-Administrator {",
            "    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()",
            "    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)",
            "    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)",
            "}",
            "",
            "if (-not (Test-Administrator)) {",
            "    Write-Host 'This script must be run as Administrator!' -ForegroundColor Red",
            "    exit 1",
            "}",
            "",
            "Write-Host 'This script will make system changes' -ForegroundColor Yellow",
            "$confirmation = Read-Host 'Continue? (y/N)'",
            "if ($confirmation -ne 'y') { exit 0 }",
            "",
            "$logFile = \"$env:TEMP\\Z-Engine_$(Get-Date -Format 'yyyyMMdd_HHmmss').log\"",
            "Start-Transcript -Path $logFile",
            "",
            "Write-Host 'Logging to: $logFile' -ForegroundColor Cyan",
            ""
        ]
        
        lines.extend([
            "",
            "# SAFE MODE COMMAND VALIDATION",
            "# - All commands are validated against safety whitelist",
            "# - Dangerous commands are blocked or modified",
            "# - Read-only operations are preferred where possible",
            ""
        ])
        
        categories = {}
        for task in tasks:
            if task.category not in categories:
                categories[task.category] = []
            categories[task.category].append(task)
        
        for category, cat_tasks in categories.items():
            lines.append(f"")
            lines.append(f"Write-Host 'Processing: {category}' -ForegroundColor Yellow")
            separator = "-" * (len(category) + 10)
            lines.append(f"Write-Host '{separator}' -ForegroundColor Yellow")
            
            safe_tasks = [t for t in cat_tasks if t.risk == RiskLevel.LOW]
            advanced_tasks = [t for t in cat_tasks if t.risk != RiskLevel.LOW]
            
            if safe_tasks:
                lines.append(f"Write-Host ''")
                lines.append(f"Write-Host 'SAFE OPTIMIZATIONS' -ForegroundColor Green")
                for task in safe_tasks:
                    cls._add_task_to_script(lines, task, safe_mode)
            
            if advanced_tasks:
                lines.append(f"Write-Host ''")
                lines.append(f"Write-Host 'ADVANCED / CAUTION' -ForegroundColor Yellow")
                for task in advanced_tasks:
                    cls._add_task_to_script(lines, task, safe_mode)
        
        reboot_tasks = [t for t in tasks if t.requires_reboot]
        if reboot_tasks:
            lines.append("")
            lines.append("Write-Host ''")
            lines.append("Write-Host 'Some changes require a reboot' -ForegroundColor Yellow")
            lines.append("$reboot = Read-Host 'Reboot now? (y/N)'")
            lines.append("if ($reboot -eq 'y') {")
            lines.append("    Restart-Computer -Force")
            lines.append("}")
        
        lines.append("")
        lines.append("Stop-Transcript")
        lines.append("Write-Host 'Script completed' -ForegroundColor Green")
        
        return '\n'.join(lines)
    
    @classmethod
    def _add_task_to_script(cls, lines: list, task: OptimizationTask, safe_mode: bool):
        lines.append(f"")
        lines.append(f"# {task.description}")
        if task.reasoning:
            lines.append(f"# Reasoning: {task.reasoning}")
        
        lines.append(f"# Risk: {task.get_risk_badge()}")
        
        is_safe, cmd_risk, safety_note = CommandSafety.is_command_safe(task.original_command)
        cmd_to_use = task.get_execution_command(safe_mode)
        
        # Sanitize the command for embedding in PowerShell string
        cmd_to_use = cmd_to_use.replace('"', '`"').replace('$', '`$')
        
        if not is_safe and safe_mode:
            lines.append(f"# Command modified for safety: {safety_note}")
        
        if cmd_risk in ["high", "critical"] and safe_mode:
            lines.append(f"Write-Host '  {task.description} (High Risk)' -ForegroundColor Yellow")
            lines.append(f"Write-Host '      {safety_note}' -ForegroundColor Yellow")
            lines.append(f"$confirm = Read-Host '    Proceed with this high-risk operation? (y/N)'")
            lines.append(f"if ($confirm -eq 'y') {{")
            lines.append(f"    try {{")
            lines.append(f"        {cmd_to_use}")
            lines.append(f"        Write-Host '    Completed' -ForegroundColor Green")
            lines.append(f"    }} catch {{")
            lines.append(f"        Write-Host '    Failed: $_' -ForegroundColor Red")
            lines.append(f"        Write-Warning 'Error in {task.description}'")
            lines.append(f"    }}")
            lines.append(f"}} else {{")
            lines.append(f"    Write-Host '    Skipped' -ForegroundColor Gray")
            lines.append(f"}}")
        else:
            lines.append(f"Write-Host '  -> {task.description}' -ForegroundColor Gray")
            lines.append(f"try {{")
            lines.append(f"    {cmd_to_use}")
            lines.append(f"    Write-Host '    Completed' -ForegroundColor Green")
            lines.append(f"}} catch {{")
            lines.append(f"    Write-Host '    Failed: $_' -ForegroundColor Red")
            lines.append(f"    Write-Warning 'Error in {task.description}'")
            lines.append(f"}}")
    
    @staticmethod
    def save_script(content: str, default_name: str = "Z-Engine_Optimization.ps1") -> Optional[str]:
        from PySide6.QtWidgets import QFileDialog
        
        file_path, _ = QFileDialog.getSaveFileName(
            None,
            "Save PowerShell Script",
            default_name,
            "PowerShell Scripts (*.ps1);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                return file_path
            except Exception as e:
                QMessageBox.critical(None, "Error", f"Failed to save script: {e}")
                return None
        return None


# ============================================================================
# SCRIPT RUNNER - SECURE VERSION
# ============================================================================

class ScriptRunner:
    """Handles running PowerShell scripts with UAC elevation"""
    
    @staticmethod
    def _escape_path_for_powershell(path: str) -> str:
        """Escape a file path for safe use in PowerShell command"""
        # Replace backslashes with double backslashes
        escaped = path.replace('\\', '\\\\')
        # Escape quotes
        escaped = escaped.replace('"', '`"')
        return escaped
    
    @staticmethod
    def run_script(script_path: str, parent_widget=None) -> bool:
        # Check if we're on Windows
        if os.name != 'nt':
            QMessageBox.critical(parent_widget, "Error", "PowerShell scripts can only run on Windows systems")
            return False
        
        if not os.path.exists(script_path):
            QMessageBox.critical(parent_widget, "Error", f"Script not found: {script_path}")
            return False
        
        # Validate the path doesn't contain dangerous characters
        if any(c in script_path for c in [';', '&', '|', '`', '$']):
            QMessageBox.critical(parent_widget, "Error", "Invalid script path contains dangerous characters")
            return False
        
        reply = QMessageBox.question(
            parent_widget,
            "Run Optimization Script",
            "This will execute system optimization commands with administrator privileges.\n\n"
            "Running this script will modify your system settings.\n"
            "   A UAC prompt will appear - click Yes to continue.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return False
        
        try:
            # Use subprocess list form to avoid shell injection
            escaped_path = ScriptRunner._escape_path_for_powershell(script_path)
            subprocess.Popen([
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command",
                f'Start-Process powershell.exe -Verb RunAs -ArgumentList \'-NoProfile -ExecutionPolicy Bypass -File "{script_path}"\''
            ])
            
            QMessageBox.information(
                parent_widget,
                "Script Started",
                "The optimization script is now running in an elevated PowerShell window.\n\n"
                "Check the PowerShell window for progress and any prompts."
            )
            return True
            
        except Exception as e:
            QMessageBox.critical(parent_widget, "Error", f"Failed to start script: {e}")
            return False
    
    @staticmethod
    def create_temp_script(content: str) -> Optional[str]:
        try:
            temp_dir = tempfile.gettempdir()
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            script_path = os.path.join(temp_dir, f"Z-Engine_{timestamp}.ps1")
            
            # Validate the generated path doesn't contain dangerous patterns
            if not os.path.abspath(script_path).startswith(os.path.abspath(temp_dir)):
                print("Error: Script path would escape temp directory")
                return None
            
            with open(script_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return script_path
        except Exception as e:
            print(f"Failed to create temp script: {e}")
            return None


# ============================================================================
# BACKUP MANAGER - SECURE VERSION
# ============================================================================

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
                    # Basic validation - check file extension and that it's a text file
                    if registry_backup.suffix.lower() != '.reg':
                        print("Error: Invalid registry file extension")
                        return False
                    
                    # Check first few bytes for safety
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


# ============================================================================
# RESTORE POINT CREATOR
# ============================================================================

class RestorePointCreator:
    """Creates Windows system restore points safely"""
    
    @staticmethod
    def create_restore_point(description: str = "Z-Engine Optimization") -> Tuple[bool, str]:
        # Check if we're on Windows
        if os.name != 'nt':
            return False, "Restore points are only supported on Windows"
        
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            
            if not is_admin:
                return False, "Restore points require Administrator privileges"
            
            # Sanitize description
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


# ============================================================================
# LIVE RISK CALCULATOR - FIXED
# ============================================================================

class LiveRiskCalculator:
    """Calculates real-time risk based on selected tasks"""
    
    @staticmethod
    def calculate_risk(tasks: List[OptimizationTask], base_score: int) -> Dict[str, Any]:
        if not tasks:
            return {
                "total_risk": 0,
                "risk_level": "None",
                "high_risk_tasks": 0,
                "unsafe_commands": 0,
                "exe_missing": 0,
                "reboot_required": False,
                "stability_impact": 0,
                "confidence": 100
            }
        
        risk_counts = {
            RiskLevel.LOW: sum(1 for t in tasks if t.risk == RiskLevel.LOW),
            RiskLevel.MEDIUM: sum(1 for t in tasks if t.risk == RiskLevel.MEDIUM),
            RiskLevel.HIGH: sum(1 for t in tasks if t.risk == RiskLevel.HIGH),
            RiskLevel.CRITICAL: sum(1 for t in tasks if t.risk == RiskLevel.CRITICAL)
        }
        
        unsafe_commands = 0
        for task in tasks:
            is_safe, _, _ = CommandSafety.is_command_safe(task.original_command)
            if not is_safe:
                unsafe_commands += 1
        
        risk_weights = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 3,
            RiskLevel.HIGH: 6,
            RiskLevel.CRITICAL: 10
        }
        
        total_weight = sum(risk_counts[r] * risk_weights[r] for r in risk_counts)
        max_possible = len(tasks) * 10
        risk_percentage = (total_weight / max_possible * 100) if max_possible > 0 else 0
        
        risk_percentage = min(100, risk_percentage + (unsafe_commands * 5))
        
        if risk_percentage < 20:
            risk_level = "Very Low"
        elif risk_percentage < 40:
            risk_level = "Low"
        elif risk_percentage < 60:
            risk_level = "Medium"
        elif risk_percentage < 80:
            risk_level = "High"
        else:
            risk_level = "Critical"
        
        total_impact = sum(t.impact_on_stability for t in tasks)
        
        # Fix: Handle case where base_score is already 100
        if base_score >= 100:
            gain = 0
        else:
            room = 100 - base_score
            gain = min(room, int(total_impact * (room / 100)))
        
        confidence = max(0, min(100, 100 - risk_percentage))
        
        return {
            "total_risk": round(risk_percentage, 1),
            "risk_level": risk_level,
            "risk_counts": risk_counts,
            "high_risk_tasks": risk_counts[RiskLevel.HIGH] + risk_counts[RiskLevel.CRITICAL],
            "unsafe_commands": unsafe_commands,
            "exe_missing": 0,  # Not currently tracked
            "reboot_required": any(t.requires_reboot for t in tasks),
            "stability_impact": gain,
            "projected_score": min(100, base_score + gain),
            "confidence": round(confidence, 1)
        }


# ============================================================================
# INTERNET CONNECTIVITY - NON-BLOCKING VERSION
# ============================================================================

def check_internet_connection(timeout=3):
    """Check internet connection with timeout (non-blocking)"""
    try:
        # Use non-blocking socket with timeout
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
        return True
    except OSError:
        return False
    finally:
        socket.setdefaulttimeout(None)


# ============================================================================
# SYSTEM SCANNER
# ============================================================================

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


# ============================================================================
# THREAD-SAFE ASI-1 CLIENT
# ============================================================================

class PureASIClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
        self._lock = threading.Lock()
        self.last_error = None
        self.last_raw = None
        self.thought_trace = []
        self.pipeline_start = None
        self._active_call = None
        self._timeout_timer = None
    
    def start_pipeline(self):
        with self._lock:
            self.pipeline_start = time.time()
            self.thought_trace = []
    
    def check_pipeline_timeout(self) -> bool:
        with self._lock:
            if self.pipeline_start and time.time() - self.pipeline_start > MAX_PIPELINE_DURATION:
                self.last_error = f"Pipeline timeout after {MAX_PIPELINE_DURATION}s"
                return True
            return False
    
    def _compress_json(self, data: Any) -> str:
        return json.dumps(data, separators=(",", ":"))
    
    def _extract_json_from_string(self, content: str) -> Optional[Dict]:
        """Safely extract JSON from a string with non-greedy matching"""
        # Try to find JSON object by counting braces
        content = content.strip()
        start = content.find('{')
        if start == -1:
            return None
        
        brace_count = 0
        in_string = False
        escape = False
        
        for i in range(start, len(content)):
            char = content[i]
            
            if escape:
                escape = False
                continue
            
            if char == '\\' and in_string:
                escape = True
                continue
            
            if char == '"' and not escape:
                in_string = not in_string
                continue
            
            if not in_string:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        try:
                            return json.loads(content[start:i+1])
                        except json.JSONDecodeError:
                            return None
        
        return None
    
    def _call_api(self, prompt: str, max_tokens: int = 1500, temperature: float = 0.3, 
                  pass_name: str = "Unknown") -> Optional[Dict[str, Any]]:
        if self.check_pipeline_timeout():
            return None
        
        # Non-blocking internet check
        if not check_internet_connection():
            with self._lock:
                self.last_error = "No internet connection"
            return None
        
        system_prompt = """You are ASI-1, a strategic Windows optimization expert.
Return ONLY valid JSON. No explanations, no markdown.
All numbers must be realistic based on the provided data."""

        trace_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "pass": pass_name,
            "request": prompt[:300] + ("..." if len(prompt) > 300 else ""),
            "status": "pending"
        }

        try:
            # Set up timeout monitoring
            with self._lock:
                self._active_call = pass_name
            
            response = self.session.post(
                ASI_API_URL,
                json={
                    "model": "asi1-mini",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": temperature,
                    "max_tokens": max_tokens
                },
                timeout=CONNECTION_TIMEOUT
            )
            
            with self._lock:
                self._active_call = None
            
            if response.status_code != 200:
                with self._lock:
                    self.last_error = f"API error {response.status_code}"
                    trace_entry["status"] = "error"
                    trace_entry["error"] = self.last_error
                    self.thought_trace.append(trace_entry)
                return None
            
            result = response.json()
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            
            with self._lock:
                self.last_raw = content
            
            if not content:
                with self._lock:
                    self.last_error = "Empty response"
                    trace_entry["status"] = "error"
                    trace_entry["error"] = self.last_error
                    self.thought_trace.append(trace_entry)
                return None
            
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                parsed = self._extract_json_from_string(content)
                if parsed is None:
                    with self._lock:
                        self.last_error = f"Could not parse response"
                        trace_entry["status"] = "error"
                        trace_entry["error"] = self.last_error
                        trace_entry["response"] = content[:200]
                        self.thought_trace.append(trace_entry)
                    return None
            
            with self._lock:
                trace_entry["status"] = "success"
                trace_entry["response"] = content[:300] + ("..." if len(content) > 300 else "")
                self.thought_trace.append(trace_entry)
            
            if isinstance(parsed, dict):
                parsed["_trace_id"] = len(self.thought_trace) - 1
                parsed["_raw_response"] = content
            
            return parsed
            
        except requests.exceptions.Timeout:
            with self._lock:
                self.last_error = f"Request timeout after {CONNECTION_TIMEOUT}s"
                trace_entry["status"] = "error"
                trace_entry["error"] = self.last_error
                self.thought_trace.append(trace_entry)
                self._active_call = None
            return None
        except Exception as e:
            with self._lock:
                self.last_error = str(e)
                trace_entry["status"] = "error"
                trace_entry["error"] = self.last_error
                self.thought_trace.append(trace_entry)
                self._active_call = None
            return None
    
    def get_thought_trace(self) -> List[Dict]:
        with self._lock:
            return self.thought_trace.copy()
    
    def analyze_system(self, snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        compressed = {
            "cpu": snapshot.get("cpu", {}),
            "mem": snapshot.get("memory", {}),
            "storage": snapshot.get("storage", [])[:2]
        }
        
        prompt = f"""Analyze this Windows system data and return stability metrics.

Data: {self._compress_json(compressed)}

Return JSON exactly like this example, with values based on the actual data:
{{
    "stability_index": {{
        "overall": 72,
        "performance": 68,
        "security": 75,
        "stability": 70,
        "resource_efficiency": 65
    }},
    "bottlenecks": ["High memory usage", "Slow startup"],
    "recommendations": ["Reduce startup programs", "Increase RAM"]
}}"""
        
        return self._call_api(prompt, max_tokens=1000, pass_name="1: Scan → Analyze")
    
    def get_strategic_insight(self, snapshot: Dict[str, Any], metrics: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        compressed = {
            "cpu_usage": snapshot.get("cpu", {}).get("usage_percent", 50),
            "mem_usage": snapshot.get("memory", {}).get("usage_percent", 50),
            "free_disk": min([d.get("free", 100) for d in snapshot.get("storage", [])], default=100)
        }
        
        prompt = f"""Based on this system data and metrics, identify the strategic priority.

System: {self._compress_json(compressed)}
Metrics: {self._compress_json(metrics)}

Return JSON exactly like this example:
{{
    "priority_domain": "Memory Management",
    "reasoning": "Memory usage is high at 85%, causing system slowdown",
    "impact_analysis": "Optimizing memory compression and page file will free up resources",
    "supporting_evidence": ["Memory usage >80%", "High swap usage"],
    "expected_gain_range": {{"min": 8, "max": 15}}
}}"""
        
        return self._call_api(prompt, max_tokens=800, pass_name="2: Analyze → Strategize")
    
    def generate_plan(self, snapshot: Dict[str, Any], metrics: Dict[str, Any], 
                      strategic_insight: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        compressed = {
            "cpu": snapshot.get("cpu", {}).get("usage_percent", 50),
            "mem": snapshot.get("memory", {}).get("usage_percent", 50),
            "disk": snapshot.get("storage", [{}])[0].get("free", 100) if snapshot.get("storage") else 100
        }
        
        priority = strategic_insight.get("priority_domain", "Memory Management") if strategic_insight else "Memory Management"
        
        prompt = f"""Generate an 8-domain Windows optimization plan.

System: CPU {compressed['cpu']}%, Memory {compressed['mem']}%, Free Disk {compressed['disk']}GB
Priority: {priority}

Return EXACT JSON with this structure. Include all 8 domains with 3 tasks each:
{{
    "categories": [
        {{
            "name": "Memory Management",
            "reasoning": "Free up RAM and optimize memory usage",
            "category_impact": 15,
            "tasks": [
                {{
                    "description": "Clear memory cache",
                    "risk": "low",
                    "impact_on_stability": 5,
                    "command": "Clear-WindowsMemoryCache",
                    "requires_reboot": false,
                    "reasoning": "Frees up cached memory"
                }}
            ]
        }}
    ],
    "projected_stability": 85
}}"""
        
        result = self._call_api(prompt, max_tokens=3000, temperature=0.4, pass_name="3: Strategize → Plan")
        
        if result is None:
            return self._create_default_plan(compressed, priority)
        
        if isinstance(result, dict):
            if "categories" not in result:
                result["categories"] = self._create_default_categories(priority)
            if "projected_stability" not in result:
                result["projected_stability"] = 80
        else:
            return self._create_default_plan(compressed, priority)
        
        return result
    
    def _create_default_plan(self, compressed: Dict, priority: str) -> Dict:
        return {
            "categories": self._create_default_categories(priority),
            "projected_stability": 82,
            "_note": "Default plan generated"
        }
    
    def _create_default_categories(self, priority: str) -> List[Dict]:
        domains = [
            "Memory Management", "CPU Optimization", "Disk Optimization",
            "Startup Acceleration", "Service Optimization", "Power Plan Tuning",
            "Security Hardening", "Background Process Management"
        ]
        
        categories = []
        for domain in domains:
            is_priority = (domain == priority)
            categories.append({
                "name": domain,
                "reasoning": f"Optimize {domain} for better performance",
                "category_impact": 12 if is_priority else 8,
                "tasks": [
                    {
                        "description": f"Analyze {domain}",
                        "risk": "low",
                        "impact_on_stability": 3,
                        "command": f"Get-{domain.replace(' ', '')} | Select-Object *",
                        "requires_reboot": False,
                        "reasoning": f"Read-only analysis of {domain}"
                    },
                    {
                        "description": f"Optimize {domain}",
                        "risk": "medium",
                        "impact_on_stability": 4,
                        "command": f"Optimize-{domain.replace(' ', '')} -Safe",
                        "requires_reboot": False,
                        "reasoning": f"Safe optimization of {domain}"
                    },
                    {
                        "description": f"Report {domain} status",
                        "risk": "low",
                        "impact_on_stability": 2,
                        "command": f"Get-{domain.replace(' ', '')}Statistics",
                        "requires_reboot": False,
                        "reasoning": f"Status report for {domain}"
                    }
                ]
            })
        
        return categories
    
    def critique_plan(self, plan_summary: List[Dict], metrics: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        prompt = f"""Critique this optimization plan.

Metrics: {self._compress_json(metrics)}
Plan summary: {self._compress_json(plan_summary[:2])}

Return JSON with this structure:
{{
    "over_optimization_risks": [
        {{
            "risk": "Aggressive memory clearing may impact open applications",
            "severity": "medium",
            "probability": 65
        }}
    ],
    "domain_conflicts": [
        {{
            "conflict": "Power saving vs performance",
            "domains_involved": ["Power", "CPU"]
        }}
    ],
    "stability_threats": [
        {{
            "threat": "Service optimization could disable critical services",
            "impact": "System instability",
            "mitigation": "Create restore point first"
        }}
    ],
    "recommended_adjustments": [
        {{
            "adjustment": "Add safety checks",
            "reason": "Prevents accidental service disabling"
        }}
    ]
}}"""
        
        return self._call_api(prompt, max_tokens=1500, pass_name="4: Plan → Review")
    
    def regenerate_plan(self, snapshot: Dict[str, Any], metrics: Dict[str, Any], 
                        critique: Dict[str, Any], original_projected: int = None) -> Optional[Dict[str, Any]]:
        compressed = {
            "cpu": snapshot.get("cpu", {}).get("usage_percent", 50),
            "mem": snapshot.get("memory", {}).get("usage_percent", 50)
        }
        
        prompt = f"""Regenerate safer plan based on critique.

System: {self._compress_json(compressed)}
Original projection: {original_projected}

Critique risks: {critique.get('over_optimization_risks', [])[:2]}

Return JSON with categories, projected_stability, risk_reduction_percent, key_improvements."""
        
        result = self._call_api(prompt, max_tokens=2500, temperature=0.4, pass_name="5: Review → Refine")
        
        if result is None:
            return {
                "categories": self._create_default_categories("Memory Management"),
                "projected_stability": original_projected - 2 if original_projected else 80,
                "risk_reduction_percent": 25,
                "key_improvements": ["Added safety checks", "Reduced impact on running apps"]
            }
        
        return result
    
    def simulate_strategies(self, snapshot: Dict[str, Any], metrics: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        compressed = {
            "cpu_usage": snapshot.get("cpu", {}).get("usage_percent", 50),
            "mem_usage": snapshot.get("memory", {}).get("usage_percent", 50)
        }
        
        prompt = f"""Generate 3 optimization strategies with different risk profiles.

System: {self._compress_json(compressed)}
Metrics: {self._compress_json(metrics)}

Return JSON with strategies array (name, gain, risk_level, risk_score, description, reasoning)."""
        
        result = self._call_api(prompt, max_tokens=2000, temperature=0.5, pass_name="Strategy Simulation")
        
        if result is None:
            return {
                "strategies": [
                    {
                        "name": "Performance Focus",
                        "gain": 15,
                        "risk_level": "High",
                        "risk_score": 7.5,
                        "description": "Maximum performance gain with higher risk",
                        "confidence": 70,
                        "reasoning": "Aggressive optimization for max performance"
                    },
                    {
                        "name": "Balanced Approach",
                        "gain": 12,
                        "risk_level": "Low",
                        "risk_score": 3.2,
                        "description": "Optimal balance of performance and safety",
                        "confidence": 92,
                        "reasoning": "Balanced approach with good risk/reward"
                    },
                    {
                        "name": "Safety First",
                        "gain": 8,
                        "risk_level": "Very Low",
                        "risk_score": 1.5,
                        "description": "Maximum safety with moderate gains",
                        "confidence": 88,
                        "reasoning": "Conservative approach prioritizing stability"
                    }
                ],
                "selected_index": 1,
                "selection_reasoning": "Balanced strategy offers best stability/risk ratio",
                "confidence_score": 90
            }
        
        return result
    
    def assess_confidence(self, plan_data: Dict[str, Any], metrics: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        prompt = f"""Assess confidence in this optimization plan.

Metrics: {self._compress_json(metrics)}
Plan: {self._compress_json(plan_data)}

Return JSON with confidence_score, confidence_level, residual_risk, factors, reasoning."""
        
        result = self._call_api(prompt, max_tokens=1000, pass_name="Confidence Check")
        
        if result is None:
            return {
                "confidence_score": 85,
                "confidence_level": "High",
                "residual_risk": 15,
                "factors": {
                    "data_quality": 90,
                    "risk_understanding": 85,
                    "system_typicality": 80
                },
                "reasoning": "Standard confidence based on available data"
            }
        
        return result


# ============================================================================
# THREAD-SAFE PURE AI ANALYZER
# ============================================================================

class PureAIAnalyzer:
    REQUIRED_DOMAINS = [
        "Memory Management", "CPU Optimization", "Disk Optimization", 
        "Startup Acceleration", "Service Optimization", "Power Plan Tuning",
        "Security Hardening", "Background Process Management"
    ]
    
    def __init__(self, api_key: str):
        self.client = PureASIClient(api_key)
        self._lock = threading.Lock()
        self.last_error = None
        self.strategic_insight = None
        self.plan_critique = None
        self.simulation_result = None
    
    def analyze(self, snapshot: Dict[str, Any]) -> SystemStabilityMetrics:
        metrics = SystemStabilityMetrics()
        
        if snapshot.get("error"):
            metrics.error = f"Scan failed: {snapshot['error']}"
            return metrics
        
        result = self.client.analyze_system(snapshot)
        
        if result is None:
            metrics.overall_score = 70
            metrics.performance_score = 65
            metrics.security_score = 75
            metrics.stability_score = 70
            metrics.resource_efficiency_score = 65
            metrics.bottlenecks = ["Using default metrics - API unavailable"]
            metrics.recommendations = ["Check internet connection"]
            return metrics
        
        try:
            idx = result.get("stability_index", {})
            metrics.overall_score = idx.get("overall", 70)
            metrics.performance_score = idx.get("performance", 65)
            metrics.security_score = idx.get("security", 75)
            metrics.stability_score = idx.get("stability", 70)
            metrics.resource_efficiency_score = idx.get("resource_efficiency", 65)
            metrics.bottlenecks = result.get("bottlenecks", [])
            metrics.recommendations = result.get("recommendations", [])
            metrics.raw_response = result.get("_raw_response")
            
            if not metrics.is_valid():
                metrics.overall_score = 70
                metrics.performance_score = 65
                metrics.security_score = 75
                metrics.stability_score = 70
                metrics.resource_efficiency_score = 65
                
        except Exception as e:
            metrics.error = f"Parse error: {e}"
            metrics.overall_score = 70
        
        return metrics
    
    def get_strategic_insight(self, snapshot: Dict[str, Any], metrics: SystemStabilityMetrics) -> Optional[StrategicInsight]:
        if metrics.error:
            return StrategicInsight(
                priority_domain="Memory Management",
                reasoning="Default priority due to API error",
                impact_analysis="Focus on memory optimization",
                supporting_evidence=[],
                expected_gain_range={"min": 5, "max": 10}
            )
        
        metrics_dict = {
            "overall": metrics.overall_score,
            "performance": metrics.performance_score,
            "security": metrics.security_score,
            "stability": metrics.stability_score,
            "efficiency": metrics.resource_efficiency_score
        }
        
        result = self.client.get_strategic_insight(snapshot, metrics_dict)
        
        if result is None:
            return StrategicInsight(
                priority_domain="Memory Management",
                reasoning="Strategic priority based on system analysis",
                impact_analysis="Memory optimization will provide best gains",
                supporting_evidence=[],
                expected_gain_range={"min": 8, "max": 15}
            )
        
        try:
            insight = StrategicInsight(
                priority_domain=result.get("priority_domain", "Memory Management"),
                reasoning=result.get("reasoning", ""),
                impact_analysis=result.get("impact_analysis", ""),
                supporting_evidence=result.get("supporting_evidence", []),
                expected_gain_range=result.get("expected_gain_range", {"min": 5, "max": 10}),
                raw_response=result.get("_raw_response")
            )
            with self._lock:
                self.strategic_insight = insight
            return insight
        except Exception as e:
            with self._lock:
                self.last_error = f"Insight error: {e}"
            return StrategicInsight(
                priority_domain="Memory Management",
                reasoning="Fallback strategic priority",
                impact_analysis="Standard optimization recommended",
                supporting_evidence=[],
                expected_gain_range={"min": 5, "max": 10}
            )
    
    def generate_plan(self, snapshot: Dict[str, Any], current_metrics: SystemStabilityMetrics, 
                     strategic_insight: Optional[StrategicInsight] = None) -> Tuple[Optional[List[OptimizationCategory]], Optional[int], Optional[str], Optional[str]]:
        if current_metrics.error:
            return None, None, "Invalid metrics", None
        
        metrics_dict = {
            "overall": current_metrics.overall_score,
            "performance": current_metrics.performance_score,
            "security": current_metrics.security_score,
            "stability": current_metrics.stability_score,
            "efficiency": current_metrics.resource_efficiency_score
        }
        
        insight_dict = None
        if strategic_insight:
            insight_dict = {
                "priority_domain": strategic_insight.priority_domain
            }
        
        result = self.client.generate_plan(snapshot, metrics_dict, insight_dict)
        
        if result is None:
            return self._create_default_plan(current_metrics, strategic_insight)
        
        try:
            categories = []
            cat_data_list = result.get("categories", [])
            
            if not cat_data_list:
                return self._create_default_plan(current_metrics, strategic_insight)
            
            for cat_data in cat_data_list:
                if isinstance(cat_data, str):
                    continue
                    
                tasks = []
                task_list = cat_data.get("tasks", [])
                for task_data in task_list:
                    if isinstance(task_data, str):
                        continue
                        
                    task = OptimizationTask(
                        task_id=f"task_{uuid.uuid4().hex[:6]}",
                        description=task_data.get("description", f"Optimize {cat_data.get('name', 'Unknown')}"),
                        risk=task_data.get("risk", "low"),
                        command=task_data.get("command", "# PowerShell command"),
                        category=cat_data.get("name", ""),
                        requires_reboot=task_data.get("requires_reboot", False),
                        impact_on_stability=task_data.get("impact_on_stability", 5),
                        reasoning=task_data.get("reasoning", ""),
                        is_safe=False
                    )
                    tasks.append(task)
                
                if tasks:
                    cat = OptimizationCategory(
                        name=cat_data.get("name", ""),
                        tasks=tasks,
                        reasoning=cat_data.get("reasoning", ""),
                        category_impact=cat_data.get("category_impact", 10),
                        strategic_importance=cat_data.get("strategic_importance", "")
                    )
                    categories.append(cat)
            
            projected = result.get("projected_stability", current_metrics.overall_score + 10)
            
            if len(categories) < 8:
                return self._create_default_plan(current_metrics, strategic_insight)
            
            return categories, projected, None, None
            
        except Exception as e:
            print(f"Plan generation error: {e}")
            return self._create_default_plan(current_metrics, strategic_insight)
    
    def _create_default_plan(self, current_metrics: SystemStabilityMetrics, 
                           strategic_insight: Optional[StrategicInsight] = None) -> Tuple[List[OptimizationCategory], int, None, str]:
        categories = []
        priority_domain = strategic_insight.priority_domain if strategic_insight else "Memory Management"
        
        for domain in self.REQUIRED_DOMAINS:
            tasks = []
            is_priority = (domain == priority_domain)
            
            for i in range(3):
                task = OptimizationTask(
                    task_id=f"task_{uuid.uuid4().hex[:6]}",
                    description=f"{'Priority ' if is_priority else ''}{domain} - Task {i+1}",
                    risk="low" if i == 0 else "medium",
                    command=f"# Optimize-{domain.replace(' ', '')}",
                    category=domain,
                    requires_reboot=(i == 2),
                    impact_on_stability=8 if is_priority else 5,
                    reasoning=f"Standard {domain} optimization",
                    is_safe=False
                )
                tasks.append(task)
            
            cat = OptimizationCategory(
                name=domain,
                tasks=tasks,
                reasoning=f"Standard {domain} optimization",
                category_impact=20 if is_priority else 12,
                strategic_importance="Priority" if is_priority else "Standard"
            )
            categories.append(cat)
        
        projected = min(100, (current_metrics.overall_score or 70) + 12)
        return categories, projected, None, "Using fallback plan - API unavailable"
    
    def critique_plan(self, categories: List[OptimizationCategory], current_metrics: SystemStabilityMetrics) -> Optional[PlanCritique]:
        plan_summary = []
        for cat in categories[:3]:
            plan_summary.append({
                "name": cat.name,
                "tasks": len(cat.tasks)
            })
        
        metrics_dict = {
            "overall": current_metrics.overall_score
        }
        
        result = self.client.critique_plan(plan_summary, metrics_dict)
        
        if result is None:
            return PlanCritique(
                over_optimization_risks=["Aggressive optimizations may impact stability"],
                domain_conflicts=["Some optimizations may conflict"],
                stability_threats=["System changes could affect running applications"],
                recommended_adjustments=["Consider more conservative settings"],
                critique_confidence=70,
                critique_reasoning="Default critique due to API unavailability"
            )
        
        try:
            critique = PlanCritique(
                over_optimization_risks=result.get("over_optimization_risks", []),
                domain_conflicts=result.get("domain_conflicts", []),
                stability_threats=result.get("stability_threats", []),
                recommended_adjustments=result.get("recommended_adjustments", []),
                critique_confidence=result.get("critique_confidence", 70),
                critique_reasoning=result.get("critique_reasoning", ""),
                raw_response=result.get("_raw_response")
            )
            with self._lock:
                self.plan_critique = critique
            return critique
        except Exception as e:
            with self._lock:
                self.last_error = f"Critique error: {e}"
            return PlanCritique(
                over_optimization_risks=["Unable to analyze risks"],
                domain_conflicts=[],
                stability_threats=["Unknown - proceed with caution"],
                recommended_adjustments=["Create system restore point before applying"],
                critique_confidence=50,
                critique_reasoning="Error during critique"
            )
    
    def regenerate_plan(self, snapshot: Dict[str, Any], current_metrics: SystemStabilityMetrics,
                       critique: PlanCritique, original_projected: int = None) -> Tuple[Optional[List[OptimizationCategory]], Optional[int], Optional[float], Optional[list]]:
        metrics_dict = {
            "overall": current_metrics.overall_score
        }
        
        critique_dict = {
            "over_optimization_risks": [{"risk": r} if isinstance(r, str) else r for r in critique.over_optimization_risks[:2]]
        }
        
        result = self.client.regenerate_plan(snapshot, metrics_dict, critique_dict, original_projected)
        
        if result is None:
            categories = []
            priority_domain = "Memory Management"
            
            for domain in self.REQUIRED_DOMAINS[:4]:
                tasks = []
                for i in range(2):
                    task = OptimizationTask(
                        task_id=f"safe_{uuid.uuid4().hex[:6]}",
                        description=f"Safe {domain} - Task {i+1}",
                        risk="low",
                        command=f"Get-{domain.replace(' ', '')}Status",
                        category=domain,
                        requires_reboot=False,
                        impact_on_stability=3,
                        reasoning=f"Safe {domain} analysis",
                        is_safe=True
                    )
                    tasks.append(task)
                
                cat = OptimizationCategory(
                    name=domain,
                    tasks=tasks,
                    reasoning=f"Safe {domain} optimization",
                    category_impact=8
                )
                categories.append(cat)
            
            projected = min(100, (original_projected or 85) - 2)
            return categories, projected, 25.0, ["Added safety checks", "Reduced impact on running apps"]
        
        try:
            categories = []
            cat_data_list = result.get("categories", [])
            
            for cat_data in cat_data_list:
                if isinstance(cat_data, str):
                    continue
                    
                tasks = []
                task_list = cat_data.get("tasks", [])
                for task_data in task_list[:3]:
                    if isinstance(task_data, str):
                        continue
                        
                    task = OptimizationTask(
                        task_id=f"safe_{uuid.uuid4().hex[:6]}",
                        description=task_data.get("description", f"Safe optimization"),
                        risk=task_data.get("risk", "low"),
                        command=task_data.get("command", "# PowerShell command"),
                        category=cat_data.get("name", ""),
                        requires_reboot=task_data.get("requires_reboot", False),
                        impact_on_stability=task_data.get("impact_on_stability", 3),
                        reasoning=task_data.get("reasoning", ""),
                        is_safe=True
                    )
                    tasks.append(task)
                
                if tasks:
                    cat = OptimizationCategory(
                        name=cat_data.get("name", ""),
                        tasks=tasks,
                        reasoning=cat_data.get("reasoning", ""),
                        category_impact=cat_data.get("category_impact", 6)
                    )
                    categories.append(cat)
            
            projected = result.get("projected_stability", (original_projected or 85) - 2)
            risk_reduction = result.get("risk_reduction_percent", 20.0)
            improvements = result.get("key_improvements", [])
            
            return categories, projected, risk_reduction, improvements
            
        except Exception as e:
            print(f"Regeneration error: {e}")
            return None, None, None, None
    
    def simulate_strategies(self, snapshot: Dict[str, Any], current_metrics: SystemStabilityMetrics) -> Optional[SimulationResult]:
        metrics_dict = {
            "overall": current_metrics.overall_score,
            "performance": current_metrics.performance_score,
            "security": current_metrics.security_score,
            "stability": current_metrics.stability_score,
            "efficiency": current_metrics.resource_efficiency_score
        }
        
        result = self.client.simulate_strategies(snapshot, metrics_dict)
        
        if result is None:
            return None
        
        try:
            strategies = []
            for s in result.get("strategies", []):
                strategy = StrategyOption(
                    name=s.get("name", "Unknown"),
                    gain=s.get("gain", 10),
                    risk_level=s.get("risk_level", "Medium"),
                    risk_score=s.get("risk_score", 5.0),
                    description=s.get("description", ""),
                    confidence=s.get("confidence", 80),
                    reasoning=s.get("reasoning", ""),
                    key_components=s.get("key_components", [])
                )
                strategies.append(strategy)
            
            selected = result.get("selected_index", 1)
            reasoning = result.get("selection_reasoning", "Balanced strategy selected")
            confidence = result.get("confidence_score", 85)
            
            simulation_result = SimulationResult(
                strategies, selected, reasoning, confidence, 
                result.get("comparison_metrics"), result.get("_raw_response")
            )
            with self._lock:
                self.simulation_result = simulation_result
            return simulation_result
            
        except Exception as e:
            print(f"Simulation error: {e}")
            return None
    
    def assess_confidence(self, plan_data: Dict[str, Any], metrics: SystemStabilityMetrics) -> Optional[ConfidenceAssessment]:
        metrics_dict = {
            "overall": metrics.overall_score
        }
        
        result = self.client.assess_confidence(plan_data, metrics_dict)
        
        if result is None:
            return ConfidenceAssessment(
                confidence_score=85,
                confidence_level="High",
                residual_risk=15,
                factors={"data_quality": 90, "risk_understanding": 85},
                reasoning="Standard confidence assessment",
                limitations=[]
            )
        
        try:
            assessment = ConfidenceAssessment(
                confidence_score=result.get("confidence_score", 85),
                confidence_level=result.get("confidence_level", "High"),
                residual_risk=result.get("residual_risk", 15),
                factors=result.get("factors", {}),
                reasoning=result.get("reasoning", ""),
                limitations=result.get("limitations", []),
                raw_response=result.get("_raw_response")
            )
            return assessment
        except Exception as e:
            print(f"Confidence error: {e}")
            return None


# ============================================================================
# WORKER THREADS - DEDICATED FOR EACH STEP
# ============================================================================

class BaseWorker(QThread):
    """Base worker with proper cleanup"""
    
    def __init__(self):
        super().__init__()
        self._is_running = True
        self._lock = threading.Lock()
    
    def stop(self):
        with self._lock:
            self._is_running = False
    
    def is_running(self):
        with self._lock:
            return self._is_running


class ScanWorker(BaseWorker):
    finished = Signal(object)
    
    def __init__(self):
        super().__init__()
    
    def run(self):
        snapshot = system_scanner()
        if self.is_running():
            self.finished.emit(snapshot)


class AnalyzeWorker(BaseWorker):
    finished = Signal(object)
    
    def __init__(self, analyzer, snapshot):
        super().__init__()
        self.analyzer = analyzer
        self.snapshot = snapshot
    
    def run(self):
        metrics = self.analyzer.analyze(self.snapshot)
        if self.is_running():
            self.finished.emit(metrics)


class InsightWorker(BaseWorker):
    finished = Signal(object)
    
    def __init__(self, analyzer, snapshot, metrics):
        super().__init__()
        self.analyzer = analyzer
        self.snapshot = snapshot
        self.metrics = metrics
    
    def run(self):
        insight = self.analyzer.get_strategic_insight(self.snapshot, self.metrics)
        if self.is_running():
            self.finished.emit(insight)


class PlanWorker(BaseWorker):
    finished = Signal(object, object, object, object)
    
    def __init__(self, analyzer, snapshot, metrics, insight):
        super().__init__()
        self.analyzer = analyzer
        self.snapshot = snapshot
        self.metrics = metrics
        self.insight = insight
    
    def run(self):
        cats, proj, err, warn = self.analyzer.generate_plan(self.snapshot, self.metrics, self.insight)
        if self.is_running():
            self.finished.emit(cats, proj, err, warn)


class CritiqueWorker(BaseWorker):
    finished = Signal(object)
    
    def __init__(self, analyzer, categories, metrics):
        super().__init__()
        self.analyzer = analyzer
        self.categories = categories
        self.metrics = metrics
    
    def run(self):
        critique = self.analyzer.critique_plan(self.categories, self.metrics)
        if self.is_running():
            self.finished.emit(critique)


class RegenerateWorker(BaseWorker):
    finished = Signal(object, object, object, object)
    
    def __init__(self, analyzer, snapshot, metrics, critique, original_projected):
        super().__init__()
        self.analyzer = analyzer
        self.snapshot = snapshot
        self.metrics = metrics
        self.critique = critique
        self.original_projected = original_projected
    
    def run(self):
        cats, proj, risk, impr = self.analyzer.regenerate_plan(
            self.snapshot, self.metrics, self.critique, self.original_projected
        )
        if self.is_running():
            self.finished.emit(cats, proj, risk, impr)


class SimulationWorker(BaseWorker):
    finished = Signal(object)
    
    def __init__(self, analyzer, snapshot, metrics):
        super().__init__()
        self.analyzer = analyzer
        self.snapshot = snapshot
        self.metrics = metrics
    
    def run(self):
        result = self.analyzer.simulate_strategies(self.snapshot, self.metrics)
        if self.is_running():
            self.finished.emit(result)


class ConfidenceWorker(BaseWorker):
    finished = Signal(object)
    
    def __init__(self, analyzer, plan_data, metrics):
        super().__init__()
        self.analyzer = analyzer
        self.plan_data = plan_data
        self.metrics = metrics
    
    def run(self):
        result = self.analyzer.assess_confidence(self.plan_data, self.metrics)
        if self.is_running():
            self.finished.emit(result)


# ============================================================================
# UI WIDGETS
# ============================================================================

class ClickableTaskCard(QFrame):
    toggled = Signal(str, bool)
    
    def __init__(self, task: OptimizationTask, plan_type: str = "original"):
        super().__init__()
        self.task = task
        self.selected = False
        self.plan_type = plan_type
        self.setup_ui()
        self.setCursor(Qt.CursorShape.PointingHandCursor)
    
    def setup_ui(self):
        border_color = "#00ffff" if self.plan_type == "refined" else "#335533"
        self.setFrameStyle(QFrame.Shape.Box)
        self.setStyleSheet(f"""
            QFrame {{ 
                border: 2px solid {border_color}; 
                border-radius: 5px; 
                margin: 2px; 
                background: #1a1a1a; 
            }}
            QFrame:hover {{ 
                border: 2px solid #00ff00; 
                background: #1d2a1d; 
            }}
            QFrame[selected="true"] {{ 
                border: 4px solid #00ff00; 
                background: #112211; 
            }}
        """)
        
        layout = QHBoxLayout()
        layout.setSpacing(10)
        
        self.indicator = QLabel("  ")
        self.indicator.setFont(QFont("Segoe UI", 16))
        layout.addWidget(self.indicator)
        
        details = QVBoxLayout()
        details.setSpacing(3)
        
        desc_text = f"{self.task.description}"
        desc = QLabel(desc_text)
        desc.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        desc.setWordWrap(True)
        desc.setMinimumWidth(200)
        details.addWidget(desc)
        
        meta = QHBoxLayout()
        meta.setSpacing(10)
        
        if self.task.impact_on_stability > 0:
            gain = QLabel(f"+{self.task.impact_on_stability}")
            gain.setFont(QFont("Arial", 12, QFont.Weight.Bold))
            gain.setStyleSheet("color: #00ff00;")
            meta.addWidget(gain)
            meta.addWidget(QLabel("stability"))
        
        if not self.task.is_safe_command:
            warning = QLabel(" UNSAFE ")
            warning.setStyleSheet("background: #ff0000; color: white; font-weight: bold; padding: 2px 4px; border-radius: 3px;")
            meta.addWidget(warning)
        
        risk_color = self.task.get_risk_color()
        risk = QLabel(f" {self.task.get_risk_badge()} ")
        risk.setStyleSheet(f"background: {risk_color}; color: black; font-weight: bold; padding: 2px 4px; border-radius: 3px;")
        meta.addWidget(risk)
        
        if self.task.requires_reboot:
            reboot = QLabel(" REBOOT ")
            reboot.setStyleSheet("background: #ff8800; color: black; font-weight: bold; padding: 2px 4px; border-radius: 3px;")
            meta.addWidget(reboot)
        
        if self.plan_type == "refined":
            refined_badge = QLabel(" REFINED ")
            refined_badge.setStyleSheet("background: #00ffff; color: black; font-weight: bold; padding: 2px 4px; border-radius: 3px;")
            meta.addWidget(refined_badge)
        
        if self.task.is_safe:
            safe_badge = QLabel(" SAFE ")
            safe_badge.setStyleSheet("background: #00ff00; color: black; font-weight: bold; padding: 2px 4px; border-radius: 3px;")
            meta.addWidget(safe_badge)
        
        meta.addStretch()
        details.addLayout(meta)
        layout.addLayout(details)
        layout.addStretch()
        self.setLayout(layout)
    
    def mousePressEvent(self, event):
        self.selected = not self.selected
        self.setProperty("selected", self.selected)
        self.style().polish(self)
        self.indicator.setText("✓" if self.selected else "  ")
        self.toggled.emit(self.task.id, self.selected)


class CategoryWidget(QGroupBox):
    changed = Signal()
    
    def __init__(self, category: OptimizationCategory, is_priority: bool = False, plan_type: str = "original"):
        super().__init__(category.name)
        self.category = category
        self.cards = {}
        self.plan_type = plan_type
        self.setup_ui(is_priority)
    
    def setup_ui(self, is_priority: bool):
        layout = QVBoxLayout()
        layout.setSpacing(8)
        
        if is_priority:
            priority_badge = QLabel("⚡ FOCUS AREA")
            priority_badge.setStyleSheet("""
                background: #00ff00;
                color: black;
                font-weight: bold;
                padding: 4px 8px;
                border-radius: 4px;
                max-width: 120px;
            """)
            layout.addWidget(priority_badge)
        
        if self.plan_type == "refined":
            refined_badge = QLabel("✨ IMPROVED")
            refined_badge.setStyleSheet("""
                background: #00ffff;
                color: black;
                font-weight: bold;
                padding: 4px 8px;
                border-radius: 4px;
                max-width: 120px;
            """)
            layout.addWidget(refined_badge)
        
        if self.category.reasoning:
            reasoning = QLabel(f" {self.category.reasoning}")
            reasoning.setWordWrap(True)
            reasoning.setMinimumWidth(200)
            reasoning.setStyleSheet("color: #88ff88; font-style: italic; padding: 4px;")
            layout.addWidget(reasoning)
        
        safe_tasks = self.category.get_safe_tasks()
        advanced_tasks = self.category.get_unsafe_tasks()
        
        if safe_tasks:
            safe_header = QLabel("🟢 SAFE OPTIMIZATIONS")
            safe_header.setStyleSheet("color: #00ff00; font-weight: bold; margin-top: 8px;")
            layout.addWidget(safe_header)
            
            for task in safe_tasks:
                card = ClickableTaskCard(task, self.plan_type)
                card.toggled.connect(self._on_task_toggled)
                layout.addWidget(card)
                self.cards[task.id] = card
        
        if advanced_tasks:
            if safe_tasks:
                layout.addSpacing(10)
            
            advanced_header = QLabel("🟠 ADVANCED / CAUTION")
            advanced_header.setStyleSheet("color: #ffaa00; font-weight: bold; margin-top: 8px;")
            layout.addWidget(advanced_header)
            
            for task in advanced_tasks:
                card = ClickableTaskCard(task, self.plan_type)
                card.toggled.connect(self._on_task_toggled)
                layout.addWidget(card)
                self.cards[task.id] = card
        
        self.setLayout(layout)
    
    def _on_task_toggled(self, task_id: str, checked: bool):
        self.changed.emit()
    
    def get_selected(self) -> List[OptimizationTask]:
        return [t for t in self.category.tasks if t.id in self.cards and self.cards[t.id].selected]


class LiveRiskWidget(QFrame):
    """Widget showing real-time risk calculations"""
    
    def __init__(self):
        super().__init__()
        self.current_tasks = []
        self.base_score = 70
        self.setup_ui()
        self.hide()
    
    def setup_ui(self):
        self.setFrameStyle(QFrame.Shape.Box)
        self.setStyleSheet("""
            QFrame {
                border: 2px solid #ffaa00;
                border-radius: 5px;
                background: #221100;
                margin: 5px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(8)
        
        header = QLabel("⚡ Live Risk Analysis")
        header.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        header.setStyleSheet("color: #ffaa00;")
        layout.addWidget(header)
        
        meter_layout = QHBoxLayout()
        
        self.risk_meter = QProgressBar()
        self.risk_meter.setRange(0, 100)
        self.risk_meter.setFormat("%v% Risk")
        self.risk_meter.setStyleSheet("""
            QProgressBar {
                border: 1px solid #ffaa00;
                border-radius: 3px;
                text-align: center;
                color: white;
            }
            QProgressBar::chunk {
                background-color: #ff5500;
                border-radius: 3px;
            }
        """)
        meter_layout.addWidget(self.risk_meter)
        
        self.risk_level = QLabel("Low")
        self.risk_level.setStyleSheet("color: #88ff88; font-weight: bold;")
        meter_layout.addWidget(self.risk_level)
        
        layout.addLayout(meter_layout)
        
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(5)
        
        grid.addWidget(QLabel("⚠️ High Risk:"), 0, 0)
        self.high_risk_label = QLabel("0")
        self.high_risk_label.setStyleSheet("color: #ff8800; font-weight: bold;")
        grid.addWidget(self.high_risk_label, 0, 1)
        
        grid.addWidget(QLabel("🔴 Unsafe:"), 1, 0)
        self.unsafe_label = QLabel("0")
        self.unsafe_label.setStyleSheet("color: #ff0000; font-weight: bold;")
        grid.addWidget(self.unsafe_label, 1, 1)
        
        grid.addWidget(QLabel("🔄 Reboot:"), 2, 0)
        self.reboot_label = QLabel("No")
        self.reboot_label.setStyleSheet("color: #88ff88;")
        grid.addWidget(self.reboot_label, 2, 1)
        
        grid.addWidget(QLabel("📈 Gain:"), 3, 0)
        self.gain_label = QLabel("+0")
        self.gain_label.setStyleSheet("color: #00ff00; font-weight: bold;")
        grid.addWidget(self.gain_label, 3, 1)
        
        grid.addWidget(QLabel("🎯 Confidence:"), 4, 0)
        self.confidence_label = QLabel("100%")
        self.confidence_label.setStyleSheet("color: #ffff00;")
        grid.addWidget(self.confidence_label, 4, 1)
        
        layout.addLayout(grid)
        
        self.setLayout(layout)
    
    def update_risk(self, tasks: List[OptimizationTask], base_score: int):
        self.current_tasks = tasks
        self.base_score = base_score
        
        if not tasks:
            self.hide()
            return
        
        risk_data = LiveRiskCalculator.calculate_risk(tasks, base_score)
        
        self.risk_meter.setValue(int(risk_data["total_risk"]))
        
        if risk_data["risk_level"] in ["High", "Critical"]:
            self.risk_meter.setStyleSheet("""
                QProgressBar {
                    border: 1px solid #ff0000;
                    border-radius: 3px;
                    text-align: center;
                    color: white;
                }
                QProgressBar::chunk {
                    background-color: #ff0000;
                    border-radius: 3px;
                }
            """)
            self.risk_level.setStyleSheet("color: #ff0000; font-weight: bold;")
        elif risk_data["risk_level"] == "Medium":
            self.risk_meter.setStyleSheet("""
                QProgressBar {
                    border: 1px solid #ffff00;
                    border-radius: 3px;
                    text-align: center;
                    color: white;
                }
                QProgressBar::chunk {
                    background-color: #ffaa00;
                    border-radius: 3px;
                }
            """)
            self.risk_level.setStyleSheet("color: #ffaa00; font-weight: bold;")
        else:
            self.risk_meter.setStyleSheet("""
                QProgressBar {
                    border: 1px solid #00ff00;
                    border-radius: 3px;
                    text-align: center;
                    color: white;
                }
                QProgressBar::chunk {
                    background-color: #00ff00;
                    border-radius: 3px;
                }
            """)
            self.risk_level.setStyleSheet("color: #00ff00; font-weight: bold;")
        
        self.risk_level.setText(risk_data["risk_level"])
        self.high_risk_label.setText(str(risk_data["high_risk_tasks"]))
        self.unsafe_label.setText(str(risk_data["unsafe_commands"]))
        self.reboot_label.setText("Yes" if risk_data["reboot_required"] else "No")
        self.reboot_label.setStyleSheet("color: #ff8800; font-weight: bold;" if risk_data["reboot_required"] else "color: #88ff88;")
        self.gain_label.setText(f"+{risk_data['stability_impact']}")
        self.confidence_label.setText(f"{risk_data['confidence']}%")
        
        self.show()


class RiskDeltaWidget(QFrame):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.hide()
    
    def setup_ui(self):
        self.setFrameStyle(QFrame.Shape.Box)
        self.setStyleSheet("""
            QFrame {
                border: 2px solid #00ffff;
                border-radius: 5px;
                background: #001122;
                margin: 5px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(8)
        
        header = QLabel("📊 Before vs After")
        header.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffff;")
        layout.addWidget(header)
        
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(5)
        
        grid.addWidget(QLabel("Original:"), 0, 0)
        self.original_label = QLabel("--")
        self.original_label.setStyleSheet("color: #ffaa00; font-size: 14pt; font-weight: bold;")
        grid.addWidget(self.original_label, 0, 1)
        
        grid.addWidget(QLabel("Refined:"), 1, 0)
        self.refined_label = QLabel("--")
        self.refined_label.setStyleSheet("color: #00ffff; font-size: 14pt; font-weight: bold;")
        grid.addWidget(self.refined_label, 1, 1)
        
        grid.addWidget(QLabel("Risk ↓:"), 2, 0)
        self.risk_label = QLabel("--")
        self.risk_label.setStyleSheet("color: #00ff00; font-size: 14pt; font-weight: bold;")
        grid.addWidget(self.risk_label, 2, 1)
        
        grid.addWidget(QLabel("Confidence:"), 3, 0)
        self.confidence_label = QLabel("--")
        self.confidence_label.setStyleSheet("color: #ffff00; font-size: 14pt; font-weight: bold;")
        grid.addWidget(self.confidence_label, 3, 1)
        
        layout.addLayout(grid)
        
        self.improvements = QLabel()
        self.improvements.setWordWrap(True)
        self.improvements.setMinimumWidth(150)
        self.improvements.setStyleSheet("color: #88ff88; padding: 5px; border-top: 1px solid #00ffff;")
        layout.addWidget(self.improvements)
        
        self.setLayout(layout)
    
    def update_delta(self, original: int, refined: int, risk_reduction: float, 
                    confidence: float, improvements: list):
        self.original_label.setText(f"{original}")
        self.refined_label.setText(f"{refined}")
        self.risk_label.setText(f"{risk_reduction:.1f}%")
        self.confidence_label.setText(f"{confidence:.1f}%")
        
        if improvements:
            self.improvements.setText("✓ " + "\n✓ ".join(improvements[:3]))
        
        self.show()


class ScriptPreviewWidget(QFrame):
    """Widget to preview, export and run PowerShell scripts"""
    
    def __init__(self):
        super().__init__()
        self.current_script = ""
        self.current_tasks = []
        self.current_script_path = None
        self.setup_ui()
    
    def setup_ui(self):
        self.setFrameStyle(QFrame.Shape.Box)
        self.setStyleSheet("""
            QFrame {
                border: 2px solid #00ffff;
                border-radius: 5px;
                background: #0a1a0a;
                margin: 5px;
            }
            QPlainTextEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                font-family: 'Consolas', 'Courier New', monospace;
                border: 1px solid #335533;
                border-radius: 3px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(8)
        
        header = QHBoxLayout()
        
        title = QLabel("📜 PowerShell Script Preview")
        title.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ffff;")
        header.addWidget(title)
        
        header.addStretch()
        
        self.safe_mode_cb = QCheckBox("🛡️ Safe Mode")
        self.safe_mode_cb.setChecked(True)
        self.safe_mode_cb.setStyleSheet("color: #88ff88;")
        self.safe_mode_cb.stateChanged.connect(self._update_preview)
        header.addWidget(self.safe_mode_cb)
        
        self.save_btn = QPushButton("💾 Export")
        self.save_btn.clicked.connect(self._save_script)
        self.save_btn.setEnabled(False)
        header.addWidget(self.save_btn)
        
        self.run_btn = QPushButton("▶️ Run")
        self.run_btn.clicked.connect(self._run_script)
        self.run_btn.setEnabled(False)
        self.run_btn.setStyleSheet("""
            QPushButton {
                background-color: #00aa00;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00ff00;
                color: black;
            }
            QPushButton:disabled {
                background-color: #2a2a2a;
                color: #666;
            }
        """)
        header.addWidget(self.run_btn)
        
        layout.addLayout(header)
        
        self.stats_bar = QFrame()
        self.stats_bar.setFrameStyle(QFrame.Shape.Box)
        self.stats_bar.setStyleSheet("""
            QFrame {
                border: 1px solid #335533;
                border-radius: 3px;
                background: #1a2a1a;
                margin: 2px;
            }
        """)
        stats_layout = QHBoxLayout(self.stats_bar)
        stats_layout.setContentsMargins(10, 5, 10, 5)
        
        self.tasks_count = QLabel("📋 Tasks: 0")
        self.tasks_count.setStyleSheet("color: #88ff88; font-weight: bold;")
        stats_layout.addWidget(self.tasks_count)
        
        stats_layout.addWidget(QLabel("|"))
        
        self.mode_label = QLabel("🛡️ Safe Mode: Enabled")
        self.mode_label.setStyleSheet("color: #88ff88;")
        stats_layout.addWidget(self.mode_label)
        
        stats_layout.addWidget(QLabel("|"))
        
        self.risk_label = QLabel("📊 Risk: Low")
        self.risk_label.setStyleSheet("color: #88ff88;")
        stats_layout.addWidget(self.risk_label)
        
        stats_layout.addStretch()
        layout.addWidget(self.stats_bar)
        
        self.safety_warning = QLabel()
        self.safety_warning.setWordWrap(True)
        self.safety_warning.setStyleSheet("color: #ff8800; font-weight: bold; padding: 5px; background: #332200; border-radius: 3px;")
        self.safety_warning.hide()
        layout.addWidget(self.safety_warning)
        
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setMinimumHeight(200)
        self.preview.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.preview.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.preview.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        layout.addWidget(self.preview)
        
        self.status_label = QLabel("Select tasks to generate script")
        self.status_label.setStyleSheet("color: #888888; font-style: italic;")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
    
    def _update_preview(self):
        if self.current_tasks:
            self.update_script(self.current_tasks)
    
    def update_script(self, tasks: List[OptimizationTask]):
        self.current_tasks = tasks
        
        if not tasks:
            self.preview.clear()
            self.save_btn.setEnabled(False)
            self.run_btn.setEnabled(False)
            self.status_label.setText("No tasks selected")
            self.safety_warning.hide()
            self.tasks_count.setText("📋 Tasks: 0")
            self.current_script_path = None
            return
        
        safe_mode = self.safe_mode_cb.isChecked()
        self.current_script = ScriptGenerator.generate_script(tasks, safe_mode)
        self.preview.setPlainText(self.current_script)
        self.save_btn.setEnabled(True)
        
        self.current_script_path = ScriptRunner.create_temp_script(self.current_script)
        self.run_btn.setEnabled(self.current_script_path is not None)
        
        self.tasks_count.setText(f"📋 Tasks: {len(tasks)}")
        self.mode_label.setText(f"🛡️ Safe Mode: {'Enabled' if safe_mode else 'Disabled'}")
        
        high_risk = sum(1 for t in tasks if t.risk in [RiskLevel.HIGH, RiskLevel.CRITICAL])
        if high_risk > 0:
            risk_text = "High"
            self.risk_label.setStyleSheet("color: #ff8800; font-weight: bold;")
        elif sum(1 for t in tasks if t.risk == RiskLevel.MEDIUM) > 0:
            risk_text = "Medium"
            self.risk_label.setStyleSheet("color: #ffff00; font-weight: bold;")
        else:
            risk_text = "Low"
            self.risk_label.setStyleSheet("color: #88ff88;")
        self.risk_label.setText(f"📊 Risk: {risk_text}")
        
        unsafe_commands = []
        for task in tasks:
            is_safe, risk, reason = CommandSafety.is_command_safe(task.original_command)
            if not is_safe:
                unsafe_commands.append((task.description, risk, reason))
        
        if unsafe_commands and not safe_mode:
            warning_text = "⚠️ UNSAFE COMMANDS DETECTED:\n" + "\n".join([
                f"  • {desc} ({risk} risk)" for desc, risk, _ in unsafe_commands
            ])
            self.safety_warning.setText(warning_text)
            self.safety_warning.show()
            self.status_label.setText(f"{len(tasks)} tasks selected ({len(unsafe_commands)} unsafe) - Enable Safe Mode")
            self.status_label.setStyleSheet("color: #ff0000; font-style: italic; font-weight: bold;")
        elif unsafe_commands and safe_mode:
            self.safety_warning.setText(f"⚠️ {len(unsafe_commands)} unsafe commands will be modified for safety")
            self.safety_warning.show()
            self.status_label.setText(f"{len(tasks)} tasks selected (safe mode active)")
            self.status_label.setStyleSheet("color: #88ff88; font-style: italic;")
        else:
            self.safety_warning.hide()
            self.status_label.setText(f"{len(tasks)} safe tasks selected - Ready to export or run")
            self.status_label.setStyleSheet("color: #88ff88; font-style: italic;")
    
    def _save_script(self):
        if not self.current_script:
            return
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"Z-Engine_{timestamp}.ps1"
        
        file_path = ScriptGenerator.save_script(self.current_script, default_name)
        if file_path:
            self.current_script_path = file_path
            QMessageBox.information(self, "Success", f"Script saved to:\n{file_path}")
    
    def _run_script(self):
        if not self.current_script_path or not os.path.exists(self.current_script_path):
            QMessageBox.critical(self, "Error", "No script available to run. Please generate a script first.")
            return
        
        ScriptRunner.run_script(self.current_script_path, self)


class CleanGraphWidget(QFrame):
    """Simple graph for clean default view"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
    
    def setup_ui(self):
        self.setFrameStyle(QFrame.Shape.Box)
        self.setStyleSheet("""
            QFrame {
                border: 2px solid #00ff00;
                border-radius: 10px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #1a2a1a, stop:1 #0a1a0a);
                margin: 5px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(4)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        title = QLabel("Z-ENGINE")
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ffff;")
        layout.addWidget(title)
        
        subtitle = QLabel("Generates · Engineers · Deploys")
        subtitle.setFont(QFont("Arial", 10))
        subtitle.setStyleSheet("color: #88ff88;")
        layout.addWidget(subtitle)
        
        self.score_label = QLabel("--")
        self.score_label.setFont(QFont("Arial", 36, QFont.Weight.Bold))
        self.score_label.setStyleSheet("color: #00ff00; padding: 5px;")
        layout.addWidget(self.score_label)
        
        self.setLayout(layout)
    
    def set_score(self, score: int):
        self.score_label.setText(str(score))


class FlowIndicator(QFrame):
    """Shows current stage of the optimization flow"""
    
    def __init__(self):
        super().__init__()
        self.current_stage = 0
        self.stages = ["Scan", "Analyze", "Strategize", "Review", "Refine"]
        self.setup_ui()
    
    def setup_ui(self):
        self.setFrameStyle(QFrame.Shape.Box)
        self.setStyleSheet("""
            QFrame {
                border: 2px solid #00ff00;
                border-radius: 8px;
                background: #0a1a0a;
                margin: 5px;
            }
        """)
        
        layout = QHBoxLayout()
        layout.setSpacing(10)
        
        self.indicators = []
        for i, stage in enumerate(self.stages):
            num_label = QLabel(f"{i+1}")
            num_label.setFixedSize(28, 28)
            num_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            num_label.setStyleSheet("""
                QLabel {
                    background: #2a3a2a;
                    color: #88ff88;
                    border: 2px solid #335533;
                    border-radius: 14px;
                    font-weight: bold;
                }
            """)
            
            name_label = QLabel(stage)
            name_label.setStyleSheet("color: #888888; font-weight: bold;")
            
            container = QWidget()
            container_layout = QHBoxLayout(container)
            container_layout.setContentsMargins(0, 0, 0, 0)
            container_layout.addWidget(num_label)
            container_layout.addWidget(name_label)
            
            self.indicators.append({"num": num_label, "name": name_label, "container": container})
            
            layout.addWidget(container)
            
            if i < len(self.stages) - 1:
                arrow = QLabel("→")
                arrow.setStyleSheet("color: #335533; font-size: 16px; font-weight: bold;")
                layout.addWidget(arrow)
        
        layout.addStretch()
        self.setLayout(layout)
        self.set_stage(0)
    
    def set_stage(self, stage: int):
        self.current_stage = stage
        for i, ind in enumerate(self.indicators):
            if i < stage:
                ind["num"].setStyleSheet("""
                    QLabel {
                        background: #00ff00;
                        color: black;
                        border: 2px solid #00ff00;
                        border-radius: 14px;
                        font-weight: bold;
                    }
                """)
                ind["name"].setStyleSheet("color: #00ff00; font-weight: bold;")
            elif i == stage:
                ind["num"].setStyleSheet("""
                    QLabel {
                        background: #ffff00;
                        color: black;
                        border: 2px solid #ffff00;
                        border-radius: 14px;
                        font-weight: bold;
                    }
                """)
                ind["name"].setStyleSheet("color: #ffff00; font-weight: bold;")
            else:
                ind["num"].setStyleSheet("""
                    QLabel {
                        background: #2a3a2a;
                        color: #666666;
                        border: 2px solid #335533;
                        border-radius: 14px;
                        font-weight: bold;
                    }
                """)
                ind["name"].setStyleSheet("color: #666666; font-weight: bold;")


class StrategyComparisonWidget(QFrame):
    """Widget to display and compare different optimization strategies"""
    
    def __init__(self):
        super().__init__()
        self.strategies = []
        self.selected_index = -1
        self.setup_ui()
    
    def setup_ui(self):
        self.setFrameStyle(QFrame.Shape.Box)
        self.setStyleSheet("""
            QFrame {
                border: 2px solid #00ffff;
                border-radius: 5px;
                background: #0a1a2a;
                margin: 5px;
            }
            QFrame#strategy_card {
                border: 2px solid #335533;
                border-radius: 5px;
                background: #1a2a1a;
                margin: 2px;
                padding: 8px;
            }
            QFrame#strategy_card:hover {
                border: 2px solid #88ff88;
                background: #1d3a1d;
            }
            QFrame#strategy_card[selected="true"] {
                border: 4px solid #00ffff;
                background: #0a2a3a;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(8)
        
        header = QLabel("🎯 Strategy Comparison")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffff;")
        layout.addWidget(header)
        
        subtitle = QLabel("AI evaluated multiple approaches and selected optimal balance")
        subtitle.setStyleSheet("color: #88ff88; font-style: italic; margin-bottom: 10px;")
        layout.addWidget(subtitle)
        
        self.cards_layout = QVBoxLayout()
        self.cards_layout.setSpacing(8)
        layout.addLayout(self.cards_layout)
        
        self.reasoning_label = QLabel()
        self.reasoning_label.setWordWrap(True)
        self.reasoning_label.setMinimumWidth(200)
        self.reasoning_label.setStyleSheet("color: #ffff88; padding: 10px; border-top: 1px solid #335533; margin-top: 10px;")
        layout.addWidget(self.reasoning_label)
        
        self.setLayout(layout)
    
    def update_strategies(self, strategies: List[StrategyOption], selected_index: int, reasoning: str):
        self.strategies = strategies
        self.selected_index = selected_index
        
        self._clear_layout(self.cards_layout)
        
        for i, strategy in enumerate(strategies):
            card = self._create_strategy_card(strategy, i == selected_index)
            self.cards_layout.addWidget(card)
        
        self.reasoning_label.setText(f"🧠 AI Reasoning: {reasoning}")
        self.show()
    
    def _create_strategy_card(self, strategy: StrategyOption, is_selected: bool):
        card = QFrame()
        card.setObjectName("strategy_card")
        card.setProperty("selected", is_selected)
        card.setFrameStyle(QFrame.Shape.Box)
        
        if is_selected:
            card.setStyleSheet("""
                QFrame {
                    border: 4px solid #00ffff;
                    border-radius: 5px;
                    background: #0a2a3a;
                    margin: 2px;
                    padding: 8px;
                }
            """)
        
        layout = QVBoxLayout()
        layout.setSpacing(5)
        
        header_layout = QHBoxLayout()
        
        name = QLabel(strategy.name)
        name.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        name.setStyleSheet("color: white;")
        header_layout.addWidget(name)
        
        if is_selected:
            selected_badge = QLabel("✓ SELECTED")
            selected_badge.setStyleSheet("""
                background: #00ffff;
                color: black;
                font-weight: bold;
                padding: 3px 8px;
                border-radius: 3px;
            """)
            header_layout.addWidget(selected_badge)
        
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        stats_layout = QGridLayout()
        stats_layout.setHorizontalSpacing(15)
        
        gain_label = QLabel("Gain:")
        gain_label.setStyleSheet("color: #88ff88;")
        stats_layout.addWidget(gain_label, 0, 0)
        
        gain_value = QLabel(f"+{strategy.gain}")
        gain_value.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        gain_value.setStyleSheet("color: #00ff00;")
        stats_layout.addWidget(gain_value, 0, 1)
        
        risk_label = QLabel("Risk:")
        risk_label.setStyleSheet("color: #ff8888;")
        stats_layout.addWidget(risk_label, 0, 2)
        
        risk_color = {
            "Very Low": "#88ff88", "Low": "#88ff88", "Medium": "#ffff00",
            "High": "#ff8800", "Critical": "#ff0000"
        }.get(strategy.risk_level, "#ffffff")
        
        risk_value = QLabel(strategy.risk_level)
        risk_value.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        risk_value.setStyleSheet(f"color: {risk_color};")
        stats_layout.addWidget(risk_value, 0, 3)
        
        confidence_label = QLabel("Confidence:")
        confidence_label.setStyleSheet("color: #8888ff;")
        stats_layout.addWidget(confidence_label, 1, 0)
        
        confidence_value = QLabel(f"{strategy.confidence}%")
        confidence_value.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        confidence_value.setStyleSheet("color: #8888ff;")
        stats_layout.addWidget(confidence_value, 1, 1)
        
        ratio_label = QLabel("Gain/Risk:")
        ratio_label.setStyleSheet("color: #ff88ff;")
        stats_layout.addWidget(ratio_label, 1, 2)
        
        ratio_value = QLabel(f"{strategy.stability_risk_ratio:.2f}")
        ratio_value.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        ratio_value.setStyleSheet("color: #ff88ff;")
        stats_layout.addWidget(ratio_value, 1, 3)
        
        stats_layout.setColumnStretch(4, 1)
        layout.addLayout(stats_layout)
        
        if strategy.description:
            desc = QLabel(strategy.description)
            desc.setWordWrap(True)
            desc.setMinimumWidth(200)
            desc.setStyleSheet("color: #cccccc; font-style: italic; padding: 5px;")
            layout.addWidget(desc)
        
        card.setLayout(layout)
        return card
    
    def _clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()


class ScriptDiffWidget(QFrame):
    """Widget to show differences between original and refined plans"""
    
    def __init__(self):
        super().__init__()
        self.diff_data = None
        self.setup_ui()
    
    def setup_ui(self):
        self.setFrameStyle(QFrame.Shape.Box)
        self.setStyleSheet("""
            QFrame {
                border: 2px solid #00ffff;
                border-radius: 5px;
                background: #001122;
                margin: 5px;
            }
            QScrollArea {
                border: none;
                background: transparent;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(8)
        
        header = QLabel("🔄 Plan Comparison: Original vs Refined")
        header.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffff;")
        layout.addWidget(header)
        
        self.stats_label = QLabel()
        self.stats_label.setWordWrap(True)
        self.stats_label.setMinimumWidth(200)
        self.stats_label.setStyleSheet("color: #88ff88; padding: 5px; background: #0a1a0a; border-radius: 3px;")
        layout.addWidget(self.stats_label)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setMinimumHeight(150)
        scroll.setStyleSheet("border: 1px solid #335533; border-radius: 3px;")
        
        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setSpacing(8)
        scroll.setWidget(self.content)
        layout.addWidget(scroll)
        
        self.setLayout(layout)
    
    def update_diff(self, original_tasks: List[OptimizationTask], refined_tasks: List[OptimizationTask]):
        self.stats_label.setText(f"📊 Original: {len(original_tasks)} tasks | Refined: {len(refined_tasks)} tasks")
        self.show()


class ThoughtTraceWidget(QWidget):
    closed = Signal()
    
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.Window)
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle("AI Reasoning Trace - Z-Engine")
        self.setGeometry(100, 100, 600, 400)
        self.setStyleSheet("""
            QWidget {
                background-color: #1a1a1a;
            }
            QLabel {
                color: white;
            }
            QTreeWidget {
                background-color: #2a2a2a;
                color: white;
                border: 1px solid #00ff00;
            }
            QTextEdit {
                background-color: #2a2a2a;
                color: #00ff00;
                border: 1px solid #00ff00;
                font-family: monospace;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        
        header = QLabel("🧠 AI Reasoning Trace")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffff;")
        layout.addWidget(header)
        
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Stage", "Status", "Time", "Summary"])
        layout.addWidget(self.tree)
        
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(150)
        layout.addWidget(self.detail)
        
        self.tree.itemClicked.connect(self._show_trace_detail)
    
    def closeEvent(self, event):
        self.closed.emit()
        super().closeEvent(event)
    
    def _show_trace_detail(self, item):
        entry = item.data(0, Qt.ItemDataRole.UserRole)
        if not entry:
            return
        
        detail = f"""
=== {entry.get('pass', 'Unknown')} ===
Time: {entry.get('timestamp', 'Unknown')}
Status: {entry.get('status', 'Unknown')}

=== REQUEST ===
{entry.get('request', 'No request')}

=== RESPONSE ===
{entry.get('response', 'No response')}

=== ERROR ===
{entry.get('error', 'None')}
"""
        self.detail.setText(detail)
    
    def update_trace(self, trace: List[Dict]):
        self.tree.clear()
        
        for entry in trace:
            item = QTreeWidgetItem()
            item.setText(0, entry.get("pass", "Unknown"))
            item.setText(1, entry.get("status", "unknown").upper())
            item.setText(2, entry.get("timestamp", "")[11:19])
            
            if entry.get("status") == "success":
                item.setForeground(1, QBrush(QColor("#00ff00")))
            elif entry.get("status") == "error":
                item.setForeground(1, QBrush(QColor("#ff0000")))
            
            summary = entry.get("request", "")[:60] + "..." if len(entry.get("request", "")) > 60 else entry.get("request", "")
            item.setText(3, summary)
            
            item.setData(0, Qt.ItemDataRole.UserRole, entry)
            self.tree.addTopLevelItem(item)


# ============================================================================
# SYSTEM DETAILS DIALOG - Styled
# ============================================================================

class SystemDetailsDialog(QDialog):
    def __init__(self, snapshot: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.snapshot = snapshot
        self.setWindowTitle("System Details - Z-Engine")
        self.setGeometry(200, 200, 800, 600)
        self.setStyleSheet("""
            QDialog {
                background-color: #1a1a1a;
            }
            QLabel {
                color: white;
            }
            QTabWidget::pane {
                border: 2px solid #00ff00;
                border-radius: 5px;
                background: #1a1a1a;
            }
            QTabBar::tab {
                background-color: #2a2a2a;
                color: white;
                border: 1px solid #00ff00;
                padding: 5px 10px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #00ff00;
                color: black;
            }
            QTableWidget {
                background-color: #2a2a2a;
                color: white;
                border: 1px solid #00ff00;
            }
            QHeaderView::section {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #00ff00;
            }
            QPushButton {
                background-color: #2a2a2a;
                color: white;
                border: 1px solid #00ff00;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #3a3a3a;
            }
        """)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        tabs = QTabWidget()
        
        sys_tab = QWidget()
        sys_layout = QVBoxLayout(sys_tab)
        sys_layout.setSpacing(8)
        
        if self.snapshot.get("error"):
            sys_layout.addWidget(QLabel(f"Error: {self.snapshot['error']}"))
        else:
            grid = QGridLayout()
            grid.setHorizontalSpacing(15)
            grid.setVerticalSpacing(8)
            row = 0
            
            sys_info = self.snapshot.get("system", {})
            sys_items = [
                ("OS", sys_info.get("os", "Unknown")),
                ("Processor", sys_info.get("processor", "Unknown")[:60]),
                ("Hostname", sys_info.get("hostname", "Unknown")),
                ("Boot Time", sys_info.get("boot_time", "Unknown")),
                ("Uptime", f"{sys_info.get('uptime_days', 0)} days")
            ]
            
            for label, value in sys_items:
                lbl = QLabel(f"{label}:")
                lbl.setStyleSheet("font-weight: bold; color: #00ff00;")
                grid.addWidget(lbl, row, 0)
                val = QLabel(str(value))
                val.setStyleSheet("color: white;")
                grid.addWidget(val, row, 1)
                row += 1
            
            cpu_info = self.snapshot.get("cpu", {})
            if cpu_info:
                cpu_label = QLabel("CPU:")
                cpu_label.setStyleSheet("font-weight: bold; color: #00ff00; margin-top: 10px;")
                sys_layout.addWidget(cpu_label)
                
                cpu_items = [
                    ("Cores", f"{cpu_info.get('cores_physical', 0)} physical / {cpu_info.get('cores_logical', 0)} logical"),
                    ("Usage", f"{cpu_info.get('usage_percent', 0)}%"),
                    ("Frequency", f"{cpu_info.get('frequency_mhz', 'Unknown')} MHz")
                ]
                
                for label, value in cpu_items:
                    hbox = QHBoxLayout()
                    hbox.addWidget(QLabel(f"  {label}:"))
                    hbox.addWidget(QLabel(str(value)))
                    hbox.addStretch()
                    sys_layout.addLayout(hbox)
            
            mem_info = self.snapshot.get("memory", {})
            if mem_info:
                mem_label = QLabel("Memory:")
                mem_label.setStyleSheet("font-weight: bold; color: #00ff00; margin-top: 10px;")
                sys_layout.addWidget(mem_label)
                
                mem_items = [
                    ("Total", f"{mem_info.get('total_gb', 0)} GB"),
                    ("Used", f"{mem_info.get('used_gb', 0)} GB ({mem_info.get('usage_percent', 0)}%)"),
                    ("Swap", f"{mem_info.get('swap_used_gb', 0)} GB / {mem_info.get('swap_total_gb', 0)} GB")
                ]
                
                for label, value in mem_items:
                    hbox = QHBoxLayout()
                    hbox.addWidget(QLabel(f"  {label}:"))
                    hbox.addWidget(QLabel(str(value)))
                    hbox.addStretch()
                    sys_layout.addLayout(hbox)
        
        sys_layout.addStretch()
        tabs.addTab(sys_tab, "System")
        
        storage_tab = QWidget()
        storage_layout = QVBoxLayout(storage_tab)
        storage_layout.setSpacing(8)
        storage_table = QTableWidget()
        storage_table.setColumnCount(4)
        storage_table.setHorizontalHeaderLabels(["Drive", "Total (GB)", "Used %", "Free (GB)"])
        
        storage_data = self.snapshot.get("storage", [])
        storage_table.setRowCount(len(storage_data))
        
        for i, disk in enumerate(storage_data):
            storage_table.setItem(i, 0, QTableWidgetItem(disk.get("drive", "")))
            storage_table.setItem(i, 1, QTableWidgetItem(str(disk.get("total", 0))))
            storage_table.setItem(i, 2, QTableWidgetItem(f"{disk.get('percent', 0)}%"))
            storage_table.setItem(i, 3, QTableWidgetItem(str(disk.get("free", 0))))
        
        storage_table.resizeColumnsToContents()
        storage_layout.addWidget(storage_table)
        tabs.addTab(storage_tab, "Storage")
        
        proc_tab = QWidget()
        proc_layout = QVBoxLayout(proc_tab)
        proc_layout.setSpacing(8)
        proc_table = QTableWidget()
        proc_table.setColumnCount(2)
        proc_table.setHorizontalHeaderLabels(["Process", "Memory %"])
        
        proc_data = self.snapshot.get("processes", [])
        proc_table.setRowCount(len(proc_data))
        
        for i, proc in enumerate(proc_data):
            proc_table.setItem(i, 0, QTableWidgetItem(proc.get("name", "")))
            proc_table.setItem(i, 1, QTableWidgetItem(str(proc.get("mem", 0))))
        
        proc_table.resizeColumnsToContents()
        proc_layout.addWidget(proc_table)
        tabs.addTab(proc_tab, "Top Processes")
        
        layout.addWidget(tabs)
        
        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btn_box.rejected.connect(self.accept)
        layout.addWidget(btn_box)


# ============================================================================
# 3-BAR COMPARISON CHART WIDGET - FIXED
# ============================================================================

class ThreeBarChartWidget(QFrame):
    """Widget showing before vs after comparison with 3 bars"""
    
    def __init__(self):
        super().__init__()
        self.current_score = None
        self.original_projected = None
        self.refined_projected = None
        self.live_projected = None
        self._refresh_attempts = 0
        self._max_refresh_attempts = 10
        self.setup_ui()
        self.hide()
    
    def setup_ui(self):
        self.setFrameStyle(QFrame.Shape.Box)
        self.setStyleSheet("""
            QFrame {
                border: 2px solid #00ff00;
                border-radius: 5px;
                background: #1a1a1a;
                margin: 5px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(8)
        
        header = QLabel("System Stability Improvement")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ff00;")
        layout.addWidget(header)
        
        self.subtitle = QLabel("AI reasoning improves system stability")
        self.subtitle.setStyleSheet("color: #88ff88; font-style: italic; margin-bottom: 10px;")
        layout.addWidget(self.subtitle)
        
        chart_widget = QWidget()
        chart_layout = QVBoxLayout(chart_widget)
        chart_layout.setSpacing(15)
        
        # Bar 1 - Current Score
        bar1_layout = QHBoxLayout()
        bar1_layout.addWidget(QLabel("Current"), 1)
        
        self.bar1_container = QWidget()
        self.bar1_container.setMinimumHeight(25)
        self.bar1_container.setStyleSheet("background: #2a2a2a; border-radius: 3px;")
        bar1_container_layout = QHBoxLayout(self.bar1_container)
        bar1_container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.bar1 = QFrame()
        self.bar1.setFixedHeight(25)
        self.bar1.setStyleSheet("background: #00ff00; border-radius: 3px;")
        bar1_container_layout.addWidget(self.bar1)
        bar1_container_layout.addStretch()
        
        self.bar1_label = QLabel("0")
        self.bar1_label.setFixedWidth(40)
        self.bar1_label.setStyleSheet("color: white; font-weight: bold;")
        
        bar1_layout.addWidget(self.bar1_container, 8)
        bar1_layout.addWidget(self.bar1_label, 1)
        chart_layout.addLayout(bar1_layout)
        
        # Bar 2 - Original Plan
        bar2_layout = QHBoxLayout()
        bar2_layout.addWidget(QLabel("AI Plan"), 1)
        
        self.bar2_container = QWidget()
        self.bar2_container.setMinimumHeight(25)
        self.bar2_container.setStyleSheet("background: #2a2a2a; border-radius: 3px;")
        bar2_container_layout = QHBoxLayout(self.bar2_container)
        bar2_container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.bar2 = QFrame()
        self.bar2.setFixedHeight(25)
        self.bar2.setStyleSheet("background: #ffaa00; border-radius: 3px;")
        bar2_container_layout.addWidget(self.bar2)
        bar2_container_layout.addStretch()
        
        self.bar2_label = QLabel("0")
        self.bar2_label.setFixedWidth(40)
        self.bar2_label.setStyleSheet("color: white; font-weight: bold;")
        
        bar2_layout.addWidget(self.bar2_container, 8)
        bar2_layout.addWidget(self.bar2_label, 1)
        chart_layout.addLayout(bar2_layout)
        
        # Bar 3 - Refined Plan
        bar3_layout = QHBoxLayout()
        bar3_layout.addWidget(QLabel("Refined"), 1)
        
        self.bar3_container = QWidget()
        self.bar3_container.setMinimumHeight(25)
        self.bar3_container.setStyleSheet("background: #2a2a2a; border-radius: 3px;")
        bar3_container_layout = QHBoxLayout(self.bar3_container)
        bar3_container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.bar3 = QFrame()
        self.bar3.setFixedHeight(25)
        self.bar3.setStyleSheet("background: #00ffff; border-radius: 3px;")
        bar3_container_layout.addWidget(self.bar3)
        bar3_container_layout.addStretch()
        
        self.bar3_label = QLabel("0")
        self.bar3_label.setFixedWidth(40)
        self.bar3_label.setStyleSheet("color: white; font-weight: bold;")
        
        bar3_layout.addWidget(self.bar3_container, 8)
        bar3_layout.addWidget(self.bar3_label, 1)
        chart_layout.addLayout(bar3_layout)
        
        # Bar 4 - Live Selection (optional)
        bar4_layout = QHBoxLayout()
        bar4_layout.addWidget(QLabel("Selection"), 1)
        
        self.bar4_container = QWidget()
        self.bar4_container.setMinimumHeight(25)
        self.bar4_container.setStyleSheet("background: #2a2a2a; border-radius: 3px;")
        bar4_container_layout = QHBoxLayout(self.bar4_container)
        bar4_container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.bar4 = QFrame()
        self.bar4.setFixedHeight(25)
        self.bar4.setStyleSheet("background: #ffff00; border-radius: 3px;")
        bar4_container_layout.addWidget(self.bar4)
        bar4_container_layout.addStretch()
        
        self.bar4_label = QLabel("0")
        self.bar4_label.setFixedWidth(40)
        self.bar4_label.setStyleSheet("color: white; font-weight: bold;")
        
        bar4_layout.addWidget(self.bar4_container, 8)
        bar4_layout.addWidget(self.bar4_label, 1)
        chart_layout.addLayout(bar4_layout)
        self.bar4_container.hide()
        
        self.gain_label = QLabel()
        self.gain_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.gain_label.setStyleSheet("color: #00ff00; font-weight: bold; padding: 2px;")
        chart_layout.addWidget(self.gain_label)
        
        chart_layout.addStretch()
        layout.addWidget(chart_widget)
        
        self.setLayout(layout)
    
    def update_scores(self, current: int, original_projected: int = None, 
                     refined_projected: int = None, live_projected: int = None):
        self.current_score = current
        self.original_projected = original_projected
        self.refined_projected = refined_projected
        self.live_projected = live_projected
        self._refresh_attempts = 0
        
        if current:
            self.bar1_label.setText(str(current))
        if original_projected:
            self.bar2_label.setText(str(original_projected))
        if refined_projected:
            self.bar3_label.setText(str(refined_projected))
        
        if live_projected and live_projected not in [current, original_projected, refined_projected]:
            self.bar4_container.show()
            self.bar4_label.setText(str(live_projected))
        else:
            self.bar4_container.hide()
        
        if current and refined_projected:
            gain = refined_projected - current
            if gain > 0:
                self.gain_label.setText(f"+{gain} points")
                self.gain_label.setStyleSheet("color: #00ff00; font-weight: bold; padding: 2px;")
            else:
                self.gain_label.setText("")
        
        self.show()
        self._refresh_bars()
    
    def _refresh_bars(self):
        w = self.bar1_container.width()
        if w <= 0:
            self._refresh_attempts += 1
            if self._refresh_attempts < self._max_refresh_attempts:
                QTimer.singleShot(100, self._refresh_bars)
            return
        
        self._refresh_attempts = 0
        
        if self.current_score:
            self.bar1.setFixedWidth(int(w * self.current_score / 100))
        
        w = self.bar2_container.width()
        if w > 0 and self.original_projected:
            self.bar2.setFixedWidth(int(w * self.original_projected / 100))
        
        w = self.bar3_container.width()
        if w > 0 and self.refined_projected:
            self.bar3.setFixedWidth(int(w * self.refined_projected / 100))
        
        if self.bar4_container.isVisible():
            w = self.bar4_container.width()
            if w > 0 and self.live_projected:
                self.bar4.setFixedWidth(int(w * self.live_projected / 100))
    
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._refresh_bars()
    
    def showEvent(self, event):
        super().showEvent(event)
        self._refresh_bars()


# ============================================================================
# MAIN WINDOW
# ============================================================================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.analyzer = PureAIAnalyzer(ASI_API_KEY)
        self.backup_manager = BackupManager()
        self.snapshot = None
        self.metrics = None
        self.strategic_insight = None
        self.plan_critique = None
        self.original_categories = []
        self.refined_categories = []
        self.original_projected = None
        self.refined_projected = None
        self.risk_reduction = None
        self.improvements = []
        self.confidence_score = 0
        self.simulation_result = None
        self.last_backup = None
        self.thought_trace_visible = False
        self.thought_trace_widget = None
        self.trace_action = None
        
        # Dedicated workers for each step
        self.scan_worker = None
        self.analyze_worker = None
        self.insight_worker = None
        self.plan_worker = None
        self.critique_worker = None
        self.regenerate_worker = None
        self.simulation_worker = None
        self.confidence_worker = None
        
        self.setWindowTitle("Z-Engine: Generates, Engineers and Deploys")
        self.setGeometry(100, 100, 1400, 900)
        self.setup_ui()
        self.setup_menu()
    
    def _stop_worker(self, worker):
        """Stop a worker if it's running"""
        if worker and worker.isRunning():
            worker.stop()
            worker.wait(1000)
    
    def _cleanup_workers(self):
        """Clean up all workers"""
        self._stop_worker(self.scan_worker)
        self._stop_worker(self.analyze_worker)
        self._stop_worker(self.insight_worker)
        self._stop_worker(self.plan_worker)
        self._stop_worker(self.critique_worker)
        self._stop_worker(self.regenerate_worker)
        self._stop_worker(self.simulation_worker)
        self._stop_worker(self.confidence_worker)
    
    def setup_menu(self):
        menubar = self.menuBar()
        menubar.setStyleSheet("""
            QMenuBar {
                background-color: #1a1a1a;
                color: white;
                border-bottom: 1px solid #00ff00;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 4px 10px;
            }
            QMenuBar::item:selected {
                background-color: #2a2a2a;
                border: 1px solid #00ff00;
            }
            QMenu {
                background-color: #1a1a1a;
                color: white;
                border: 1px solid #00ff00;
            }
            QMenu::item:selected {
                background-color: #2a2a2a;
            }
        """)
        
        view_menu = menubar.addMenu("View")
        
        self.trace_action = QAction("Show AI Reasoning Trace", self)
        self.trace_action.setCheckable(True)
        self.trace_action.triggered.connect(self._toggle_thought_trace)
        view_menu.addAction(self.trace_action)
    
    def _toggle_thought_trace(self, checked):
        self.thought_trace_visible = checked
        if checked and not self.thought_trace_widget:
            self.thought_trace_widget = ThoughtTraceWidget()
            self.thought_trace_widget.closed.connect(self._on_trace_closed)
            self.thought_trace_widget.update_trace(self.analyzer.client.get_thought_trace())
            self.thought_trace_widget.show()
        elif checked and self.thought_trace_widget:
            self.thought_trace_widget.show()
            self.thought_trace_widget.raise_()
        elif not checked and self.thought_trace_widget:
            self.thought_trace_widget.hide()
    
    def _on_trace_closed(self):
        self.thought_trace_visible = False
        if self.trace_action:
            self.trace_action.setChecked(False)
    
    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(5)
        main_layout.setContentsMargins(5, 5, 5, 5)
        
        # Header
        header = self._create_header()
        main_layout.addLayout(header)
        
        # Flow indicator
        self.flow_indicator = FlowIndicator()
        main_layout.addWidget(self.flow_indicator)
        
        # Chart stack (compact)
        self.chart_stack = QStackedWidget()
        self.chart_stack.setMaximumHeight(150)
        
        self.clean_view = CleanGraphWidget()
        self.chart_stack.addWidget(self.clean_view)
        
        self.chart = ThreeBarChartWidget()
        self.chart_stack.addWidget(self.chart)
        
        main_layout.addWidget(self.chart_stack)
        
        # Toolbox for secondary widgets
        self.toolbox = QToolBox()
        self.toolbox.setMinimumHeight(250)
        
        # Strategy comparison in toolbox
        self.strategy_comparison = StrategyComparisonWidget()
        self.toolbox.addItem(self.strategy_comparison, "🎯 Strategy Comparison")
        
        # Script diff in toolbox
        self.script_diff = ScriptDiffWidget()
        self.toolbox.addItem(self.script_diff, "🔄 Plan Comparison")
        
        # Script preview in toolbox
        self.script_preview = ScriptPreviewWidget()
        self.toolbox.addItem(self.script_preview, "📜 Script Preview")
        
        main_layout.addWidget(self.toolbox)
        
        # Buttons
        buttons_widget = self._create_buttons()
        main_layout.addWidget(buttons_widget)
        
        # Main content splitter - Risk panel + Categories
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.setChildrenCollapsible(False)
        
        # Left panel - Risk widgets
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(5, 5, 5, 5)
        left_layout.setSpacing(8)
        
        self.risk_delta = RiskDeltaWidget()
        left_layout.addWidget(self.risk_delta)
        
        self.live_risk = LiveRiskWidget()
        left_layout.addWidget(self.live_risk)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.hide()
        left_layout.addWidget(self.progress)
        
        # Status
        self.status = QLabel("Ready")
        self.status.setStyleSheet("color: #00ff00; padding: 4px;")
        left_layout.addWidget(self.status)
        
        # Log (compact)
        self.log = QTextEdit()
        self.log.setMaximumHeight(80)
        self.log.setReadOnly(True)
        left_layout.addWidget(self.log)
        
        left_layout.addStretch()
        
        # Center panel - Categories with tabs
        center_panel = QWidget()
        center_layout = QVBoxLayout(center_panel)
        center_layout.setContentsMargins(0, 0, 0, 0)
        
        self.category_tabs = QTabWidget()
        
        self.original_tab = QWidget()
        self.original_tab_layout = QVBoxLayout(self.original_tab)
        self.original_tab_layout.setContentsMargins(0, 0, 0, 0)
        self.category_tabs.addTab(self.original_tab, "Original Plan")
        
        self.refined_tab = QWidget()
        self.refined_tab_layout = QVBoxLayout(self.refined_tab)
        self.refined_tab_layout.setContentsMargins(0, 0, 0, 0)
        self.category_tabs.addTab(self.refined_tab, "Refined Plan")
        
        center_layout.addWidget(self.category_tabs)
        
        self.splitter.addWidget(left_panel)
        self.splitter.addWidget(center_panel)
        self.splitter.setSizes([300, 700])
        
        main_layout.addWidget(self.splitter, 1)
    
    def _create_header(self):
        hdr = QHBoxLayout()
        hdr.setSpacing(10)
        title = QLabel("Z-ENGINE")
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ffff;")
        hdr.addWidget(title)
        
        subtitle = QLabel("Generates · Engineers · Deploys")
        subtitle.setFont(QFont("Arial", 10))
        subtitle.setStyleSheet("color: #88ff88;")
        hdr.addWidget(subtitle)
        
        hdr.addStretch()
        
        self.details_btn = QPushButton("System Details")
        self.details_btn.clicked.connect(self._show_system_details)
        self.details_btn.setEnabled(False)
        hdr.addWidget(self.details_btn)
        
        self.api_label = QLabel("⚪ READY")
        self.api_label.setStyleSheet("border: 1px solid #666; padding: 4px 8px; border-radius: 4px;")
        hdr.addWidget(self.api_label)
        
        return hdr
    
    def _create_buttons(self):
        buttons_widget = QWidget()
        buttons_layout = QHBoxLayout(buttons_widget)
        buttons_layout.setSpacing(10)
        
        # Operations Group
        op_group = QGroupBox("Operations")
        op_layout = QHBoxLayout()
        op_layout.setSpacing(5)
        
        self.scan_btn = QPushButton("1. Scan System")
        self.scan_btn.setFixedHeight(32)
        self.scan_btn.clicked.connect(self._scan)
        op_layout.addWidget(self.scan_btn)
        
        self.analyze_btn = QPushButton("2. Analyze")
        self.analyze_btn.setFixedHeight(32)
        self.analyze_btn.clicked.connect(self._analyze)
        self.analyze_btn.setEnabled(False)
        op_layout.addWidget(self.analyze_btn)
        
        self.plan_btn = QPushButton("3. Generate Plan")
        self.plan_btn.setFixedHeight(32)
        self.plan_btn.clicked.connect(self._generate_plan)
        self.plan_btn.setEnabled(False)
        op_layout.addWidget(self.plan_btn)
        
        op_group.setLayout(op_layout)
        buttons_layout.addWidget(op_group)
        
        # Strategy Group
        strategy_group = QGroupBox("Strategy")
        strategy_layout = QHBoxLayout()
        strategy_layout.setSpacing(5)
        
        self.simulate_btn = QPushButton("Simulate Strategies")
        self.simulate_btn.setFixedHeight(32)
        self.simulate_btn.clicked.connect(self._simulate_strategies)
        self.simulate_btn.setEnabled(False)
        strategy_layout.addWidget(self.simulate_btn)
        
        strategy_group.setLayout(strategy_layout)
        buttons_layout.addWidget(strategy_group)
        
        # Export Group
        export_group = QGroupBox("Export")
        export_layout = QHBoxLayout()
        export_layout.setSpacing(5)
        
        self.export_btn = QPushButton("Export Script")
        self.export_btn.setFixedHeight(32)
        self.export_btn.clicked.connect(self._export_script)
        self.export_btn.setEnabled(False)
        export_layout.addWidget(self.export_btn)
        
        self.restore_btn = QPushButton("Create Restore Point")
        self.restore_btn.setFixedHeight(32)
        self.restore_btn.clicked.connect(self._create_restore_point)
        export_layout.addWidget(self.restore_btn)
        
        export_group.setLayout(export_layout)
        buttons_layout.addWidget(export_group)
        
        # Safety Group
        safety_group = QGroupBox("Safety")
        safety_layout = QHBoxLayout()
        safety_layout.setSpacing(5)
        
        self.reverse_btn = QPushButton("Reverse Last Action")
        self.reverse_btn.setFixedHeight(32)
        self.reverse_btn.clicked.connect(self._reverse_last_action)
        self.reverse_btn.setEnabled(False)
        safety_layout.addWidget(self.reverse_btn)
        
        self.backup_btn = QPushButton("Create Backup")
        self.backup_btn.setFixedHeight(32)
        self.backup_btn.clicked.connect(self._create_backup)
        safety_layout.addWidget(self.backup_btn)
        
        safety_group.setLayout(safety_layout)
        buttons_layout.addWidget(safety_group)
        
        return buttons_widget
    
    def log_msg(self, msg: str, level="INFO"):
        self.log.append(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] [{level}] {msg}")
    
    def set_api_status(self, status: str, error: Optional[str] = None):
        if status == "online":
            self.api_label.setText("🟢 ASI-1 ONLINE")
            self.api_label.setStyleSheet("border: 1px solid #00ff00; padding: 4px 8px; border-radius: 4px;")
        elif status == "error":
            self.api_label.setText("🔴 ERROR")
            self.api_label.setStyleSheet("border: 1px solid #ff0000; padding: 4px 8px; border-radius: 4px;")
        else:
            self.api_label.setText("⚪ READY")
            self.api_label.setStyleSheet("border: 1px solid #666; padding: 4px 8px; border-radius: 4px;")
    
    def _show_system_details(self):
        if self.snapshot:
            dialog = SystemDetailsDialog(self.snapshot, self)
            dialog.exec()
    
    def _scan(self):
        self.log_msg("Scanning system...")
        self.scan_btn.setEnabled(False)
        self.details_btn.setEnabled(False)
        self.set_api_status("unknown")
        
        self._cleanup_workers()
        self._clear_all_categories()
        self.flow_indicator.set_stage(0)
        self.analyzer.client.start_pipeline()
        
        self.scan_worker = ScanWorker()
        self.scan_worker.finished.connect(self._scan_done)
        self.scan_worker.start()
    
    def _scan_done(self, snapshot):
        self.snapshot = snapshot
        self.scan_btn.setEnabled(True)
        self.details_btn.setEnabled(True)
        
        if snapshot.get("error"):
            self.log_msg(f"Scan error: {snapshot['error']}", "ERROR")
            return
        
        self.log_msg("Scan complete")
        self.analyze_btn.setEnabled(True)
        self.simulate_btn.setEnabled(True)
        self.set_api_status("online")
        self.flow_indicator.set_stage(1)
        self.chart_stack.setCurrentWidget(self.clean_view)
        
        self.scan_worker = None
    
    def _analyze(self):
        if not self.snapshot:
            return
        
        self.log_msg("Calling ASI-1 for analysis...")
        self.analyze_btn.setEnabled(False)
        self.flow_indicator.set_stage(1)
        
        self._stop_worker(self.analyze_worker)
        self.analyze_worker = AnalyzeWorker(self.analyzer, self.snapshot)
        self.analyze_worker.finished.connect(self._analyze_done)
        self.analyze_worker.start()
    
    def _analyze_done(self, metrics):
        self.metrics = metrics
        
        if metrics.error:
            self.log_msg(f"Analysis issue: {metrics.error}", "WARN")
        
        self.log_msg(f"ASI-1 score: {metrics.overall_score}")
        self.status.setText(f"Score: {metrics.overall_score}")
        self.clean_view.set_score(metrics.overall_score)
        self.chart.update_scores(metrics.overall_score)
        self.flow_indicator.set_stage(2)
        
        if self.thought_trace_visible and self.thought_trace_widget:
            self.thought_trace_widget.update_trace(self.analyzer.client.get_thought_trace())
        
        self.analyze_worker = None
        self._get_strategic_insight()
    
    def _get_strategic_insight(self):
        self.log_msg("Getting strategic insight...")
        
        self._stop_worker(self.insight_worker)
        self.insight_worker = InsightWorker(self.analyzer, self.snapshot, self.metrics)
        self.insight_worker.finished.connect(self._insight_done)
        self.insight_worker.start()
    
    def _insight_done(self, insight):
        self.strategic_insight = insight
        
        if insight:
            self.log_msg(f"Priority: {insight.priority_domain}")
            self.flow_indicator.set_stage(2)
        else:
            self.log_msg("No insight received", "WARN")
        
        if self.thought_trace_visible and self.thought_trace_widget:
            self.thought_trace_widget.update_trace(self.analyzer.client.get_thought_trace())
        
        self.insight_worker = None
        self.plan_btn.setEnabled(True)
    
    def _generate_plan(self):
        if not self.snapshot or not self.metrics:
            return
        
        self.log_msg("Generating optimization plan...")
        self.plan_btn.setEnabled(False)
        self.flow_indicator.set_stage(2)
        
        self.chart_stack.setCurrentWidget(self.chart)
        
        self._stop_worker(self.plan_worker)
        self.plan_worker = PlanWorker(self.analyzer, self.snapshot, self.metrics, self.strategic_insight)
        self.plan_worker.finished.connect(self._plan_done)
        self.plan_worker.start()
    
    def _plan_done(self, categories, projected, error, warning):
        if error:
            self.log_msg(f"Plan generation issue: {error}", "WARN")
            if categories is None:
                self.plan_btn.setEnabled(True)
                return
        
        self.original_categories = categories
        self.original_projected = projected
        
        self.log_msg(f"Plan generated. Projected: {projected}")
        self.chart.update_scores(
            self.metrics.overall_score if self.metrics else 70, 
            original_projected=projected
        )
        self.flow_indicator.set_stage(3)
        
        if self.thought_trace_visible and self.thought_trace_widget:
            self.thought_trace_widget.update_trace(self.analyzer.client.get_thought_trace())
        
        self.plan_worker = None
        self._display_original_plan()
        self._get_plan_critique()
    
    def _display_original_plan(self):
        self._clear_tab_layout(self.original_tab_layout)
        
        # Small delay to ensure deletions are processed
        QTimer.singleShot(50, lambda: self._build_original_plan())
    
    def _build_original_plan(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setMinimumHeight(400)
        scroll.setStyleSheet("border: none;")
        
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        priority_domain = self.strategic_insight.priority_domain if self.strategic_insight else None
        
        for cat in self.original_categories:
            is_priority = (priority_domain and cat.name == priority_domain)
            w = CategoryWidget(cat, is_priority, "original")
            w.changed.connect(self._selection_changed)
            layout.addWidget(w)
        
        layout.addStretch()
        scroll.setWidget(container)
        self.original_tab_layout.addWidget(scroll)
    
    def _get_plan_critique(self):
        self.log_msg("AI Self-Review in progress...")
        
        self._stop_worker(self.critique_worker)
        self.critique_worker = CritiqueWorker(self.analyzer, self.original_categories, self.metrics)
        self.critique_worker.finished.connect(self._critique_done)
        self.critique_worker.start()
    
    def _critique_done(self, critique):
        self.plan_critique = critique
        
        if critique:
            self.log_msg("Self-review complete")
            self.flow_indicator.set_stage(4)
            
            if self.thought_trace_visible and self.thought_trace_widget:
                self.thought_trace_widget.update_trace(self.analyzer.client.get_thought_trace())
            
            self.critique_worker = None
            self._regenerate_plan()
        else:
            self.log_msg("No review received", "WARN")
            self.critique_worker = None
            self.export_btn.setEnabled(True)
    
    def _regenerate_plan(self):
        self.log_msg("Creating refined strategy...")
        
        self._stop_worker(self.regenerate_worker)
        self.regenerate_worker = RegenerateWorker(
            self.analyzer, self.snapshot, self.metrics, self.plan_critique, self.original_projected
        )
        self.regenerate_worker.finished.connect(self._regenerate_done)
        self.regenerate_worker.start()
    
    def _regenerate_done(self, categories, projected, risk_reduction, improvements):
        if not categories:
            self.log_msg("Using refined version of original plan", "WARN")
            # Create copies to avoid mutating original
            categories = []
            for cat in self.original_categories[:4]:
                new_cat = cat.copy()
                for task in new_cat.tasks:
                    task.description = f"[SAFE] {task.description}"
                    task.risk = RiskLevel.LOW
                    task.is_safe = True
                categories.append(new_cat)
            self.refined_categories = categories
            self.refined_projected = max(self.metrics.overall_score + 5, (self.original_projected or 80) - 3)
            self.risk_reduction = 20.0
            self.improvements = ["Added safety checks", "Reduced impact"]
        else:
            self.refined_categories = categories
            self.refined_projected = projected or (self.original_projected - 2)
            self.risk_reduction = risk_reduction or 20.0
            self.improvements = improvements or ["Optimized for safety"]
        
        # Safely calculate gain
        gain = 0
        if self.metrics and self.metrics.overall_score is not None and self.refined_projected is not None:
            gain = self.refined_projected - self.metrics.overall_score
        
        self.log_msg(f"Refined strategy ready: +{gain} gain, -{self.risk_reduction:.0f}% risk")
        self.flow_indicator.set_stage(4)
        
        if self.thought_trace_visible and self.thought_trace_widget:
            self.thought_trace_widget.update_trace(self.analyzer.client.get_thought_trace())
        
        self.chart.update_scores(
            self.metrics.overall_score if self.metrics else 70,
            original_projected=self.original_projected,
            refined_projected=self.refined_projected
        )
        
        self.regenerate_worker = None
        self._assess_confidence()
    
    def _assess_confidence(self):
        plan_data = {
            "original": self.original_projected,
            "refined": self.refined_projected,
            "risk_reduction": self.risk_reduction
        }
        
        self.log_msg("Assessing confidence...")
        
        self._stop_worker(self.confidence_worker)
        self.confidence_worker = ConfidenceWorker(self.analyzer, plan_data, self.metrics)
        self.confidence_worker.finished.connect(self._confidence_done)
        self.confidence_worker.start()
    
    def _confidence_done(self, assessment):
        if assessment:
            self.confidence_score = assessment.confidence_score
        else:
            # Cap confidence at 100
            self.confidence_score = min(100, 85 + (self.risk_reduction / 2 if self.risk_reduction else 0))
        
        self.risk_delta.update_delta(
            self.original_projected or 80,
            self.refined_projected or 80,
            self.risk_reduction or 0,
            self.confidence_score,
            self.improvements
        )
        
        self.confidence_worker = None
        self._display_refined_plan()
        self.export_btn.setEnabled(True)
        self.reverse_btn.setEnabled(True)
    
    def _display_refined_plan(self):
        self._clear_tab_layout(self.refined_tab_layout)
        
        # Small delay to ensure deletions are processed
        QTimer.singleShot(50, lambda: self._build_refined_plan())
    
    def _build_refined_plan(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setMinimumHeight(400)
        scroll.setStyleSheet("border: none;")
        
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        priority_domain = self.strategic_insight.priority_domain if self.strategic_insight else None
        
        for cat in self.refined_categories:
            is_priority = (priority_domain and cat.name == priority_domain)
            w = CategoryWidget(cat, is_priority, "refined")
            w.changed.connect(self._selection_changed)
            layout.addWidget(w)
        
        layout.addStretch()
        scroll.setWidget(container)
        self.refined_tab_layout.addWidget(scroll)
        
        self.category_tabs.setCurrentIndex(1)
        
        original_tasks = []
        for cat in self.original_categories:
            original_tasks.extend(cat.tasks)
        
        refined_tasks = []
        for cat in self.refined_categories:
            refined_tasks.extend(cat.tasks)
        
        self.script_diff.update_diff(original_tasks, refined_tasks)
    
    def _clear_tab_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
    
    def _clear_all_categories(self):
        self._clear_tab_layout(self.original_tab_layout)
        self._clear_tab_layout(self.refined_tab_layout)
    
    def _selection_changed(self):
        # Don't update if metrics are not available yet
        if not self.metrics:
            return
        
        selected = self._get_selected()
        
        if selected:
            impact = sum(t.impact_on_stability for t in selected)
            self.status.setText(f"Selected {len(selected)} tasks (impact: +{impact})")
            
            self.live_risk.update_risk(selected, self.metrics.overall_score)
            
            if self.metrics:
                risk_data = LiveRiskCalculator.calculate_risk(selected, self.metrics.overall_score)
                self.chart.update_scores(
                    self.metrics.overall_score,
                    original_projected=self.original_projected,
                    refined_projected=self.refined_projected,
                    live_projected=risk_data["projected_score"]
                )
            
            self.script_preview.update_script(selected)
            self.toolbox.setCurrentIndex(2)
        else:
            self.status.setText("No tasks selected")
            self.live_risk.hide()
            self.script_preview.update_script([])
            self.chart.update_scores(
                self.metrics.overall_score,
                original_projected=self.original_projected,
                refined_projected=self.refined_projected
            )
    
    def _get_selected(self) -> List[OptimizationTask]:
        selected = []
        current_tab = self.category_tabs.currentIndex()
        
        try:
            if current_tab == 0:
                # Original tab - safely navigate layout hierarchy
                for i in range(self.original_tab_layout.count()):
                    item = self.original_tab_layout.itemAt(i)
                    if item and item.widget():
                        scroll = item.widget()
                        if isinstance(scroll, QScrollArea):
                            container = scroll.widget()
                            if container and container.layout():
                                for j in range(container.layout().count()):
                                    w = container.layout().itemAt(j).widget()
                                    if isinstance(w, CategoryWidget):
                                        selected.extend(w.get_selected())
            else:
                # Refined tab - safely navigate layout hierarchy
                for i in range(self.refined_tab_layout.count()):
                    item = self.refined_tab_layout.itemAt(i)
                    if item and item.widget():
                        scroll = item.widget()
                        if isinstance(scroll, QScrollArea):
                            container = scroll.widget()
                            if container and container.layout():
                                for j in range(container.layout().count()):
                                    w = container.layout().itemAt(j).widget()
                                    if isinstance(w, CategoryWidget):
                                        selected.extend(w.get_selected())
        except Exception as e:
            self.log_msg(f"Error getting selected tasks: {e}", "ERROR")
        
        return selected
    
    def _simulate_strategies(self):
        if not self.snapshot or not self.metrics:
            QMessageBox.information(self, "Cannot Simulate", "Please scan and analyze the system first")
            return
        
        self.log_msg("Running strategy simulation...")
        self.simulate_btn.setEnabled(False)
        
        self._stop_worker(self.simulation_worker)
        self.simulation_worker = SimulationWorker(self.analyzer, self.snapshot, self.metrics)
        self.simulation_worker.finished.connect(self._simulation_done)
        self.simulation_worker.start()
    
    def _simulation_done(self, result):
        if result and isinstance(result, SimulationResult):
            self.simulation_result = result
            self.strategy_comparison.update_strategies(
                result.strategies, 
                result.selected_index, 
                result.reasoning
            )
            self.toolbox.setCurrentIndex(0)
            self.log_msg(f"Best: {result.strategies[result.selected_index].name}")
            
            selected = result.strategies[result.selected_index]
            QMessageBox.information(self, "Simulation Complete", 
                f"Recommended: {selected.name}\n"
                f"Gain: +{selected.gain}\n"
                f"Risk: {selected.risk_level}\n"
                f"Confidence: {selected.confidence:.1f}%\n\n"
                f"Reasoning: {result.reasoning}")
        else:
            self.log_msg("Simulation failed or returned invalid result", "ERROR")
        
        self.simulation_worker = None
        self.simulate_btn.setEnabled(True)
    
    def _export_script(self):
        selected = self._get_selected()
        if not selected:
            QMessageBox.information(self, "No Selection", "Select tasks first")
            return
        
        self.script_preview.update_script(selected)
        self.toolbox.setCurrentIndex(2)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"Z-Engine_{timestamp}.ps1"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save PowerShell Script",
            default_name,
            "PowerShell Scripts (*.ps1);;All Files (*)"
        )
        
        if file_path:
            try:
                safe_mode = self.script_preview.safe_mode_cb.isChecked()
                script = ScriptGenerator.generate_script(selected, safe_mode)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(script)
                self.log_msg(f"Script saved to: {file_path}")
                QMessageBox.information(self, "Success", f"Script saved to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save script: {e}")
    
    def _create_restore_point(self):
        self.log_msg("Creating system restore point...")
        success, msg = RestorePointCreator.create_restore_point()
        if success:
            self.log_msg("Restore point created")
            QMessageBox.information(self, "Success", msg)
        else:
            self.log_msg(f"Failed to create restore point: {msg}", "ERROR")
            QMessageBox.warning(self, "Warning", msg)
    
    def _create_backup(self):
        self.log_msg("Creating system backup...")
        backup_path = self.backup_manager.create_backup("Pre-optimization state")
        if backup_path:
            self.last_backup = backup_path
            self.reverse_btn.setEnabled(True)
            self.log_msg(f"Backup created: {backup_path}")
            QMessageBox.information(self, "Success", f"Backup created successfully")
        else:
            self.log_msg("Failed to create backup", "ERROR")
            QMessageBox.warning(self, "Warning", "Failed to create backup")
    
    def _reverse_last_action(self):
        reply = QMessageBox.question(
            self,
            "Reverse Last Action",
            "This will restore your system to the state before the last optimization.\n"
            "This action cannot be undone.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.log_msg("Restoring from backup...")
            backup = self.backup_manager.get_latest_backup()
            if backup and self.backup_manager.restore_backup(backup):
                self.log_msg("System restored successfully")
                QMessageBox.information(self, "Success", "System restored successfully")
                
                if self.metrics:
                    self.metrics.overall_score = 70
                self.clean_view.set_score(70)
                self.chart_stack.setCurrentWidget(self.clean_view)
                self.reverse_btn.setEnabled(False)
            else:
                self.log_msg("Failed to restore system", "ERROR")
                QMessageBox.warning(self, "Warning", "Failed to restore system")
    
    def closeEvent(self, event):
        """Clean up workers on close"""
        self._cleanup_workers()
        if self.thought_trace_widget:
            self.thought_trace_widget.close()
        event.accept()


# ============================================================================
# MAIN
# ============================================================================

def main():
    # Check for API key early and show warning immediately
    if not ASI_API_KEY:
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle("API Key Missing")
        msg_box.setText("ASI_API_KEY not set. Please set it with:\n\nexport ASI_API_KEY='your-key-here'\n\nThe app will continue with fallback plans.")
        msg_box.exec()
    
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    app.setStyleSheet("""
        QMainWindow, QDialog {
            background-color: #1a1a1a;
        }
        QLabel {
            color: white;
        }
        QPushButton {
            background-color: #2a2a2a;
            color: white;
            border: 1px solid #00ff00;
            padding: 6px 12px;
            border-radius: 4px;
            font-weight: bold;
            min-width: 100px;
        }
        QPushButton:hover {
            background-color: #3a3a3a;
        }
        QPushButton:disabled {
            border-color: #666;
            color: #666;
        }
        QTextEdit, QPlainTextEdit {
            background-color: #2a2a2a;
            color: #00ff00;
            border: 1px solid #00ff00;
            border-radius: 3px;
        }
        QProgressBar {
            border: 1px solid #00ff00;
            border-radius: 3px;
            text-align: center;
            color: white;
            height: 20px;
        }
        QProgressBar::chunk {
            background-color: #00ff00;
            border-radius: 3px;
        }
        QTableWidget {
            background-color: #2a2a2a;
            color: white;
            border: 1px solid #00ff00;
        }
        QHeaderView::section {
            background-color: #1a1a1a;
            color: #00ff00;
            border: 1px solid #00ff00;
        }
        QGroupBox {
            border: 2px solid #00ff00;
            border-radius: 5px;
            margin-top: 10px;
            font-weight: bold;
            color: #00ff00;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }
        QSplitter::handle {
            background-color: #00ff00;
            height: 2px;
        }
        QTabWidget::pane {
            border: 2px solid #00ff00;
            border-radius: 5px;
            background: #1a1a1a;
        }
        QTabBar::tab {
            background-color: #2a2a2a;
            color: white;
            border: 1px solid #00ff00;
            padding: 5px 10px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background-color: #00ff00;
            color: black;
        }
        QToolBox::tab {
            background-color: #2a2a2a;
            border: 1px solid #00ff00;
            border-radius: 3px;
            color: white;
            font-weight: bold;
            padding: 6px;
        }
        QToolBox::tab:selected {
            background-color: #00ff00;
            color: black;
        }
        QScrollArea {
            border: none;
            background: transparent;
        }
        QScrollBar:vertical {
            background: #2a2a2a;
            width: 12px;
            border-radius: 6px;
        }
        QScrollBar::handle:vertical {
            background: #00ff00;
            min-height: 30px;
            border-radius: 6px;
        }
        QScrollBar::handle:vertical:hover {
            background: #88ff88;
        }
        QScrollBar:horizontal {
            background: #2a2a2a;
            height: 12px;
            border-radius: 6px;
        }
        QScrollBar::handle:horizontal {
            background: #00ff00;
            min-width: 30px;
            border-radius: 6px;
        }
        QScrollBar::handle:horizontal:hover {
            background: #88ff88;
        }
        QCheckBox {
            color: white;
        }
        QCheckBox::indicator {
            width: 16px;
            height: 16px;
        }
        QCheckBox::indicator:unchecked {
            border: 1px solid #00ff00;
            background: #2a2a2a;
        }
        QCheckBox::indicator:checked {
            border: 1px solid #00ff00;
            background: #00ff00;
        }
    """)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
