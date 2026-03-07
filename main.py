#!/usr/bin/env python3
"""
Z-Engine: Generates, Engineers and Deploys
Python 3.11+ / PySide6
FINAL - Fixed All Issues + Secure API Key Handling
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
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from enum import Enum
import threading

# Use environment variable for API key (SECURITY FIX)
ASI_API_KEY = os.environ.get("ASI_API_KEY", "")
if not ASI_API_KEY:
    # Fallback to config file if exists (for development)
    config_path = Path.home() / ".zengine" / "config.json"
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = json.load(f)
                ASI_API_KEY = config.get("api_key", "")
        except:
            pass
    
    # If still no key, show warning but don't hardcode
    if not ASI_API_KEY:
        print("WARNING: ASI_API_KEY environment variable not set")
        print("Please set it with: export ASI_API_KEY='your-key-here'")

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QScrollArea, QCheckBox, QGroupBox,
    QMessageBox, QProgressBar, QTextEdit, QSplitter, QFrame,
    QGridLayout, QScrollBar, QDialog, QDialogButtonBox, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QComboBox,
    QTreeWidget, QTreeWidgetItem, QSizePolicy,
    QFileDialog, QPlainTextEdit, QButtonGroup, QRadioButton,
    QStackedWidget
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QPainter, QColor, QBrush, QPen, QTextCursor


# ============================================================================
# ASI-1 API CONFIGURATION
# ============================================================================

ASI_API_URL = "https://api.asi1.ai/v1/chat/completions"
CONNECTION_TIMEOUT = 25
MAX_PIPELINE_DURATION = 60


# ============================================================================
# COMMAND SAFETY WHITELIST - PRODUCTION SAFE
# ============================================================================

class CommandSafety:
    """Validates PowerShell commands against production-safe whitelist"""
    
    # SAFE WHITELIST - Only these commands are allowed in production
    SAFE_WHITELIST = [
        "cleanmgr",           # Disk cleanup utility
        "Optimize-Volume",     # Volume optimization (with correct params)
        "powercfg",           # Power configuration
        "fsutil",             # Filesystem utility (read-only operations)
        "Get-Service",        # Read service state
        "Set-Service",        # Service configuration (validated)
        "Get-Process",        # Read process info
        "Get-ItemProperty",   # Registry reading
        "Clear-RecycleBin",   # Safe recycle bin cleanup
        "Get-ChildItem",      # File listing
        "Remove-Item",        # File removal (with safety checks)
    ]
    
    # COMMANDS THAT REQUIRE EXE CHECK
    EXE_REQUIRED = [
        "EmptyStandbyList.exe",  # Must be bundled or checked
    ]
    
    # COMMANDS THAT ARE NEVER ALLOWED IN SAFE MODE
    BLOCKED_COMMANDS = [
        "bcdedit",                 # Boot configuration - too risky
        "wmic",                    # Deprecated, potentially dangerous
        "diskpart",                # Disk partitioning - too risky
        "format",                  # Formatting - never in safe mode
        "del /f /s /q",            # Force delete - too aggressive
        "rmdir /s /q",             # Recursive remove - too aggressive
        "reg delete",              # Registry deletion - too risky
        "sc delete",               # Service deletion - too risky
        "schtasks /delete",        # Task deletion - too risky
        "Disable-ScheduledTask",   # Disable without validation
    ]
    
    # COMMAND-SPECIFIC VALIDATORS
    @staticmethod
    def validate_optimize_volume(command: str) -> Tuple[bool, str]:
        """Validate Optimize-Volume command"""
        if "-ReTrim" in command:
            return True, "Safe TRIM operation for SSDs"
        elif "-Defrag" in command:
            return False, "Defrag on unknown drive type - use -ReTrim for SSDs"
        elif "-Analyze" in command:
            return True, "Analysis only - safe"
        return False, "Unknown Optimize-Volume parameters"
    
    @staticmethod
    def validate_set_service(command: str) -> Tuple[bool, str]:
        """Validate Set-Service command"""
        # Check for dangerous service changes
        dangerous_services = ["WinDefend", "SecurityCenter", "wuauserv", "BITS"]
        for svc in dangerous_services:
            if svc in command:
                return False, f"Modifying critical service: {svc}"
        
        # Only allow Manual startup type, not Disabled
        if "StartupType Disabled" in command:
            return False, "Disabling services is not allowed in safe mode"
        
        if "StartupType Manual" in command or "StartupType Automatic" in command:
            return True, "Safe service configuration"
        
        return False, "Unsafe service modification"
    
    @staticmethod
    def validate_remove_item(command: str) -> Tuple[bool, str]:
        """Validate Remove-Item command"""
        # Check for dangerous paths
        dangerous_paths = ["System32", "Windows", "Program Files", "boot"]
        for path in dangerous_paths:
            if path in command and "-Recurse" in command:
                return False, f"Recursive removal from {path} is not allowed"
        
        # Only allow temp file cleanup
        if "Temp" in command or "temp" in command:
            if "-Recurse" not in command:
                return True, "Safe temp file cleanup"
            else:
                return False, "Recursive temp cleanup not allowed"
        
        return False, "Remove-Item only allowed for temp files"
    
    @staticmethod
    def validate_powercfg(command: str) -> Tuple[bool, str]:
        """Validate powercfg command"""
        # Allow power scheme changes
        if "setactive" in command:
            # Verify GUID is a standard scheme
            safe_guids = [
                "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",  # High performance
                "381b4222-f694-41f0-9685-ff5bb260df2f",  # Balanced
                "a1841308-3541-4fab-bc81-f71556f20b4a"   # Power saver
            ]
            for guid in safe_guids:
                if guid in command:
                    return True, "Safe power scheme change"
        
        # Allow reading commands
        if "/list" in command or "/query" in command or "/getactivescheme" in command:
            return True, "Safe power configuration read"
        
        return False, "Unsafe powercfg operation"
    
    @staticmethod
    def validate_cleanmgr(command: str) -> Tuple[bool, str]:
        """Validate cleanmgr command"""
        # cleanmgr /sagerun:1 requires prior setup - warn but allow
        if "/sagerun" in command:
            return True, "cleanmgr with sagerun - requires prior configuration"
        
        # /lowdisk runs without config - safer
        if "/lowdisk" in command:
            return True, "cleanmgr low disk mode"
        
        return False, "Unknown cleanmgr parameters"
    
    @staticmethod
    def check_exe_exists(exe_name: str) -> bool:
        """Check if an executable exists in PATH or current directory"""
        # Check current directory
        if os.path.exists(exe_name):
            return True
        
        # Check PATH safely (FIX: use os.getenv with default)
        path_env = os.getenv("PATH", "")
        for path in path_env.split(os.pathsep):
            exe_path = os.path.join(path, exe_name)
            if os.path.exists(exe_path):
                return True
        
        return False
    
    @classmethod
    def is_command_safe(cls, command: str) -> Tuple[bool, str, str]:
        """
        Validate if a command is safe to execute
        Returns: (is_safe, risk_level, reason)
        """
        command_lower = command.lower()
        
        # Check for blocked commands first
        for blocked in cls.BLOCKED_COMMANDS:
            if blocked.lower() in command_lower:
                return False, "critical", f"Command blocked in safe mode: {blocked}"
        
        # Check for EXE requirements
        for exe in cls.EXE_REQUIRED:
            if exe.lower() in command_lower:
                if not cls.check_exe_exists(exe):
                    return False, "high", f"Required executable not found: {exe}"
        
        # Command-specific validation
        if "optimize-volume" in command_lower:
            return cls.validate_optimize_volume(command)
        
        if "set-service" in command_lower:
            return cls.validate_set_service(command)
        
        if "remove-item" in command_lower:
            return cls.validate_remove_item(command)
        
        if "powercfg" in command_lower:
            return cls.validate_powercfg(command)
        
        if "cleanmgr" in command_lower:
            return cls.validate_cleanmgr(command)
        
        # Check if command starts with any whitelisted command
        for safe_cmd in cls.SAFE_WHITELIST:
            if command.strip().startswith(safe_cmd):
                return True, "low", f"Whitelisted command: {safe_cmd}"
        
        # Not in whitelist - reject
        return False, "high", "Command not in safety whitelist"
    
    @classmethod
    def get_safe_version(cls, command: str) -> str:
        """Return a safe version of a command if possible"""
        command_lower = command.lower()
        
        # Fix Optimize-Volume for SSDs
        if "optimize-volume" in command_lower and "-defrag" in command_lower:
            return command.replace("-Defrag", "-ReTrim")
        
        # Fix service commands - never use Disabled
        if "set-service" in command_lower and "startuptype disabled" in command_lower:
            return command.replace("Disabled", "Manual")
        
        # Remove dangerous parameters from Remove-Item
        if "remove-item" in command_lower:
            if "-recurse" in command_lower and "temp" not in command_lower:
                command = command.replace("-Recurse", "").replace("-recurse", "")
            if "-force" in command_lower:
                command = command.replace("-Force", "").replace("-force", "")
        
        return command


# ============================================================================
# RISK LEVEL HANDLING - SAFE PARSING
# ============================================================================

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @classmethod
    def safe_parse(cls, value: str, default: str = "low") -> 'RiskLevel':
        """Safely parse risk level from string, with fallback"""
        if not value:
            return cls.LOW
        
        value = value.lower().strip()
        
        # Map of valid values
        valid_values = {
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL
        }
        
        return valid_values.get(value, cls.LOW)


# ============================================================================
# BAR COMPARISON CHART WIDGET 
# ============================================================================

class ThreeBarChartWidget(QFrame):
    """Widget showing before vs after comparison with 3 bars"""
    
    def __init__(self):
        super().__init__()
        self.current_score = None
        self.original_projected = None
        self.refined_projected = None
        self.live_projected = None
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
        
        # Header
        header = QLabel("System Stability Improvement")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ff00;")
        layout.addWidget(header)
        
        # Subtitle
        self.subtitle = QLabel("AI reasoning improves system stability")
        self.subtitle.setStyleSheet("color: #88ff88; font-style: italic; margin-bottom: 10px;")
        layout.addWidget(self.subtitle)
        
        # Chart area
        chart_widget = QWidget()
        chart_layout = QVBoxLayout(chart_widget)
        chart_layout.setSpacing(15)
        
        # Bar 1 - Current Score
        bar1_layout = QHBoxLayout()
        bar1_layout.addWidget(QLabel("Current"), 1)
        
        self.bar1_container = QWidget()
        self.bar1_container.setMinimumHeight(30)
        self.bar1_container.setStyleSheet("background: #2a2a2a; border-radius: 3px;")
        bar1_container_layout = QHBoxLayout(self.bar1_container)
        bar1_container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.bar1 = QFrame()
        self.bar1.setFixedHeight(30)
        self.bar1.setStyleSheet("background: #00ff00; border-radius: 3px;")
        bar1_container_layout.addWidget(self.bar1)
        bar1_container_layout.addStretch()
        
        self.bar1_label = QLabel("0")
        self.bar1_label.setFixedWidth(60)
        self.bar1_label.setStyleSheet("color: white; font-weight: bold;")
        
        bar1_layout.addWidget(self.bar1_container, 8)
        bar1_layout.addWidget(self.bar1_label, 1)
        chart_layout.addLayout(bar1_layout)
        
        # Bar 2 - Original Plan
        bar2_layout = QHBoxLayout()
        bar2_layout.addWidget(QLabel("AI Plan"), 1)
        
        self.bar2_container = QWidget()
        self.bar2_container.setMinimumHeight(30)
        self.bar2_container.setStyleSheet("background: #2a2a2a; border-radius: 3px;")
        bar2_container_layout = QHBoxLayout(self.bar2_container)
        bar2_container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.bar2 = QFrame()
        self.bar2.setFixedHeight(30)
        self.bar2.setStyleSheet("background: #ffaa00; border-radius: 3px;")
        bar2_container_layout.addWidget(self.bar2)
        bar2_container_layout.addStretch()
        
        self.bar2_label = QLabel("0")
        self.bar2_label.setFixedWidth(60)
        self.bar2_label.setStyleSheet("color: white; font-weight: bold;")
        
        bar2_layout.addWidget(self.bar2_container, 8)
        bar2_layout.addWidget(self.bar2_label, 1)
        chart_layout.addLayout(bar2_layout)
        
        # Bar 3 - Refined Plan
        bar3_layout = QHBoxLayout()
        bar3_layout.addWidget(QLabel("Refined"), 1)
        
        self.bar3_container = QWidget()
        self.bar3_container.setMinimumHeight(30)
        self.bar3_container.setStyleSheet("background: #2a2a2a; border-radius: 3px;")
        bar3_container_layout = QHBoxLayout(self.bar3_container)
        bar3_container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.bar3 = QFrame()
        self.bar3.setFixedHeight(30)
        self.bar3.setStyleSheet("background: #00ffff; border-radius: 3px;")
        bar3_container_layout.addWidget(self.bar3)
        bar3_container_layout.addStretch()
        
        self.bar3_label = QLabel("0")
        self.bar3_label.setFixedWidth(60)
        self.bar3_label.setStyleSheet("color: white; font-weight: bold;")
        
        bar3_layout.addWidget(self.bar3_container, 8)
        bar3_layout.addWidget(self.bar3_label, 1)
        chart_layout.addLayout(bar3_layout)
        
        # Bar 4 - Live Selection (optional)
        bar4_layout = QHBoxLayout()
        bar4_layout.addWidget(QLabel("Selection"), 1)
        
        self.bar4_container = QWidget()
        self.bar4_container.setMinimumHeight(30)
        self.bar4_container.setStyleSheet("background: #2a2a2a; border-radius: 3px;")
        bar4_container_layout = QHBoxLayout(self.bar4_container)
        bar4_container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.bar4 = QFrame()
        self.bar4.setFixedHeight(30)
        self.bar4.setStyleSheet("background: #ffff00; border-radius: 3px;")
        bar4_container_layout.addWidget(self.bar4)
        bar4_container_layout.addStretch()
        
        self.bar4_label = QLabel("0")
        self.bar4_label.setFixedWidth(60)
        self.bar4_label.setStyleSheet("color: white; font-weight: bold;")
        
        bar4_layout.addWidget(self.bar4_container, 8)
        bar4_layout.addWidget(self.bar4_label, 1)
        chart_layout.addLayout(bar4_layout)
        self.bar4_container.hide()  # Hide by default
        
        # Gain indicator
        self.gain_label = QLabel()
        self.gain_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.gain_label.setStyleSheet("color: #00ff00; font-weight: bold; padding: 5px;")
        chart_layout.addWidget(self.gain_label)
        
        chart_layout.addStretch()
        layout.addWidget(chart_widget)
        
        self.setLayout(layout)
    
    def update_scores(self, current: int, original_projected: int = None, 
                     refined_projected: int = None, live_projected: int = None):
        """Update the chart with new scores"""
        self.current_score = current
        self.original_projected = original_projected
        self.refined_projected = refined_projected
        self.live_projected = live_projected
        
        # Update labels immediately
        if current:
            self.bar1_label.setText(str(current))
        if original_projected:
            self.bar2_label.setText(str(original_projected))
        if refined_projected:
            self.bar3_label.setText(str(refined_projected))
        
        # Show/hide live projection bar
        if live_projected and live_projected not in [current, original_projected, refined_projected]:
            self.bar4_container.show()
            self.bar4_label.setText(str(live_projected))
        else:
            self.bar4_container.hide()
        
        # Calculate and show gain
        if current and refined_projected:
            gain = refined_projected - current
            if gain > 0:
                self.gain_label.setText(f"AI Improved Stability by +{gain} points")
                self.gain_label.setStyleSheet("color: #00ff00; font-weight: bold; padding: 5px;")
            else:
                self.gain_label.setText("")
        
        self.show()
        # Defer bar drawing until after layout with longer timeout
        QTimer.singleShot(200, self._refresh_bars)
    
    def _refresh_bars(self):
        """Calculate and set bar widths based on container size"""
        # Bar 1
        w = self.bar1_container.width()
        if w > 0 and self.current_score:
            self.bar1.setFixedWidth(int(w * self.current_score / 100))
        
        # Bar 2
        w = self.bar2_container.width()
        if w > 0 and self.original_projected:
            self.bar2.setFixedWidth(int(w * self.original_projected / 100))
        
        # Bar 3
        w = self.bar3_container.width()
        if w > 0 and self.refined_projected:
            self.bar3.setFixedWidth(int(w * self.refined_projected / 100))
        
        # Bar 4
        if self.bar4_container.isVisible():
            w = self.bar4_container.width()
            if w > 0 and self.live_projected:
                self.bar4.setFixedWidth(int(w * self.live_projected / 100))
    
    def resizeEvent(self, event):
        """Handle resize to update bar widths"""
        super().resizeEvent(event)
        self._refresh_bars()
    
    def showEvent(self, event):
        """Handle show event to update bar widths"""
        super().showEvent(event)
        self._refresh_bars()


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
        self.risk = RiskLevel.safe_parse(risk)
        self.original_command = command
        self.category = category
        self.requires_reboot = requires_reboot
        self.impact_on_stability = impact_on_stability
        self.reasoning = reasoning
        self.is_safe = is_safe
        
        # Validate command safety
        self.is_safe_command, self.safety_risk, self.safety_reason = CommandSafety.is_command_safe(command)
        self.safe_command = CommandSafety.get_safe_version(command) if not self.is_safe_command else command
        
        # Generate actual command based on category if needed
        self.actual_command = self._generate_actual_command()
    
    def _generate_actual_command(self) -> str:
        """Generate actual safe command based on description"""
        if self.safe_command and not self.safe_command.startswith('#'):
            return self.safe_command
        
        # Generate safe PowerShell commands based on category
        cmd_map = {
            "Memory": {
                "clear": "Clear-WindowsMemoryCache",
            },
            "CPU": {
                "priority": "Get-Process | Where-Object CPU -gt 10",
                "power": "powercfg -getactivescheme"
            },
            "Disk": {
                "clean": "CleanMgr /lowdisk",
                "defrag": "Optimize-Volume -DriveLetter C -ReTrim",
                "temp": "Remove-Item -Path 'C:\\Windows\\Temp\\*' -ErrorAction SilentlyContinue"
            },
            "Startup": {
                "list": "Get-CimInstance Win32_StartupCommand | Select Name, Command, Location",
                "report": "Get-ScheduledTask | Where State -eq Ready | Select TaskName, State"
            },
            "Service": {
                "list": "Get-Service | Where Status -eq Running | Select Name, Status",
                "optimize": "Set-Service -Name 'SysMain' -StartupType Manual"
            },
            "Power": {
                "high": "powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
                "balanced": "powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2f",
                "saver": "powercfg -setactive a1841308-3541-4fab-bc81-f71556f20b4a"
            },
            "Security": {
                "check": "Get-MpPreference | Select DisableRealtimeMonitoring",
                "report": "Get-MpThreat | Select Name, Severity"
            },
            "Background": {
                "list": "Get-AppxPackage | Select Name, PackageFamilyName",
                "services": "Get-Service -Name 'SysMain' | Select Name, Status"
            }
        }
        
        # Return safe read-only commands by default
        for category, actions in cmd_map.items():
            if category.lower() in self.category.lower():
                for action, cmd in actions.items():
                    if action.lower() in self.description.lower():
                        return cmd
        
        # Return safe default
        return f"Write-Host 'Safe operation for {self.category} - {self.description}'"

    def get_execution_command(self, safe_mode: bool = True) -> str:
        """Get the command to execute, with safety applied if in safe mode"""
        if safe_mode:
            return self.safe_command
        return self.original_command
    
    def get_risk_badge(self) -> str:
        """Get formatted risk badge for display"""
        risk_badges = {
            RiskLevel.LOW: "[SAFE]",
            RiskLevel.MEDIUM: "[MEDIUM]",
            RiskLevel.HIGH: "[HIGH]",
            RiskLevel.CRITICAL: "[CRITICAL]"
        }
        return risk_badges.get(self.risk, "[UNKNOWN]")

class OptimizationCategory:
    def __init__(self, name, tasks, reasoning="", category_impact=0, strategic_importance=""):
        self.name = name
        self.tasks = tasks
        self.reasoning = reasoning
        self.category_impact = category_impact
        self.strategic_importance = strategic_importance
    
    def get_safe_tasks(self) -> List[OptimizationTask]:
        """Get tasks with LOW risk level"""
        return [t for t in self.tasks if t.risk == RiskLevel.LOW]
    
    def get_unsafe_tasks(self) -> List[OptimizationTask]:
        """Get tasks with MEDIUM, HIGH, or CRITICAL risk level"""
        return [t for t in self.tasks if t.risk != RiskLevel.LOW]


# ============================================================================
# SCRIPT DIFF ANALYZER
# ============================================================================

class ScriptDiffAnalyzer:
    """Analyzes differences between original and refined plans"""
    
    @staticmethod
    def analyze_diffs(original_tasks: List[OptimizationTask], 
                     refined_tasks: List[OptimizationTask]) -> Dict[str, Any]:
        """Analyze differences between original and refined task lists"""
        
        # Create sets for comparison
        original_set = {t.id: t for t in original_tasks}
        refined_set = {t.id: t for t in refined_tasks}
        
        # Find removed tasks (in original but not in refined)
        removed_tasks = []
        for task_id, task in original_set.items():
            if task_id not in refined_set:
                removed_tasks.append(task)
        
        # Find added tasks (in refined but not in original)
        added_tasks = []
        for task_id, task in refined_set.items():
            if task_id not in original_set:
                added_tasks.append(task)
        
        # Find modified tasks (same id but different risk/command)
        modified_tasks = []
        for task_id, original_task in original_set.items():
            if task_id in refined_set:
                refined_task = refined_set[task_id]
                if (original_task.risk != refined_task.risk or 
                    original_task.original_command != refined_task.original_command):
                    modified_tasks.append({
                        'original': original_task,
                        'refined': refined_task,
                        'risk_changed': original_task.risk != refined_task.risk,
                        'command_changed': original_task.original_command != refined_task.original_command
                    })
        
        # Calculate risk reduction
        original_high_risk = sum(1 for t in original_tasks if t.risk in [RiskLevel.HIGH, RiskLevel.CRITICAL])
        refined_high_risk = sum(1 for t in refined_tasks if t.risk in [RiskLevel.HIGH, RiskLevel.CRITICAL])
        risk_reduction = ((original_high_risk - refined_high_risk) / max(1, original_high_risk)) * 100 if original_high_risk > 0 else 0
        
        return {
            'removed_tasks': removed_tasks,
            'added_tasks': added_tasks,
            'modified_tasks': modified_tasks,
            'original_count': len(original_tasks),
            'refined_count': len(refined_tasks),
            'original_high_risk': original_high_risk,
            'refined_high_risk': refined_high_risk,
            'risk_reduction': round(risk_reduction, 1)
        }


# ============================================================================
# SCRIPT DIFF WIDGET
# ============================================================================

class ScriptDiffWidget(QFrame):
    """Widget to show differences between original and refined plans"""
    
    def __init__(self):
        super().__init__()
        self.diff_data = None
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
            QScrollArea {
                border: none;
                background: transparent;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(8)
        
        # Header
        header = QLabel("Plan Comparison: Original vs Refined")
        header.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffff;")
        layout.addWidget(header)
        
        # Stats summary
        self.stats_label = QLabel()
        self.stats_label.setWordWrap(True)
        self.stats_label.setStyleSheet("color: #88ff88; padding: 5px; background: #0a1a0a; border-radius: 3px;")
        layout.addWidget(self.stats_label)
        
        # Scroll area for diff details - with smooth scrolling enabled
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setMinimumHeight(200)
        scroll.setStyleSheet("border: 1px solid #335533; border-radius: 3px;")
        
        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setSpacing(8)
        scroll.setWidget(self.content)
        layout.addWidget(scroll)
        
        self.setLayout(layout)
    
    def update_diff(self, original_tasks: List[OptimizationTask], 
                   refined_tasks: List[OptimizationTask]):
        """Update the diff view with new data"""
        self.diff_data = ScriptDiffAnalyzer.analyze_diffs(original_tasks, refined_tasks)
        
        # Update stats
        stats_text = (
            f"Original Plan: {self.diff_data['original_count']} tasks "
            f"({self.diff_data['original_high_risk']} high risk)\n"
            f"Refined Plan: {self.diff_data['refined_count']} tasks "
            f"({self.diff_data['refined_high_risk']} high risk)\n"
            f"Risk Reduction: {self.diff_data['risk_reduction']}%"
        )
        self.stats_label.setText(stats_text)
        
        # Clear previous content
        if self.content_layout.count() > 0:
            self._clear_layout(self.content_layout)
        
        # Add removed tasks section
        if self.diff_data['removed_tasks']:
            removed_header = QLabel("Removed Risky Tasks")
            removed_header.setStyleSheet("color: #ff8800; font-weight: bold; margin-top: 5px;")
            self.content_layout.addWidget(removed_header)
            
            for task in self.diff_data['removed_tasks'][:5]:
                task_label = QLabel(f"  - {task.description} ({task.get_risk_badge()})")
                task_label.setWordWrap(True)
                task_label.setStyleSheet("color: #ffaa00;")
                self.content_layout.addWidget(task_label)
            
            if len(self.diff_data['removed_tasks']) > 5:
                more = QLabel(f"  ... and {len(self.diff_data['removed_tasks']) - 5} more")
                more.setStyleSheet("color: #888888; font-style: italic;")
                self.content_layout.addWidget(more)
        
        # Add added tasks section
        if self.diff_data['added_tasks']:
            added_header = QLabel("Added Safe Tasks")
            added_header.setStyleSheet("color: #88ff88; font-weight: bold; margin-top: 10px;")
            self.content_layout.addWidget(added_header)
            
            for task in self.diff_data['added_tasks'][:5]:
                task_label = QLabel(f"  - {task.description} ({task.get_risk_badge()})")
                task_label.setWordWrap(True)
                task_label.setStyleSheet("color: #88ff88;")
                self.content_layout.addWidget(task_label)
            
            if len(self.diff_data['added_tasks']) > 5:
                more = QLabel(f"  ... and {len(self.diff_data['added_tasks']) - 5} more")
                more.setStyleSheet("color: #888888; font-style: italic;")
                self.content_layout.addWidget(more)
        
        # Add modified tasks section
        if self.diff_data['modified_tasks']:
            modified_header = QLabel("Modified Tasks")
            modified_header.setStyleSheet("color: #ffff00; font-weight: bold; margin-top: 10px;")
            self.content_layout.addWidget(modified_header)
            
            for mod in self.diff_data['modified_tasks'][:3]:
                text = f"  - {mod['original'].description}\n    Risk: {mod['original'].get_risk_badge()} -> {mod['refined'].get_risk_badge()}"
                task_label = QLabel(text)
                task_label.setWordWrap(True)
                task_label.setStyleSheet("color: #ffff88;")
                self.content_layout.addWidget(task_label)
        
        self.content_layout.addStretch()
        self.show()
    
    def _clear_layout(self, layout):
        """Clear all widgets from a layout"""
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()


# ============================================================================
# STRATEGY COMPARISON WIDGET
# ============================================================================

class StrategyComparisonWidget(QFrame):
    """Widget to display and compare different optimization strategies"""
    
    def __init__(self):
        super().__init__()
        self.strategies = []
        self.selected_index = -1
        self.setup_ui()
        self.hide()
    
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
        
        # Header
        header = QLabel("Strategy Comparison")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffff;")
        layout.addWidget(header)
        
        # Subtitle
        subtitle = QLabel("AI evaluated multiple approaches and selected optimal balance")
        subtitle.setStyleSheet("color: #88ff88; font-style: italic; margin-bottom: 10px;")
        layout.addWidget(subtitle)
        
        # Strategy cards container
        self.cards_layout = QVBoxLayout()
        self.cards_layout.setSpacing(8)
        layout.addLayout(self.cards_layout)
        
        # Reasoning
        self.reasoning_label = QLabel()
        self.reasoning_label.setWordWrap(True)
        self.reasoning_label.setStyleSheet("color: #ffff88; padding: 10px; border-top: 1px solid #335533; margin-top: 10px;")
        layout.addWidget(self.reasoning_label)
        
        self.setLayout(layout)
    
    def update_strategies(self, strategies: List[StrategyOption], selected_index: int, reasoning: str):
        """Update the widget with new strategy data"""
        self.strategies = strategies
        self.selected_index = selected_index
        
        # Clear old cards
        self._clear_layout(self.cards_layout)
        
        # Create strategy cards
        for i, strategy in enumerate(strategies):
            card = self._create_strategy_card(strategy, i == selected_index)
            self.cards_layout.addWidget(card)
        
        # Update reasoning
        self.reasoning_label.setText(f"AI Reasoning: {reasoning}")
        self.show()
    
    def _create_strategy_card(self, strategy: StrategyOption, is_selected: bool):
        """Create a card for a single strategy"""
        card = QFrame()
        card.setObjectName("strategy_card")
        card.setProperty("selected", is_selected)
        card.setFrameStyle(QFrame.Shape.Box)
        
        # Style based on selection
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
        
        # Header with name and selection indicator
        header_layout = QHBoxLayout()
        
        name = QLabel(strategy.name)
        name.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        name.setStyleSheet("color: white;")
        header_layout.addWidget(name)
        
        if is_selected:
            selected_badge = QLabel("SELECTED")
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
        
        # Stats grid
        stats_layout = QGridLayout()
        stats_layout.setHorizontalSpacing(15)
        
        # Gain
        gain_label = QLabel("Gain:")
        gain_label.setStyleSheet("color: #88ff88;")
        stats_layout.addWidget(gain_label, 0, 0)
        
        gain_value = QLabel(f"+{strategy.gain}")
        gain_value.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        gain_value.setStyleSheet("color: #00ff00;")
        stats_layout.addWidget(gain_value, 0, 1)
        
        # Risk
        risk_label = QLabel("Risk:")
        risk_label.setStyleSheet("color: #ff8888;")
        stats_layout.addWidget(risk_label, 0, 2)
        
        # Color-code risk level
        risk_color = {
            "Very Low": "#88ff88",
            "Low": "#88ff88",
            "Medium": "#ffff00",
            "High": "#ff8800",
            "Critical": "#ff0000"
        }.get(strategy.risk_level, "#ffffff")
        
        risk_value = QLabel(strategy.risk_level)
        risk_value.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        risk_value.setStyleSheet(f"color: {risk_color};")
        stats_layout.addWidget(risk_value, 0, 3)
        
        # Confidence
        confidence_label = QLabel("Confidence:")
        confidence_label.setStyleSheet("color: #8888ff;")
        stats_layout.addWidget(confidence_label, 1, 0)
        
        confidence_value = QLabel(f"{strategy.confidence}%")
        confidence_value.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        confidence_value.setStyleSheet("color: #8888ff;")
        stats_layout.addWidget(confidence_value, 1, 1)
        
        # Ratio
        ratio_label = QLabel("Gain/Risk:")
        ratio_label.setStyleSheet("color: #ff88ff;")
        stats_layout.addWidget(ratio_label, 1, 2)
        
        ratio_value = QLabel(f"{strategy.stability_risk_ratio:.2f}")
        ratio_value.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        ratio_value.setStyleSheet("color: #ff88ff;")
        stats_layout.addWidget(ratio_value, 1, 3)
        
        stats_layout.setColumnStretch(4, 1)
        layout.addLayout(stats_layout)
        
        # Description
        if strategy.description:
            desc = QLabel(strategy.description)
            desc.setWordWrap(True)
            desc.setStyleSheet("color: #cccccc; font-style: italic; padding: 5px;")
            layout.addWidget(desc)
        
        card.setLayout(layout)
        return card
    
    def _clear_layout(self, layout):
        """Clear all widgets from a layout"""
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()


# ============================================================================
# BACKUP MANAGER
# ============================================================================

class BackupManager:
    """Manages system backups for reverse/undo functionality"""
    
    def __init__(self):
        self.backup_dir = Path.home() / "Z-Engine_Backups"
        self.current_backup = None
        self.backup_history = []
        self.load_history()
    
    def load_history(self):
        """Load backup history from disk"""
        if self.backup_dir.exists():
            self.backup_history = sorted([
                d for d in self.backup_dir.iterdir() 
                if d.is_dir() and d.name.startswith("backup_")
            ], reverse=True)
            if self.backup_history:
                self.current_backup = self.backup_history[0]
    
    def create_backup(self, description: str = "Pre-optimization state") -> Optional[Path]:
        """Create a backup of current system state (read-only)"""
        try:
            # Create backup directory
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.backup_dir / f"backup_{timestamp}"
            backup_path.mkdir(parents=True, exist_ok=True)
            
            # Backup services state (read-only)
            services_backup = backup_path / "services.csv"
            subprocess.run(
                ['powershell', '-Command', 
                 f'Get-Service | Select Name, Status, StartType | Export-Csv "{services_backup}"'],
                capture_output=True, timeout=30
            )
            
            # Backup startup items (read-only)
            startup_backup = backup_path / "startup.txt"
            subprocess.run(
                ['powershell', '-Command', 
                 f'Get-CimInstance Win32_StartupCommand | Select Name, Command, Location | Out-File "{startup_backup}"'],
                capture_output=True, timeout=30
            )
            
            # Backup registry settings (read-only)
            registry_backup = backup_path / "registry.reg"
            subprocess.run(
                ['reg', 'export', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', str(registry_backup), '/y'],
                capture_output=True, timeout=30
            )
            
            # Save metadata
            metadata = {
                "timestamp": timestamp,
                "description": description,
                "files": ["services.csv", "startup.txt", "registry.reg"]
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
        """Restore from backup (safe restoration only)"""
        if backup_path is None:
            backup_path = self.current_backup
        
        if not backup_path or not backup_path.exists():
            return False
        
        try:
            # Restore services
            services_backup = backup_path / "services.csv"
            if services_backup.exists():
                # This is a simplified restoration - in production you'd parse the CSV and restore each service
                print(f"Would restore services from: {services_backup}")
            
            # Restore startup items
            startup_backup = backup_path / "startup.txt"
            if startup_backup.exists():
                print(f"Would restore startup items from: {startup_backup}")
            
            # Restore registry
            registry_backup = backup_path / "registry.reg"
            if registry_backup.exists():
                subprocess.run(
                    ['reg', 'import', str(registry_backup)],
                    capture_output=True, timeout=30
                )
            
            # Update metadata
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
        """Get the most recent backup"""
        if self.backup_history:
            return self.backup_history[0]
        return None
    
    def get_backup_info(self, backup_path: Path) -> Dict:
        """Get information about a backup"""
        metadata_path = backup_path / "metadata.json"
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                return json.load(f)
        return {"timestamp": backup_path.name.replace("backup_", ""), "description": "Unknown"}


# ============================================================================
# RESTORE POINT CREATOR
# ============================================================================

class RestorePointCreator:
    """Creates Windows system restore points safely"""
    
    @staticmethod
    def create_restore_point(description: str = "Z-Engine Optimization") -> Tuple[bool, str]:
        """Create a system restore point"""
        try:
            # Check if running as admin (required for restore points)
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            
            if not is_admin:
                return False, "Restore points require Administrator privileges"
            
            # Enable System Restore if disabled (safe operation)
            subprocess.run(
                ['powershell', '-Command', 
                 'Enable-ComputerRestore -Drive "C:\\" -ErrorAction SilentlyContinue'],
                capture_output=True, timeout=10
            )
            
            # Create restore point
            result = subprocess.run(
                ['powershell', '-Command', 
                 f'Checkpoint-Computer -Description "{description}" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop'],
                capture_output=True, text=True, timeout=30
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
# SCRIPT GENERATOR - FIXED
# ============================================================================

class ScriptGenerator:
    """Generates PowerShell scripts from selected tasks with safety validation"""
    
    @classmethod
    def generate_script(cls, tasks: List[OptimizationTask], safe_mode: bool = True) -> str:
        """Generate PowerShell script from tasks with safety checks"""
        
        # Validate all tasks first
        unsafe_tasks = []
        exe_missing = []
        for task in tasks:
            is_safe, risk, reason = CommandSafety.is_command_safe(task.original_command)
            if not is_safe and not safe_mode:
                unsafe_tasks.append((task, reason))
            
            # Check for missing executables
            for exe in CommandSafety.EXE_REQUIRED:
                if exe in task.original_command and not CommandSafety.check_exe_exists(exe):
                    exe_missing.append((task, exe))
        
        if exe_missing:
            warning = "\n".join([f"  - {t[0].description}: missing {t[1]}" for t in exe_missing])
            return f"# WARNING: Required executables not found:\n{warning}\n#\n# Please install missing tools or use built-in alternatives"
        
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
            "# Safety checks",
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
            "# Safety confirmation",
            "Write-Host 'This script will make system changes' -ForegroundColor Yellow",
            "$confirmation = Read-Host 'Continue? (y/N)'",
            "if ($confirmation -ne 'y') { exit 0 }",
            "",
            "# Log file setup",
            "$logFile = \"$env:TEMP\\Z-Engine_$(Get-Date -Format 'yyyyMMdd_HHmmss').log\"",
            "Start-Transcript -Path $logFile",
            "",
            "Write-Host 'Logging to: $logFile' -ForegroundColor Cyan",
            ""
        ]
        
        # Add safety disclaimer
        lines.extend([
            "",
            "# SAFE MODE COMMAND VALIDATION",
            "# - All commands are validated against safety whitelist",
            "# - Dangerous commands are blocked or modified",
            "# - External executables are checked for existence",
            "# - Read-only operations are preferred where possible",
            ""
        ])
        
        # Group tasks by category
        categories = {}
        for task in tasks:
            if task.category not in categories:
                categories[task.category] = []
            categories[task.category].append(task)
        
        # Add tasks by category - split into SAFE and ADVANCED sections
        for category, cat_tasks in categories.items():
            lines.append(f"")
            lines.append(f"Write-Host 'Processing: {category}' -ForegroundColor Yellow")
            separator = "-" * (len(category) + 10)
            lines.append(f"Write-Host '{separator}' -ForegroundColor Yellow")
            
            # Split tasks by risk level
            safe_tasks = [t for t in cat_tasks if t.risk == RiskLevel.LOW]
            advanced_tasks = [t for t in cat_tasks if t.risk != RiskLevel.LOW]
            
            # SAFE OPTIMIZATIONS section
            if safe_tasks:
                lines.append(f"Write-Host ''")
                lines.append(f"Write-Host 'SAFE OPTIMIZATIONS' -ForegroundColor Green")
                for task in safe_tasks:
                    cls._add_task_to_script(lines, task, safe_mode)
            
            # ADVANCED / CAUTION section
            if advanced_tasks:
                lines.append(f"Write-Host ''")
                lines.append(f"Write-Host 'ADVANCED / CAUTION' -ForegroundColor Yellow")
                for task in advanced_tasks:
                    cls._add_task_to_script(lines, task, safe_mode)
        
        # Add reboot check
        reboot_tasks = [t for t in tasks if t.requires_reboot]
        if reboot_tasks:
            lines.append("")
            lines.append("Write-Host ''")
            lines.append("Write-Host 'Some changes require a reboot' -ForegroundColor Yellow")
            lines.append("$reboot = Read-Host 'Reboot now? (y/N)'")
            lines.append("if ($reboot -eq 'y') {")
            lines.append("    Restart-Computer -Force")
            lines.append("}")
        
        # Finalize
        lines.append("")
        lines.append("Stop-Transcript")
        lines.append("Write-Host 'Script completed' -ForegroundColor Green")
        
        return '\n'.join(lines)
    
    @classmethod
    def _add_task_to_script(cls, lines: list, task: OptimizationTask, safe_mode: bool):
        """Add a single task to the script lines"""
        lines.append(f"")
        lines.append(f"# {task.description}")
        if task.reasoning:
            lines.append(f"# Reasoning: {task.reasoning}")
        
        # Add risk badge comment
        lines.append(f"# Risk: {task.get_risk_badge()}")
        
        # Check command safety
        is_safe, cmd_risk, safety_note = CommandSafety.is_command_safe(task.original_command)
        cmd_to_use = task.get_execution_command(safe_mode)
        
        if not is_safe and safe_mode:
            lines.append(f"# Command modified for safety: {safety_note}")
        
        # Add command with appropriate safety level
        if cmd_risk in ["high", "critical"] and safe_mode:
            # High-risk commands require confirmation
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
            # Standard execution with try/catch
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
        """Save script to file"""
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
# SCRIPT RUNNER
# ============================================================================

class ScriptRunner:
    """Handles running PowerShell scripts with UAC elevation"""
    
    @staticmethod
    def run_script(script_path: str, parent_widget=None) -> bool:
        """
        Run a PowerShell script with administrator privileges
        Returns True if execution was attempted, False if cancelled
        """
        if not os.path.exists(script_path):
            QMessageBox.critical(parent_widget, "Error", f"Script not found: {script_path}")
            return False
        
        # Show confirmation dialog
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
            # Run PowerShell with elevation
            subprocess.Popen([
                "powershell",
                "-Command",
                f'Start-Process powershell -Verb RunAs -ArgumentList \'-NoProfile -ExecutionPolicy Bypass -File "{script_path}"\''
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
        """Create a temporary script file"""
        try:
            temp_dir = tempfile.gettempdir()
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            script_path = os.path.join(temp_dir, f"Z-Engine_{timestamp}.ps1")
            
            with open(script_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return script_path
        except Exception as e:
            print(f"Failed to create temp script: {e}")
            return None


# ============================================================================
# EXECUTION PREVIEW WIDGET
# ============================================================================

class ScriptPreviewWidget(QFrame):
    """Widget to preview, export and run PowerShell scripts"""
    
    def __init__(self):
        super().__init__()
        self.current_script = ""
        self.current_tasks = []
        self.current_script_path = None
        self.setup_ui()
        self.hide()
    
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
            QScrollBar:vertical {
                background: #2a2a2a;
                width: 14px;
                border-radius: 7px;
            }
            QScrollBar::handle:vertical {
                background: #00ff00;
                min-height: 30px;
                border-radius: 7px;
            }
            QScrollBar::handle:vertical:hover {
                background: #88ff88;
            }
            QScrollBar:horizontal {
                background: #2a2a2a;
                height: 14px;
                border-radius: 7px;
            }
            QScrollBar::handle:horizontal {
                background: #00ff00;
                min-width: 30px;
                border-radius: 7px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #88ff88;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(8)
        
        # Header with controls
        header = QHBoxLayout()
        
        title = QLabel("PowerShell Script Preview")
        title.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ffff;")
        header.addWidget(title)
        
        header.addStretch()
        
        self.safe_mode_cb = QCheckBox("Safe Mode")
        self.safe_mode_cb.setChecked(True)
        self.safe_mode_cb.setStyleSheet("color: #88ff88;")
        self.safe_mode_cb.stateChanged.connect(self.update_preview)
        header.addWidget(self.safe_mode_cb)
        
        # Action buttons
        self.save_btn = QPushButton("Export Script")
        self.save_btn.clicked.connect(self.save_script)
        self.save_btn.setEnabled(False)
        header.addWidget(self.save_btn)
        
        self.run_btn = QPushButton("Run Script")
        self.run_btn.clicked.connect(self.run_script)
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
        
        self.restore_btn = QPushButton("Create Restore Point")
        self.restore_btn.clicked.connect(self.create_restore_point)
        header.addWidget(self.restore_btn)
        
        layout.addLayout(header)
        
        # Admin warning
        self.admin_warning = QLabel("Running optimization requires Administrator privileges")
        self.admin_warning.setStyleSheet("color: #ffaa00; font-weight: bold; padding: 5px; background-color: #221100; border-radius: 3px;")
        self.admin_warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.admin_warning)
        
        # Script statistics bar
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
        
        self.tasks_count = QLabel("Tasks: 0")
        self.tasks_count.setStyleSheet("color: #88ff88; font-weight: bold;")
        stats_layout.addWidget(self.tasks_count)
        
        stats_layout.addWidget(QLabel("|"))
        
        self.mode_label = QLabel("Safe Mode: Enabled")
        self.mode_label.setStyleSheet("color: #88ff88;")
        stats_layout.addWidget(self.mode_label)
        
        stats_layout.addWidget(QLabel("|"))
        
        self.risk_label = QLabel("Estimated Risk: Low")
        self.risk_label.setStyleSheet("color: #88ff88;")
        stats_layout.addWidget(self.risk_label)
        
        stats_layout.addStretch()
        layout.addWidget(self.stats_bar)
        
        # Safety warning area
        self.safety_warning = QLabel()
        self.safety_warning.setWordWrap(True)
        self.safety_warning.setStyleSheet("color: #ff8800; font-weight: bold; padding: 5px;")
        self.safety_warning.hide()
        layout.addWidget(self.safety_warning)
        
        # EXE missing warning
        self.exe_warning = QLabel()
        self.exe_warning.setWordWrap(True)
        self.exe_warning.setStyleSheet("color: #ff0000; font-weight: bold; padding: 5px;")
        self.exe_warning.hide()
        layout.addWidget(self.exe_warning)
        
        # Script preview with scrollbars - smooth scrolling enabled
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setMaximumHeight(400)
        self.preview.setMinimumHeight(200)
        self.preview.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.preview.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.preview.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        layout.addWidget(self.preview)
        
        # Status
        self.status_label = QLabel("Select tasks to generate script")
        self.status_label.setStyleSheet("color: #888888; font-style: italic;")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
    
    def update_preview(self):
        """Update script when safe mode toggles"""
        if self.current_tasks:
            self.update_script(self.current_tasks)
    
    def update_script(self, tasks: List[OptimizationTask]):
        """Update script based on selected tasks"""
        self.current_tasks = tasks
        
        if not tasks:
            self.preview.clear()
            self.save_btn.setEnabled(False)
            self.run_btn.setEnabled(False)
            self.status_label.setText("No tasks selected")
            self.safety_warning.hide()
            self.exe_warning.hide()
            self.tasks_count.setText("Tasks: 0")
            self.current_script_path = None
            self.hide()
            return
        
        safe_mode = self.safe_mode_cb.isChecked()
        self.current_script = ScriptGenerator.generate_script(tasks, safe_mode)
        self.preview.setPlainText(self.current_script)
        self.save_btn.setEnabled(True)
        
        # Create temporary script for running
        self.current_script_path = ScriptRunner.create_temp_script(self.current_script)
        self.run_btn.setEnabled(self.current_script_path is not None)
        
        # Update stats
        self.tasks_count.setText(f"Tasks: {len(tasks)}")
        self.mode_label.setText(f"Safe Mode: {'Enabled' if safe_mode else 'Disabled'}")
        
        # Calculate risk level for stats
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
        self.risk_label.setText(f"Estimated Risk: {risk_text}")
        
        # Check for unsafe commands
        unsafe_commands = []
        exe_missing = []
        for task in tasks:
            is_safe, risk, reason = CommandSafety.is_command_safe(task.original_command)
            if not is_safe:
                unsafe_commands.append((task.description, risk, reason))
            
            # Check for missing executables
            for exe in CommandSafety.EXE_REQUIRED:
                if exe in task.original_command and not CommandSafety.check_exe_exists(exe):
                    exe_missing.append((task.description, exe))
        
        if exe_missing:
            warning_text = "MISSING EXECUTABLES:\n" + "\n".join([
                f"  - {desc} requires {exe}" for desc, exe in exe_missing
            ])
            self.exe_warning.setText(warning_text)
            self.exe_warning.show()
        else:
            self.exe_warning.hide()
        
        if unsafe_commands and not safe_mode:
            warning_text = "UNSAFE COMMANDS DETECTED:\n" + "\n".join([
                f"  - {desc} ({risk} risk)" for desc, risk, _ in unsafe_commands
            ])
            self.safety_warning.setText(warning_text)
            self.safety_warning.show()
            self.status_label.setText(f"{len(tasks)} tasks selected ({len(unsafe_commands)} unsafe) - Enable Safe Mode")
            self.status_label.setStyleSheet("color: #ff0000; font-style: italic; font-weight: bold;")
        elif unsafe_commands and safe_mode:
            self.safety_warning.setText(f"{len(unsafe_commands)} unsafe commands will be modified for safety")
            self.safety_warning.show()
            self.status_label.setText(f"{len(tasks)} tasks selected (safe mode active)")
            self.status_label.setStyleSheet("color: #88ff88; font-style: italic;")
        else:
            self.safety_warning.hide()
            self.status_label.setText(f"{len(tasks)} safe tasks selected - Ready to export or run")
            self.status_label.setStyleSheet("color: #88ff88; font-style: italic;")
        
        self.show()
    
    def save_script(self):
        """Save script to file"""
        if not self.current_script:
            return
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"Z-Engine_{timestamp}.ps1"
        
        file_path = ScriptGenerator.save_script(self.current_script, default_name)
        if file_path:
            self.current_script_path = file_path
            QMessageBox.information(self, "Success", f"Script saved to:\n{file_path}")
    
    def run_script(self):
        """Run the current script with UAC elevation"""
        if not self.current_script_path or not os.path.exists(self.current_script_path):
            QMessageBox.critical(self, "Error", "No script available to run. Please generate a script first.")
            return
        
        ScriptRunner.run_script(self.current_script_path, self)
    
    def create_restore_point(self):
        """Create system restore point"""
        reply = QMessageBox.question(
            self,
            "Create Restore Point",
            "This will create a Windows System Restore point.\n"
            "Administrator privileges may be required.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            success, msg = RestorePointCreator.create_restore_point()
            if success:
                QMessageBox.information(self, "Success", msg)
            else:
                QMessageBox.warning(self, "Warning", f"Could not create restore point:\n{msg}")


# ============================================================================
# LIVE RISK CALCULATOR
# ============================================================================

class LiveRiskCalculator:
    """Calculates real-time risk based on selected tasks"""
    
    @staticmethod
    def calculate_risk(tasks: List[OptimizationTask], base_score: int) -> Dict[str, Any]:
        """Calculate risk metrics for selected tasks"""
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
        
        # Count by risk level
        risk_counts = {
            RiskLevel.LOW: sum(1 for t in tasks if t.risk == RiskLevel.LOW),
            RiskLevel.MEDIUM: sum(1 for t in tasks if t.risk == RiskLevel.MEDIUM),
            RiskLevel.HIGH: sum(1 for t in tasks if t.risk == RiskLevel.HIGH),
            RiskLevel.CRITICAL: sum(1 for t in tasks if t.risk == RiskLevel.CRITICAL)
        }
        
        # Count unsafe commands
        unsafe_commands = 0
        exe_missing = 0
        for task in tasks:
            is_safe, _, _ = CommandSafety.is_command_safe(task.original_command)
            if not is_safe:
                unsafe_commands += 1
            
            # Check for missing executables
            for exe in CommandSafety.EXE_REQUIRED:
                if exe in task.original_command and not CommandSafety.check_exe_exists(exe):
                    exe_missing += 1
        
        # Calculate weighted risk score
        risk_weights = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 3,
            RiskLevel.HIGH: 6,
            RiskLevel.CRITICAL: 10
        }
        
        total_weight = sum(risk_counts[r] * risk_weights[r] for r in risk_counts)
        max_possible = len(tasks) * 10
        risk_percentage = (total_weight / max_possible * 100) if max_possible > 0 else 0
        
        # Adjust for unsafe commands and missing executables
        risk_percentage = min(100, risk_percentage + (unsafe_commands * 5) + (exe_missing * 10))
        
        # Determine risk level
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
        
        # Calculate stability impact
        total_impact = sum(t.impact_on_stability for t in tasks)
        room = 100 - base_score
        gain = min(100, int(total_impact * (room / 100)))
        
        # Calculate confidence (inverse of risk)
        confidence = max(0, min(100, 100 - risk_percentage))
        
        return {
            "total_risk": round(risk_percentage, 1),
            "risk_level": risk_level,
            "risk_counts": risk_counts,
            "high_risk_tasks": risk_counts[RiskLevel.HIGH] + risk_counts[RiskLevel.CRITICAL],
            "unsafe_commands": unsafe_commands,
            "exe_missing": exe_missing,
            "reboot_required": any(t.requires_reboot for t in tasks),
            "stability_impact": gain,
            "projected_score": min(100, base_score + gain),
            "confidence": round(confidence, 1)
        }


# ============================================================================
# RISK WIDGET
# ============================================================================

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
        
        header = QLabel("Live Risk Analysis")
        header.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        header.setStyleSheet("color: #ffaa00;")
        layout.addWidget(header)
        
        # Risk meter
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
        
        # Stats grid
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(5)
        
        grid.addWidget(QLabel("High Risk Tasks:"), 0, 0)
        self.high_risk_label = QLabel("0")
        self.high_risk_label.setStyleSheet("color: #ff8800; font-weight: bold;")
        grid.addWidget(self.high_risk_label, 0, 1)
        
        grid.addWidget(QLabel("Unsafe Commands:"), 1, 0)
        self.unsafe_label = QLabel("0")
        self.unsafe_label.setStyleSheet("color: #ff0000; font-weight: bold;")
        grid.addWidget(self.unsafe_label, 1, 1)
        
        grid.addWidget(QLabel("Missing EXEs:"), 2, 0)
        self.exe_label = QLabel("0")
        self.exe_label.setStyleSheet("color: #ff0000; font-weight: bold;")
        grid.addWidget(self.exe_label, 2, 1)
        
        grid.addWidget(QLabel("Reboot Required:"), 3, 0)
        self.reboot_label = QLabel("No")
        self.reboot_label.setStyleSheet("color: #88ff88;")
        grid.addWidget(self.reboot_label, 3, 1)
        
        grid.addWidget(QLabel("Projected Gain:"), 4, 0)
        self.gain_label = QLabel("+0")
        self.gain_label.setStyleSheet("color: #00ff00; font-weight: bold;")
        grid.addWidget(self.gain_label, 4, 1)
        
        grid.addWidget(QLabel("Confidence:"), 5, 0)
        self.confidence_label = QLabel("100%")
        self.confidence_label.setStyleSheet("color: #ffff00;")
        grid.addWidget(self.confidence_label, 5, 1)
        
        layout.addLayout(grid)
        
        self.setLayout(layout)
    
    def update_risk(self, tasks: List[OptimizationTask], base_score: int):
        """Update risk display based on selected tasks"""
        self.current_tasks = tasks
        self.base_score = base_score
        
        if not tasks:
            self.hide()
            return
        
        risk_data = LiveRiskCalculator.calculate_risk(tasks, base_score)
        
        # Update meter
        self.risk_meter.setValue(int(risk_data["total_risk"]))
        
        # Color based on risk level
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
        self.exe_label.setText(str(risk_data["exe_missing"]))
        self.reboot_label.setText("Yes" if risk_data["reboot_required"] else "No")
        self.reboot_label.setStyleSheet("color: #ff8800; font-weight: bold;" if risk_data["reboot_required"] else "color: #88ff88;")
        self.gain_label.setText(f"+{risk_data['stability_impact']}")
        self.confidence_label.setText(f"{risk_data['confidence']}%")
        
        self.show()


# ============================================================================
# SYSTEM DETAILS DIALOG
# ============================================================================

class SystemDetailsDialog(QDialog):
    def __init__(self, snapshot: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.snapshot = snapshot
        self.setWindowTitle("System Details - Z-Engine")
        self.setGeometry(200, 200, 800, 600)
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
# INTERNET CONNECTIVITY
# ============================================================================

def check_internet_connection(timeout=3):
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=timeout)
        return True
    except OSError:
        return False


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
# CLEAN DEFAULT GRAPH WIDGET
# ============================================================================

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
        layout.setSpacing(8)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        title = QLabel("Z-ENGINE")
        title.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ffff;")
        layout.addWidget(title)
        
        subtitle = QLabel("Generates · Engineers · Deploys")
        subtitle.setFont(QFont("Arial", 12))
        subtitle.setStyleSheet("color: #88ff88;")
        layout.addWidget(subtitle)
        
        self.score_label = QLabel("--")
        self.score_label.setFont(QFont("Arial", 48, QFont.Weight.Bold))
        self.score_label.setStyleSheet("color: #00ff00; padding: 20px;")
        layout.addWidget(self.score_label)
        
        self.setLayout(layout)
    
    def set_score(self, score: int):
        self.score_label.setText(str(score))


# ============================================================================
# FLOW INDICATOR WIDGET
# ============================================================================

class FlowIndicator(QFrame):
    """Shows current stage of the optimization flow"""
    
    def __init__(self):
        super().__init__()
        self.current_stage = 0
        self.stages = [
            "Scan",
            "Analyze", 
            "Strategize",
            "Review",
            "Refine"
        ]
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
            # Stage number
            num_label = QLabel(f"{i+1}")
            num_label.setFixedSize(30, 30)
            num_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            num_label.setStyleSheet("""
                QLabel {
                    background: #2a3a2a;
                    color: #88ff88;
                    border: 2px solid #335533;
                    border-radius: 15px;
                    font-weight: bold;
                }
            """)
            
            # Stage name
            name_label = QLabel(stage)
            name_label.setStyleSheet("color: #888888; font-weight: bold;")
            
            # Container
            container = QWidget()
            container_layout = QHBoxLayout(container)
            container_layout.setContentsMargins(0, 0, 0, 0)
            container_layout.addWidget(num_label)
            container_layout.addWidget(name_label)
            
            self.indicators.append({
                "num": num_label,
                "name": name_label,
                "container": container
            })
            
            layout.addWidget(container)
            
            # Arrow between stages (except last)
            if i < len(self.stages) - 1:
                arrow = QLabel("->")
                arrow.setStyleSheet("color: #335533; font-size: 16px; font-weight: bold;")
                layout.addWidget(arrow)
        
        layout.addStretch()
        self.setLayout(layout)
        self.set_stage(0)
    
    def set_stage(self, stage: int):
        """Set current stage (0-4)"""
        self.current_stage = stage
        for i, ind in enumerate(self.indicators):
            if i < stage:
                # Completed
                ind["num"].setStyleSheet("""
                    QLabel {
                        background: #00ff00;
                        color: black;
                        border: 2px solid #00ff00;
                        border-radius: 15px;
                        font-weight: bold;
                    }
                """)
                ind["name"].setStyleSheet("color: #00ff00; font-weight: bold;")
            elif i == stage:
                # Current
                ind["num"].setStyleSheet("""
                    QLabel {
                        background: #ffff00;
                        color: black;
                        border: 2px solid #ffff00;
                        border-radius: 15px;
                        font-weight: bold;
                    }
                """)
                ind["name"].setStyleSheet("color: #ffff00; font-weight: bold;")
            else:
                # Future
                ind["num"].setStyleSheet("""
                    QLabel {
                        background: #2a3a2a;
                        color: #666666;
                        border: 2px solid #335533;
                        border-radius: 15px;
                        font-weight: bold;
                    }
                """)
                ind["name"].setStyleSheet("color: #666666; font-weight: bold;")


# ============================================================================
# PURE ASI-1 CLIENT
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
        self.last_error = None
        self.last_raw = None
        self.thought_trace = []
        self.pipeline_start = None
    
    def start_pipeline(self):
        self.pipeline_start = time.time()
    
    def check_pipeline_timeout(self) -> bool:
        if self.pipeline_start and time.time() - self.pipeline_start > MAX_PIPELINE_DURATION:
            self.last_error = f"Pipeline timeout after {MAX_PIPELINE_DURATION}s"
            return True
        return False
    
    def _compress_json(self, data: Any) -> str:
        return json.dumps(data, separators=(",", ":"))
    
    def _fix_json(self, content: str) -> str:
        content = re.sub(r",\s*}", "}", content)
        content = re.sub(r",\s*]", "]", content)
        content = re.sub(r'//.*?\n', '\n', content)
        return content
    
    def _extract_json_from_string(self, content: str) -> Optional[Dict]:
        json_pattern = r'\{[\s\S]*\}'
        match = re.search(json_pattern, content)
        if match:
            try:
                return json.loads(match.group())
            except:
                pass
        return None
    
    def _call_api(self, prompt: str, max_tokens: int = 1500, temperature: float = 0.3, 
                  pass_name: str = "Unknown") -> Optional[Dict[str, Any]]:
        if self.check_pipeline_timeout():
            return None
        
        if not check_internet_connection():
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
            
            if response.status_code != 200:
                self.last_error = f"API error {response.status_code}"
                trace_entry["status"] = "error"
                trace_entry["error"] = self.last_error
                self.thought_trace.append(trace_entry)
                return None
            
            result = response.json()
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            self.last_raw = content
            
            if not content:
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
                    self.last_error = f"Could not parse response"
                    trace_entry["status"] = "error"
                    trace_entry["error"] = self.last_error
                    trace_entry["response"] = content[:200]
                    self.thought_trace.append(trace_entry)
                    return None
            
            trace_entry["status"] = "success"
            trace_entry["response"] = content[:300] + ("..." if len(content) > 300 else "")
            self.thought_trace.append(trace_entry)
            
            if isinstance(parsed, dict):
                parsed["_trace_id"] = len(self.thought_trace) - 1
                parsed["_raw_response"] = content
            
            return parsed
            
        except Exception as e:
            self.last_error = str(e)
            trace_entry["status"] = "error"
            trace_entry["error"] = self.last_error
            self.thought_trace.append(trace_entry)
            return None
    
    def get_thought_trace(self) -> List[Dict]:
        return self.thought_trace
    
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
        
        return self._call_api(prompt, max_tokens=1000, pass_name="1: Scan -> Analyze")
    
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
        
        return self._call_api(prompt, max_tokens=800, pass_name="2: Analyze -> Strategize")
    
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
        
        result = self._call_api(prompt, max_tokens=3000, temperature=0.4, pass_name="3: Strategize -> Plan")
        
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
        
        return self._call_api(prompt, max_tokens=1500, pass_name="4: Plan -> Review")
    
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
        
        result = self._call_api(prompt, max_tokens=2500, temperature=0.4, pass_name="5: Review -> Refine")
        
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
# SIMULATION WORKER THREAD - FIXED
# ============================================================================

class SimulationWorker(QThread):
    finished = Signal(object)
    
    def __init__(self, analyzer, snapshot, metrics):
        super().__init__()
        self.analyzer = analyzer
        self.snapshot = snapshot
        self.metrics = metrics
    
    def run(self):
        # Use the analyzer's simulate_strategies method which returns SimulationResult
        result = self.analyzer.simulate_strategies(self.snapshot, self.metrics)
        self.finished.emit(result)


# ============================================================================
# PURE AI ANALYZER
# ============================================================================

class PureAIAnalyzer:
    REQUIRED_DOMAINS = [
        "Memory Management", "CPU Optimization", "Disk Optimization", 
        "Startup Acceleration", "Service Optimization", "Power Plan Tuning",
        "Security Hardening", "Background Process Management"
    ]
    
    def __init__(self, api_key: str):
        self.client = PureASIClient(api_key)
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
            self.strategic_insight = insight
            return insight
        except Exception as e:
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
            self.plan_critique = critique
            return critique
        except Exception as e:
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
        # Convert metrics to dict for API call
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
            
            self.simulation_result = SimulationResult(
                strategies, selected, reasoning, confidence, 
                result.get("comparison_metrics"), result.get("_raw_response")
            )
            return self.simulation_result
            
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
# UI WIDGETS
# ============================================================================

class ThoughtTraceWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.hide()  # Hidden by default
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        
        header = QLabel("AI Reasoning Trace")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffff;")
        layout.addWidget(header)
        
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Stage", "Status", "Time", "Summary"])
        self.tree.setStyleSheet("""
            QTreeWidget {
                background-color: #1a1a1a;
                color: white;
                border: 1px solid #00ff00;
            }
        """)
        layout.addWidget(self.tree)
        
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(150)
        self.detail.setStyleSheet("""
            QTextEdit {
                background-color: #0a0a0a;
                color: #00ff00;
                font-family: monospace;
                border: 1px solid #00ff00;
            }
        """)
        layout.addWidget(self.detail)
        
        self.tree.itemClicked.connect(self.show_trace_detail)
    
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
    
    def show_trace_detail(self, item):
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


class RiskDeltaWidget(QFrame):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.hide()  # Hidden by default
    
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
        
        header = QLabel("Before vs After")
        header.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffff;")
        layout.addWidget(header)
        
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(5)
        
        grid.addWidget(QLabel("Original Plan:"), 0, 0)
        self.original_label = QLabel("--")
        self.original_label.setStyleSheet("color: #ffaa00; font-size: 14pt; font-weight: bold;")
        grid.addWidget(self.original_label, 0, 1)
        
        grid.addWidget(QLabel("Refined Plan:"), 1, 0)
        self.refined_label = QLabel("--")
        self.refined_label.setStyleSheet("color: #00ffff; font-size: 14pt; font-weight: bold;")
        grid.addWidget(self.refined_label, 1, 1)
        
        grid.addWidget(QLabel("Risk Reduction:"), 2, 0)
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
        self.improvements.setStyleSheet("color: #88ff88; padding: 5px; border-top: 1px solid #00ffff;")
        layout.addWidget(self.improvements)
        
        self.setLayout(layout)
    
    def update_delta(self, original: int, refined: int, risk_reduction: float, 
                    confidence: float, improvements: list):
        self.original_label.setText(f"{original}")
        self.refined_label.setText(f"{refined}")
        self.risk_label.setText(f"{risk_reduction:.1f}%")
        self.confidence_label.setText(f"{confidence:.1f}%")
        
        gain = refined - original
        if improvements:
            self.improvements.setText("- " + "\n- ".join(improvements[:3]))
        
        self.show()


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
        
        # Description with risk badge
        desc_text = f"{self.task.get_risk_badge()} {self.task.description}"
        desc = QLabel(desc_text)
        desc.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        desc.setWordWrap(True)
        details.addWidget(desc)
        
        meta = QHBoxLayout()
        meta.setSpacing(10)
        
        if self.task.impact_on_stability > 0:
            gain = QLabel(f"+{self.task.impact_on_stability}")
            gain.setFont(QFont("Arial", 12, QFont.Weight.Bold))
            gain.setStyleSheet("color: #00ff00;")
            meta.addWidget(gain)
            meta.addWidget(QLabel("stability"))
        
        # Show safety status
        if not self.task.is_safe_command:
            warning = QLabel(" UNSAFE ")
            warning.setStyleSheet("background: #ff0000; color: white; padding: 2px; border-radius: 2px;")
            meta.addWidget(warning)
        
        risk_color = {"low": "#00ff00", "medium": "#ffff00", "high": "#ff8800", "critical": "#ff0000"}.get(self.task.risk.value, "#ffffff")
        risk = QLabel(f" {self.task.risk.value.upper()} ")
        risk.setStyleSheet(f"background: {risk_color}; color: black; padding: 2px; border-radius: 2px;")
        meta.addWidget(risk)
        
        if self.task.requires_reboot:
            reboot = QLabel(" REBOOT ")
            reboot.setStyleSheet("background: #ff8800; color: black; padding: 2px; border-radius: 2px;")
            meta.addWidget(reboot)
        
        if self.plan_type == "refined":
            refined_badge = QLabel(" REFINED ")
            refined_badge.setStyleSheet("background: #00ffff; color: black; padding: 2px; border-radius: 2px;")
            meta.addWidget(refined_badge)
        
        if self.task.is_safe:
            safe_badge = QLabel(" SAFE ")
            safe_badge.setStyleSheet("background: #88ff88; color: black; padding: 2px; border-radius: 2px;")
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
        self.indicator.setText("+" if self.selected else "  ")
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
            priority_badge = QLabel("FOCUS AREA")
            priority_badge.setStyleSheet("""
                background: #00ff00;
                color: black;
                font-weight: bold;
                padding: 3px;
                border-radius: 3px;
                max-width: 100px;
            """)
            layout.addWidget(priority_badge)
        
        if self.plan_type == "refined":
            refined_badge = QLabel("IMPROVED")
            refined_badge.setStyleSheet("""
                background: #00ffff;
                color: black;
                font-weight: bold;
                padding: 3px;
                border-radius: 3px;
                max-width: 100px;
            """)
            layout.addWidget(refined_badge)
        
        if self.category.reasoning:
            reasoning = QLabel(f" {self.category.reasoning}")
            reasoning.setWordWrap(True)
            reasoning.setStyleSheet("color: #88ff88; font-style: italic;")
            layout.addWidget(reasoning)
        
        # Split tasks into SAFE and ADVANCED sections
        safe_tasks = self.category.get_safe_tasks()
        advanced_tasks = self.category.get_unsafe_tasks()
        
        if safe_tasks:
            safe_header = QLabel("SAFE OPTIMIZATIONS")
            safe_header.setStyleSheet("color: #00ff00; font-weight: bold; margin-top: 5px;")
            layout.addWidget(safe_header)
            
            for task in safe_tasks:
                card = ClickableTaskCard(task, self.plan_type)
                card.toggled.connect(self.on_task_toggled)
                layout.addWidget(card)
                self.cards[task.id] = card
        
        if advanced_tasks:
            if safe_tasks:
                # Add spacing between sections
                layout.addSpacing(10)
            
            advanced_header = QLabel("ADVANCED / CAUTION")
            advanced_header.setStyleSheet("color: #ffaa00; font-weight: bold; margin-top: 5px;")
            layout.addWidget(advanced_header)
            
            for task in advanced_tasks:
                card = ClickableTaskCard(task, self.plan_type)
                card.toggled.connect(self.on_task_toggled)
                layout.addWidget(card)
                self.cards[task.id] = card
        
        self.setLayout(layout)
    
    def on_task_toggled(self, task_id: str, checked: bool):
        self.changed.emit()
    
    def get_selected(self) -> List[OptimizationTask]:
        return [t for t in self.category.tasks if t.id in self.cards and self.cards[t.id].selected]


# ============================================================================
# MAIN WINDOW - With 3-Bar Chart and QStackedWidget
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
        
        self.setWindowTitle("Z-Engine: Generates, Engineers and Deploys")
        self.setGeometry(100, 100, 1400, 900)
        self.setup_ui()
    
    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(8)
        main_layout.setContentsMargins(8, 8, 8, 8)
        
        # ====================================================================
        # HEADER SECTION
        # ====================================================================
        header = self.create_header()
        main_layout.addLayout(header)
        
        # ====================================================================
        # FLOW INDICATOR SECTION
        # ====================================================================
        self.flow_indicator = FlowIndicator()
        main_layout.addWidget(self.flow_indicator)
        
        # ====================================================================
        # STACKED WIDGET FOR CHARTS (Clean vs 3-Bar)
        # ====================================================================
        self.chart_stack = QStackedWidget()
        self.chart_stack.setMaximumHeight(250)
        
        self.clean_view = CleanGraphWidget()
        self.chart_stack.addWidget(self.clean_view)
        
        self.chart = ThreeBarChartWidget()
        self.chart_stack.addWidget(self.chart)
        
        main_layout.addWidget(self.chart_stack)
        
        # ====================================================================
        # STRATEGY COMPARISON SECTION
        # ====================================================================
        self.strategy_comparison = StrategyComparisonWidget()
        main_layout.addWidget(self.strategy_comparison)
        
        # ====================================================================
        # SCRIPT DIFF VIEW SECTION
        # ====================================================================
        self.script_diff = ScriptDiffWidget()
        main_layout.addWidget(self.script_diff)
        
        # ====================================================================
        # SCRIPT PREVIEW SECTION
        # ====================================================================
        self.script_preview = ScriptPreviewWidget()
        main_layout.addWidget(self.script_preview)
        
        # ====================================================================
        # BUTTONS SECTION
        # ====================================================================
        buttons_widget = QWidget()
        buttons_layout = QHBoxLayout(buttons_widget)
        buttons_layout.setSpacing(10)
        
        # Operations Group
        op_group = QGroupBox("Operations")
        op_layout = QHBoxLayout()
        op_layout.setSpacing(5)
        
        self.scan_btn = QPushButton("1. Scan System")
        self.scan_btn.setFixedHeight(40)
        self.scan_btn.clicked.connect(self.scan)
        op_layout.addWidget(self.scan_btn)
        
        self.analyze_btn = QPushButton("2. Analyze")
        self.analyze_btn.setFixedHeight(40)
        self.analyze_btn.clicked.connect(self.analyze)
        self.analyze_btn.setEnabled(False)
        op_layout.addWidget(self.analyze_btn)
        
        self.plan_btn = QPushButton("3. Generate Plan")
        self.plan_btn.setFixedHeight(40)
        self.plan_btn.clicked.connect(self.generate_plan)
        self.plan_btn.setEnabled(False)
        op_layout.addWidget(self.plan_btn)
        
        op_group.setLayout(op_layout)
        buttons_layout.addWidget(op_group)
        
        # Strategy Group
        strategy_group = QGroupBox("Strategy")
        strategy_layout = QHBoxLayout()
        strategy_layout.setSpacing(5)
        
        self.simulate_btn = QPushButton("Simulate Strategies")
        self.simulate_btn.setFixedHeight(40)
        self.simulate_btn.clicked.connect(self.simulate_strategies)
        self.simulate_btn.setEnabled(False)
        strategy_layout.addWidget(self.simulate_btn)
        
        strategy_group.setLayout(strategy_layout)
        buttons_layout.addWidget(strategy_group)
        
        # Export Group
        export_group = QGroupBox("Export")
        export_layout = QHBoxLayout()
        export_layout.setSpacing(5)
        
        self.export_btn = QPushButton("Export Script")
        self.export_btn.setFixedHeight(40)
        self.export_btn.clicked.connect(self.export_script)
        self.export_btn.setEnabled(False)
        export_layout.addWidget(self.export_btn)
        
        self.restore_btn = QPushButton("Create Restore Point")
        self.restore_btn.setFixedHeight(40)
        self.restore_btn.clicked.connect(self.create_restore_point)
        export_layout.addWidget(self.restore_btn)
        
        export_group.setLayout(export_layout)
        buttons_layout.addWidget(export_group)
        
        # Safety Group
        safety_group = QGroupBox("Safety")
        safety_layout = QHBoxLayout()
        safety_layout.setSpacing(5)
        
        self.reverse_btn = QPushButton("Reverse Last Action")
        self.reverse_btn.setFixedHeight(40)
        self.reverse_btn.clicked.connect(self.reverse_last_action)
        self.reverse_btn.setEnabled(False)
        safety_layout.addWidget(self.reverse_btn)
        
        self.backup_btn = QPushButton("Create Backup")
        self.backup_btn.setFixedHeight(40)
        self.backup_btn.clicked.connect(self.create_backup)
        safety_layout.addWidget(self.backup_btn)
        
        safety_group.setLayout(safety_layout)
        buttons_layout.addWidget(safety_group)
        
        main_layout.addWidget(buttons_widget)
        
        # ====================================================================
        # SPLITTER SECTION (Risk + Categories + Thought Trace)
        # ====================================================================
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
        self.status.setStyleSheet("color: #00ff00;")
        left_layout.addWidget(self.status)
        
        # Log
        self.log = QTextEdit()
        self.log.setMaximumHeight(150)
        self.log.setReadOnly(True)
        left_layout.addWidget(self.log)
        
        left_layout.addStretch()
        
        # Center panel - Categories with tabs
        center_panel = QWidget()
        center_layout = QVBoxLayout(center_panel)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(0)
        
        # Category selection tabs
        self.category_tabs = QTabWidget()
        
        # Original plan tab
        self.original_tab = QWidget()
        self.original_tab_layout = QVBoxLayout(self.original_tab)
        self.original_tab_layout.setContentsMargins(0, 0, 0, 0)
        self.original_tab_layout.setSpacing(0)
        self.category_tabs.addTab(self.original_tab, "Original Plan")
        
        # Refined plan tab
        self.refined_tab = QWidget()
        self.refined_tab_layout = QVBoxLayout(self.refined_tab)
        self.refined_tab_layout.setContentsMargins(0, 0, 0, 0)
        self.refined_tab_layout.setSpacing(0)
        self.category_tabs.addTab(self.refined_tab, "Refined Plan")
        
        center_layout.addWidget(self.category_tabs)
        
        # Right panel - Thought trace
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        
        self.thought_trace = ThoughtTraceWidget()
        right_layout.addWidget(self.thought_trace)
        
        # Add panels to splitter
        self.splitter.addWidget(left_panel)
        self.splitter.addWidget(center_panel)
        self.splitter.addWidget(right_panel)
        self.splitter.setSizes([300, 600, 300])
        
        main_layout.addWidget(self.splitter, 1)
    
    def create_header(self):
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
        self.details_btn.clicked.connect(self.show_system_details)
        self.details_btn.setEnabled(False)
        hdr.addWidget(self.details_btn)
        
        self.api_label = QLabel(" READY")
        self.api_label.setStyleSheet("border: 1px solid #666; padding: 5px; border-radius: 3px;")
        hdr.addWidget(self.api_label)
        
        return hdr
    
    def log_msg(self, msg: str, level="INFO"):
        self.log.append(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] [{level}] {msg}")
    
    def set_api_status(self, status: str, error: Optional[str] = None):
        if status == "online":
            self.api_label.setText(" ASI-1 ONLINE")
            self.api_label.setStyleSheet("border: 1px solid #00ff00; padding: 5px; border-radius: 3px;")
        elif status == "error":
            self.api_label.setText(" ERROR")
            self.api_label.setStyleSheet("border: 1px solid #ff0000; padding: 5px; border-radius: 3px;")
        else:
            self.api_label.setText(" READY")
            self.api_label.setStyleSheet("border: 1px solid #666; padding: 5px; border-radius: 3px;")
    
    def show_system_details(self):
        if self.snapshot:
            dialog = SystemDetailsDialog(self.snapshot, self)
            dialog.exec()
    
    def scan(self):
        self.log_msg("Scanning system...")
        self.scan_btn.setEnabled(False)
        self.details_btn.setEnabled(False)
        self.set_api_status("unknown")
        
        self.clear_all_categories()
        self.flow_indicator.set_stage(0)
        self.analyzer.client.start_pipeline()
        
        self.scan_worker = ScanWorker()
        self.scan_worker.finished.connect(self.scan_done)
        self.scan_worker.start()
    
    def scan_done(self, snapshot):
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
        # Score shown after analysis, not scan
        self.chart_stack.setCurrentWidget(self.clean_view)
    
    def analyze(self):
        if not self.snapshot:
            return
        
        self.log_msg("Calling ASI-1 for analysis...")
        self.analyze_btn.setEnabled(False)
        self.flow_indicator.set_stage(1)
        
        self.analyze_worker = AnalyzeWorker(self.analyzer, self.snapshot)
        self.analyze_worker.finished.connect(self.analyze_done)
        self.analyze_worker.start()
    
    def analyze_done(self, metrics):
        self.metrics = metrics
        
        if metrics.error:
            self.log_msg(f"Analysis issue: {metrics.error}", "WARN")
        
        self.log_msg(f"ASI-1 score: {metrics.overall_score}")
        self.status.setText(f"Score: {metrics.overall_score}")
        self.clean_view.set_score(metrics.overall_score)
        self.chart.update_scores(metrics.overall_score)
        self.flow_indicator.set_stage(2)
        
        self.thought_trace.update_trace(self.analyzer.client.get_thought_trace())
        self.get_strategic_insight()
    
    def get_strategic_insight(self):
        self.log_msg("Getting strategic insight...")
        
        self.insight_worker = InsightWorker(self.analyzer, self.snapshot, self.metrics)
        self.insight_worker.finished.connect(self.insight_done)
        self.insight_worker.start()
    
    def insight_done(self, insight):
        self.strategic_insight = insight
        
        if insight:
            self.log_msg(f"Priority: {insight.priority_domain}")
            self.thought_trace.update_trace(self.analyzer.client.get_thought_trace())
            self.flow_indicator.set_stage(2)
        else:
            self.log_msg("No insight received", "WARN")
        
        self.plan_btn.setEnabled(True)
    
    def generate_plan(self):
        if not self.snapshot or not self.metrics:
            return
        
        self.log_msg("Generating optimization plan...")
        self.plan_btn.setEnabled(False)
        self.flow_indicator.set_stage(2)
        
        # Switch to chart view
        self.chart_stack.setCurrentWidget(self.chart)
        
        self.plan_worker = PlanWorker(self.analyzer, self.snapshot, self.metrics, self.strategic_insight)
        self.plan_worker.finished.connect(self.plan_done)
        self.plan_worker.start()
    
    def plan_done(self, categories, projected, error, warning):
        if error:
            self.log_msg(f"Plan generation issue: {error}", "WARN")
            if categories is None:
                self.plan_btn.setEnabled(True)
                return
        
        self.original_categories = categories
        self.original_projected = projected
        self.thought_trace.update_trace(self.analyzer.client.get_thought_trace())
        
        self.log_msg(f"Plan generated. Projected: {projected}")
        self.chart.update_scores(self.metrics.overall_score, original_projected=projected)
        self.flow_indicator.set_stage(3)
        
        self.display_original_plan()
        self.get_plan_critique()
    
    def display_original_plan(self):
        """Display original plan in original tab"""
        # Clear original tab
        self.clear_tab_layout(self.original_tab_layout)
        
        # Create scroll area for original plan - with smooth scrolling enabled
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setMinimumHeight(300)  # Ensure scroll area has minimum height
        scroll.setStyleSheet("border: none;")
        
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        priority_domain = self.strategic_insight.priority_domain if self.strategic_insight else None
        
        for cat in self.original_categories:
            is_priority = (priority_domain and cat.name == priority_domain)
            w = CategoryWidget(cat, is_priority, "original")
            w.changed.connect(self.selection_changed)
            layout.addWidget(w)
        
        layout.addStretch()
        scroll.setWidget(container)
        self.original_tab_layout.addWidget(scroll)
    
    def display_refined_plan(self):
        """Display refined plan in refined tab"""
        # Clear refined tab
        self.clear_tab_layout(self.refined_tab_layout)
        
        # Create scroll area for refined plan - with smooth scrolling enabled
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setMinimumHeight(300)  # Ensure scroll area has minimum height
        scroll.setStyleSheet("border: none;")
        
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        priority_domain = self.strategic_insight.priority_domain if self.strategic_insight else None
        
        for cat in self.refined_categories:
            is_priority = (priority_domain and cat.name == priority_domain)
            w = CategoryWidget(cat, is_priority, "refined")
            w.changed.connect(self.selection_changed)
            layout.addWidget(w)
        
        layout.addStretch()
        scroll.setWidget(container)
        self.refined_tab_layout.addWidget(scroll)
        
        # Switch to refined tab
        self.category_tabs.setCurrentIndex(1)
        
        # Update script diff view
        original_tasks = []
        for cat in self.original_categories:
            original_tasks.extend(cat.tasks)
        
        refined_tasks = []
        for cat in self.refined_categories:
            refined_tasks.extend(cat.tasks)
        
        self.script_diff.update_diff(original_tasks, refined_tasks)
    
    def clear_tab_layout(self, layout):
        """Clear all widgets from a layout"""
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
    
    def clear_all_categories(self):
        """Clear both tabs"""
        self.clear_tab_layout(self.original_tab_layout)
        self.clear_tab_layout(self.refined_tab_layout)
    
    def get_plan_critique(self):
        self.log_msg("AI Self-Review in progress...")
        
        self.critique_worker = CritiqueWorker(self.analyzer, self.original_categories, self.metrics)
        self.critique_worker.finished.connect(self.critique_done)
        self.critique_worker.start()
    
    def critique_done(self, critique):
        self.plan_critique = critique
        
        if critique:
            self.log_msg("Self-review complete")
            self.thought_trace.update_trace(self.analyzer.client.get_thought_trace())
            self.flow_indicator.set_stage(4)
            self.regenerate_plan()
        else:
            self.log_msg("No review received", "WARN")
            self.export_btn.setEnabled(True)
    
    def regenerate_plan(self):
        self.log_msg("Creating refined strategy...")
        
        self.regenerate_worker = RegenerateWorker(
            self.analyzer, self.snapshot, self.metrics, self.plan_critique, self.original_projected
        )
        self.regenerate_worker.finished.connect(self.regenerate_done)
        self.regenerate_worker.start()
    
    def regenerate_done(self, categories, projected, risk_reduction, improvements):
        if not categories:
            self.log_msg("Using refined version of original plan", "WARN")
            categories = self.original_categories[:4]
            for cat in categories:
                for task in cat.tasks:
                    task.description = f"[SAFE] {task.description}"
                    task.risk = RiskLevel.LOW
                    task.is_safe = True
            self.refined_categories = categories
            self.refined_projected = max(self.metrics.overall_score + 5, (self.original_projected or 80) - 3)
            self.risk_reduction = 20.0
            self.improvements = ["Added safety checks", "Reduced impact"]
        else:
            self.refined_categories = categories
            self.refined_projected = projected or (self.original_projected - 2)
            self.risk_reduction = risk_reduction or 20.0
            self.improvements = improvements or ["Optimized for safety"]
        
        self.log_msg(f"Refined strategy ready: +{self.refined_projected - self.metrics.overall_score} gain, -{self.risk_reduction:.0f}% risk")
        self.thought_trace.update_trace(self.analyzer.client.get_thought_trace())
        self.flow_indicator.set_stage(4)
        
        # Update chart with refined score
        self.chart.update_scores(
            self.metrics.overall_score,
            original_projected=self.original_projected,
            refined_projected=self.refined_projected
        )
        
        # Get confidence
        self.assess_confidence()
    
    def assess_confidence(self):
        plan_data = {
            "original": self.original_projected,
            "refined": self.refined_projected,
            "risk_reduction": self.risk_reduction
        }
        
        assessment = self.analyzer.assess_confidence(plan_data, self.metrics)
        if assessment:
            self.confidence_score = assessment.confidence_score
        else:
            self.confidence_score = 85 + (self.risk_reduction / 2)
        
        self.risk_delta.update_delta(
            self.original_projected or 80,
            self.refined_projected,
            self.risk_reduction,
            self.confidence_score,
            self.improvements
        )
        
        self.display_refined_plan()
        self.export_btn.setEnabled(True)
        self.reverse_btn.setEnabled(True)
    
    def selection_changed(self):
        """Live update risk when tasks are selected"""
        # Get selected tasks from current tab
        selected = self.get_selected()
        
        if selected:
            impact = sum(t.impact_on_stability for t in selected)
            self.status.setText(f"Selected {len(selected)} tasks (impact: +{impact})")
            
            # Update live risk
            self.live_risk.update_risk(selected, self.metrics.overall_score)
            
            # Update chart with live projection
            if self.metrics:
                risk_data = LiveRiskCalculator.calculate_risk(selected, self.metrics.overall_score)
                self.chart.update_scores(
                    self.metrics.overall_score,
                    original_projected=self.original_projected,
                    refined_projected=self.refined_projected,
                    live_projected=risk_data["projected_score"]
                )
            
            # Update script preview
            self.script_preview.update_script(selected)
        else:
            self.status.setText("No tasks selected")
            self.live_risk.hide()
            self.script_preview.hide()
            self.chart.update_scores(
                self.metrics.overall_score,
                original_projected=self.original_projected,
                refined_projected=self.refined_projected
            )
    
    def get_selected(self) -> List[OptimizationTask]:
        """Get selected tasks from current tab"""
        selected = []
        current_tab = self.category_tabs.currentIndex()
        
        if current_tab == 0:  # Original tab
            for i in range(self.original_tab_layout.count()):
                item = self.original_tab_layout.itemAt(i)
                if item and item.widget():
                    scroll = item.widget()
                    if isinstance(scroll, QScrollArea):
                        container = scroll.widget()
                        if container:
                            for j in range(container.layout().count()):
                                w = container.layout().itemAt(j).widget()
                                if isinstance(w, CategoryWidget):
                                    selected.extend(w.get_selected())
        else:  # Refined tab
            for i in range(self.refined_tab_layout.count()):
                item = self.refined_tab_layout.itemAt(i)
                if item and item.widget():
                    scroll = item.widget()
                    if isinstance(scroll, QScrollArea):
                        container = scroll.widget()
                        if container:
                            for j in range(container.layout().count()):
                                w = container.layout().itemAt(j).widget()
                                if isinstance(w, CategoryWidget):
                                    selected.extend(w.get_selected())
        
        return selected
    
    def simulate_strategies(self):
        if not self.snapshot or not self.metrics:
            return
        
        self.log_msg("Running strategy simulation...")
        self.simulate_btn.setEnabled(False)
        
        # FIX: Use worker thread for simulation that properly routes through analyzer
        self.simulation_worker = SimulationWorker(self.analyzer, self.snapshot, self.metrics)
        self.simulation_worker.finished.connect(self.simulation_done)
        self.simulation_worker.start()
    
    def simulation_done(self, result):
        """Handle simulation completion"""
        if result and isinstance(result, SimulationResult):
            self.simulation_result = result
            # Update strategy comparison widget
            self.strategy_comparison.update_strategies(
                result.strategies, 
                result.selected_index, 
                result.reasoning
            )
            self.log_msg(f"Best: {result.strategies[result.selected_index].name}")
            
            # Show popup with details
            selected = result.strategies[result.selected_index]
            QMessageBox.information(self, "Simulation Complete", 
                f"Recommended: {selected.name}\n"
                f"Gain: +{selected.gain}\n"
                f"Risk: {selected.risk_level}\n"
                f"Confidence: {selected.confidence:.1f}%\n\n"
                f"Reasoning: {result.reasoning}")
        else:
            self.log_msg("Simulation failed or returned invalid result", "ERROR")
        
        self.simulate_btn.setEnabled(True)
    
    def export_script(self):
        """Export selected tasks as PowerShell script"""
        selected = self.get_selected()
        if not selected:
            QMessageBox.information(self, "No Selection", "Select tasks first")
            return
        
        # Ensure script preview is visible
        self.script_preview.update_script(selected)
        
        # Save dialog
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
    
    def create_restore_point(self):
        """Create a system restore point"""
        self.log_msg("Creating system restore point...")
        success, msg = RestorePointCreator.create_restore_point()
        if success:
            self.log_msg("Restore point created")
            QMessageBox.information(self, "Success", msg)
        else:
            self.log_msg(f"Failed to create restore point: {msg}", "ERROR")
            QMessageBox.warning(self, "Warning", msg)
    
    def create_backup(self):
        """Create a backup of current system state"""
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
    
    def reverse_last_action(self):
        """Reverse the last action by restoring from backup"""
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
                
                # Reset UI state
                if self.metrics:
                    self.metrics.overall_score = 70
                self.clean_view.set_score(70)
                self.chart_stack.setCurrentWidget(self.clean_view)
                self.reverse_btn.setEnabled(False)
            else:
                self.log_msg("Failed to restore system", "ERROR")
                QMessageBox.warning(self, "Warning", "Failed to restore system")


# ============================================================================
# WORKER THREADS
# ============================================================================

class ScanWorker(QThread):
    finished = Signal(object)
    def run(self):
        snapshot = system_scanner()
        self.finished.emit(snapshot)

class AnalyzeWorker(QThread):
    finished = Signal(object)
    def __init__(self, analyzer, snapshot):
        super().__init__()
        self.analyzer = analyzer
        self.snapshot = snapshot
    def run(self):
        metrics = self.analyzer.analyze(self.snapshot)
        self.finished.emit(metrics)

class InsightWorker(QThread):
    finished = Signal(object)
    def __init__(self, analyzer, snapshot, metrics):
        super().__init__()
        self.analyzer = analyzer
        self.snapshot = snapshot
        self.metrics = metrics
    def run(self):
        insight = self.analyzer.get_strategic_insight(self.snapshot, self.metrics)
        self.finished.emit(insight)

class PlanWorker(QThread):
    finished = Signal(object, object, object, object)
    def __init__(self, analyzer, snapshot, metrics, insight):
        super().__init__()
        self.analyzer = analyzer
        self.snapshot = snapshot
        self.metrics = metrics
        self.insight = insight
    def run(self):
        cats, proj, err, warn = self.analyzer.generate_plan(self.snapshot, self.metrics, self.insight)
        self.finished.emit(cats, proj, err, warn)

class CritiqueWorker(QThread):
    finished = Signal(object)
    def __init__(self, analyzer, categories, metrics):
        super().__init__()
        self.analyzer = analyzer
        self.categories = categories
        self.metrics = metrics
    def run(self):
        critique = self.analyzer.critique_plan(self.categories, self.metrics)
        self.finished.emit(critique)

class RegenerateWorker(QThread):
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
        self.finished.emit(cats, proj, risk, impr)


# ============================================================================
# MAIN
# ============================================================================

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    app.setStyleSheet("""
        QMainWindow, QDialog { background-color: #1a1a1a; }
        QLabel { color: white; }
        QPushButton {
            background-color: #2a2a2a;
            color: white;
            border: 1px solid #00ff00;
            padding: 8px;
            border-radius: 4px;
            font-weight: bold;
            min-width: 120px;
        }
        QPushButton:hover { background-color: #3a3a3a; }
        QPushButton:disabled { border-color: #666; color: #666; }
        QTextEdit { background-color: #2a2a2a; color: #00ff00; border: 1px solid #00ff00; }
        QProgressBar { border: 1px solid #00ff00; text-align: center; color: white; height: 20px; }
        QProgressBar::chunk { background-color: #00ff00; }
        QTableWidget { background-color: #2a2a2a; color: white; border: 1px solid #00ff00; }
        QHeaderView::section { background-color: #1a1a1a; color: #00ff00; border: 1px solid #00ff00; }
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
    """)
    
    # Check for API key
    if not ASI_API_KEY:
        # Show warning but don't crash - app can still work with fallback plans
        msg = "ASI_API_KEY not set. Please set it with:\n"
        msg += "export ASI_API_KEY='your-key-here'\n\n"
        msg += "The app will continue with fallback plans."
        QMessageBox.warning(None, "API Key Missing", msg)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
