"""
PowerShell script generation and execution
"""

import datetime
import tempfile
import os
import subprocess
import re
from typing import List, Optional

from PySide6.QtWidgets import QMessageBox, QFileDialog

from zengine.safety import CommandSafety
from zengine.models import RiskLevel, OptimizationTask


# Real PowerShell commands mapped to common optimization categories
# IMPORTANT: CPU command must NOT use Stop-Process -Force broadly —
# it can kill the console host and crash the script mid-run.
FALLBACK_COMMANDS = {
    "memory":   "Clear-RecycleBin -Force -ErrorAction SilentlyContinue; [System.GC]::Collect()",
    "cpu":      (
        "Get-Process | Where-Object {"
        "$_.CPU -gt 100 -and "
        "$_.Name -notmatch 'powershell|pwsh|explorer|svchost|lsass|csrss|winlogon|System|smss|wininit'"
        "} | ForEach-Object { try { $_.Kill() } catch {} }"
    ),
    "disk":     "Optimize-Volume -DriveLetter C -ReTrim -Verbose",
    "startup":  "Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location | Format-Table",
    "network":  "ipconfig /flushdns; netsh winsock reset",
    "security": "Update-MpSignature -ErrorAction SilentlyContinue",
    "cache":    'Remove-Item -Path "$env:TEMP\\*" -Recurse -Force -ErrorAction SilentlyContinue',
    "service":  (
        "Get-Service | Where-Object {"
        "$_.StartType -eq 'Automatic' -and $_.Status -eq 'Stopped'"
        "} | Select-Object Name, DisplayName | Format-Table"
    ),
    "default":  "Write-Host 'Optimization task completed' -ForegroundColor Green"
}


def _get_fallback_command(description: str, category: str) -> str:
    """Return a real PowerShell command based on description/category keywords"""
    text = (description + " " + category).lower()
    if any(k in text for k in ["memory", "ram", "standby"]):
        return FALLBACK_COMMANDS["memory"]
    elif any(k in text for k in ["cpu", "process", "processor"]):
        return FALLBACK_COMMANDS["cpu"]
    elif any(k in text for k in ["disk", "drive", "storage", "volume", "defrag"]):
        return FALLBACK_COMMANDS["disk"]
    elif any(k in text for k in ["startup", "boot", "autostart"]):
        return FALLBACK_COMMANDS["startup"]
    elif any(k in text for k in ["network", "dns", "socket", "winsock"]):
        return FALLBACK_COMMANDS["network"]
    elif any(k in text for k in ["security", "defender", "antivirus", "firewall"]):
        return FALLBACK_COMMANDS["security"]
    elif any(k in text for k in ["cache", "temp", "temporary"]):
        return FALLBACK_COMMANDS["cache"]
    elif any(k in text for k in ["service", "services"]):
        return FALLBACK_COMMANDS["service"]
    else:
        return FALLBACK_COMMANDS["default"]


def _is_valid_powershell_command(cmd: str) -> bool:
    """Check if a string looks like a real PowerShell command"""
    if not cmd or len(cmd.strip()) < 3:
        return False
    cmd = cmd.strip()
    ps_indicators = [
        '-', 'Get-', 'Set-', 'Remove-', 'Clear-', 'Start-', 'Stop-',
        'Write-', 'New-', 'Add-', 'Update-', 'Invoke-', 'Test-',
        'ipconfig', 'netsh', 'sfc', 'reg ', 'sc ', 'wmic', 'bcdedit',
        'defrag', 'chkdsk', 'powercfg', 'Optimize-', 'Restart-',
        '$env:', '$_', 'foreach', 'if (', 'param('
    ]
    return any(indicator in cmd for indicator in ps_indicators)


class ScriptGenerator:
    """Generates PowerShell scripts from selected tasks with safety validation"""

    @classmethod
    def generate_script(cls, tasks: List[OptimizationTask], safe_mode: bool = True) -> str:
        unsafe_tasks = []
        for task in tasks:
            is_safe, risk, reason = CommandSafety.is_command_safe(task.original_command)
            if not is_safe and not safe_mode:
                unsafe_tasks.append((task, reason))

        if unsafe_tasks and not safe_mode:
            warning = "\n".join([f"  - {t[0].description}: {t[1]}" for t in unsafe_tasks])
            return (
                f"# WARNING: Unsafe commands detected:\n{warning}\n#\n"
                "# Please enable Safe Mode or review commands manually"
            )

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
            '$logFile = "$env:TEMP\\Z-Engine_$(Get-Date -Format \'yyyyMMdd_HHmmss\').log"',
            "Start-Transcript -Path $logFile",
            "",
            'Write-Host "Logging to: $logFile" -ForegroundColor Cyan',
            "",
            "# SAFE MODE COMMAND VALIDATION",
            "# - All commands are validated against safety whitelist",
            "# - Dangerous commands are blocked or modified",
            "# - Read-only operations are preferred where possible",
            ""
        ]

        categories = {}
        for task in tasks:
            if task.category not in categories:
                categories[task.category] = []
            categories[task.category].append(task)

        for category, cat_tasks in categories.items():
            lines.append("")
            lines.append(f"Write-Host 'Processing: {category}' -ForegroundColor Yellow")
            separator = "-" * (len(category) + 10)
            lines.append(f"Write-Host '{separator}' -ForegroundColor Yellow")

            safe_tasks     = [t for t in cat_tasks if t.risk == RiskLevel.LOW]
            advanced_tasks = [t for t in cat_tasks if t.risk != RiskLevel.LOW]

            if safe_tasks:
                lines.append("Write-Host ''")
                lines.append("Write-Host 'SAFE OPTIMIZATIONS' -ForegroundColor Green")
                for task in safe_tasks:
                    cls._add_task_to_script(lines, task, safe_mode)

            if advanced_tasks:
                lines.append("Write-Host ''")
                lines.append("Write-Host 'ADVANCED / CAUTION' -ForegroundColor Yellow")
                for task in advanced_tasks:
                    cls._add_task_to_script(lines, task, safe_mode)

        reboot_tasks = [t for t in tasks if t.requires_reboot]
        if reboot_tasks:
            lines.extend([
                "",
                "Write-Host ''",
                "Write-Host 'Some changes require a reboot' -ForegroundColor Yellow",
                "$reboot = Read-Host 'Reboot now? (y/N)'",
                "if ($reboot -eq 'y') {",
                "    Restart-Computer -Force",
                "}"
            ])

        lines.extend([
            "",
            "Stop-Transcript",
            "Write-Host 'Script completed' -ForegroundColor Green"
        ])

        return '\n'.join(lines)

    @classmethod
    def _add_task_to_script(cls, lines: list, task: OptimizationTask, safe_mode: bool):
        lines.append("")
        lines.append(f"# {task.description}")
        if task.reasoning:
            lines.append(f"# Reasoning: {task.reasoning}")
        lines.append(f"# Risk: {task.get_risk_badge()}")

        is_safe, cmd_risk, safety_note = CommandSafety.is_command_safe(task.original_command)
        cmd_to_use = task.get_execution_command(safe_mode)
        cmd_to_use = cmd_to_use.strip() if cmd_to_use else ""

        # Fall back to a real PS command if the AI returned a placeholder
        if not _is_valid_powershell_command(cmd_to_use):
            cmd_to_use = _get_fallback_command(task.description, task.category)
            lines.append("# Note: Using best-match command for this optimization")

        if not is_safe and safe_mode:
            lines.append(f"# Command modified for safety: {safety_note}")

        # $($_.Exception.Message) is the correct PS error variable inside catch {}
        if cmd_risk in ["high", "critical"] and safe_mode:
            lines.append(f"Write-Host '  {task.description} (High Risk)' -ForegroundColor Yellow")
            lines.append(f"Write-Host '      {safety_note}' -ForegroundColor Yellow")
            lines.append(f"$confirm = Read-Host '    Proceed with this high-risk operation? (y/N)'")
            lines.append(f"if ($confirm -eq 'y') {{")
            lines.append(f"    try {{")
            lines.append(f"        {cmd_to_use}")
            lines.append(f"        Write-Host '    Completed' -ForegroundColor Green")
            lines.append(f"    }} catch {{")
            lines.append(f'        Write-Host "    Failed: $($_.Exception.Message)" -ForegroundColor Red')
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
            lines.append(f'    Write-Host "    Failed: $($_.Exception.Message)" -ForegroundColor Red')
            lines.append(f"    Write-Warning 'Error in {task.description}'")
            lines.append(f"}}")

    @staticmethod
    def save_script(content: str, default_name: str = "Z-Engine_Optimization.ps1") -> Optional[str]:
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


class ScriptRunner:
    """Handles running PowerShell scripts with UAC elevation"""

    @staticmethod
    def _escape_path_for_powershell(path: str) -> str:
        return path.replace('\\', '\\\\').replace('"', '`"')

    @staticmethod
    def run_script(script_path: str, parent_widget=None) -> bool:
        if os.name != 'nt':
            QMessageBox.critical(parent_widget, "Error", "PowerShell scripts can only run on Windows systems")
            return False
        if not os.path.exists(script_path):
            QMessageBox.critical(parent_widget, "Error", f"Script not found: {script_path}")
            return False
        # Note: $ intentionally excluded from blocklist — Windows temp paths contain it
        if any(c in script_path for c in [';', '&', '|', '`']):
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
            if not os.path.abspath(script_path).startswith(os.path.abspath(temp_dir)):
                print("Error: Script path would escape temp directory")
                return None
            with open(script_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return script_path
        except Exception as e:
            print(f"Failed to create temp script: {e}")
            return None


class LiveRiskCalculator:
    """Calculates real-time risk based on selected tasks"""

    @staticmethod
    def calculate_risk(tasks, base_score: int) -> dict:
        if not tasks:
            return {
                "total_risk": 0, "risk_level": "None",
                "high_risk_tasks": 0, "unsafe_commands": 0,
                "exe_missing": 0, "reboot_required": False,
                "stability_impact": 0, "confidence": 100
            }

        risk_counts = {
            RiskLevel.LOW:      sum(1 for t in tasks if t.risk == RiskLevel.LOW),
            RiskLevel.MEDIUM:   sum(1 for t in tasks if t.risk == RiskLevel.MEDIUM),
            RiskLevel.HIGH:     sum(1 for t in tasks if t.risk == RiskLevel.HIGH),
            RiskLevel.CRITICAL: sum(1 for t in tasks if t.risk == RiskLevel.CRITICAL)
        }
        risk_weights = {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 3, RiskLevel.HIGH: 6, RiskLevel.CRITICAL: 10}
        total_weight = sum(risk_counts[r] * risk_weights[r] for r in risk_counts)
        max_possible = len(tasks) * 10
        risk_pct     = (total_weight / max_possible * 100) if max_possible > 0 else 0

        unsafe_commands = sum(1 for t in tasks if not CommandSafety.is_command_safe(t.original_command)[0])
        risk_pct = min(100, risk_pct + (unsafe_commands * 5))

        if risk_pct < 20:   risk_level = "Very Low"
        elif risk_pct < 40: risk_level = "Low"
        elif risk_pct < 60: risk_level = "Medium"
        elif risk_pct < 80: risk_level = "High"
        else:               risk_level = "Critical"

        total_impact = sum(t.impact_on_stability for t in tasks)
        if base_score >= 100:
            gain = 0
        else:
            room = 100 - base_score
            gain = min(room, int(total_impact * (room / 100)))

        confidence = max(0, min(100, 100 - risk_pct))

        return {
            "total_risk":       round(risk_pct, 1),
            "risk_level":       risk_level,
            "risk_counts":      risk_counts,
            "high_risk_tasks":  risk_counts[RiskLevel.HIGH] + risk_counts[RiskLevel.CRITICAL],
            "unsafe_commands":  unsafe_commands,
            "exe_missing":      0,
            "reboot_required":  any(t.requires_reboot for t in tasks),
            "stability_impact": gain,
            "projected_score":  min(100, base_score + gain),
            "confidence":       round(confidence, 1)
        }
