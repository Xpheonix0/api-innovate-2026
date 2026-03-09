"""
Command safety validation
"""

import re
import os
from typing import Tuple

from zengine.models import RiskLevel


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
                   return True, ("low" if validator["safe"] else "medium"), validator["message"]
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
