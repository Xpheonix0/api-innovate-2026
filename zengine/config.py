"""
Configuration constants for Z-Engine
"""

import os
from pathlib import Path

# ASI-1 API Configuration
ASI_API_URL = "https://api.asi1.ai/v1/chat/completions"
CONNECTION_TIMEOUT = 25
MAX_PIPELINE_DURATION = 60

# Load API key from environment or config file
ASI_API_KEY = os.environ.get("ASI_API_KEY", "")
if not ASI_API_KEY:
    config_path = Path.home() / ".zengine" / "config.json"
    if config_path.exists():
        try:
            import json
            with open(config_path) as f:
                config = json.load(f)
                ASI_API_KEY = config.get("api_key", "")
        except Exception as e:
            print(f"Warning: Could not read config file: {e}")
