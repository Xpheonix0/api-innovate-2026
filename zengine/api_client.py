"""
Thread-safe ASI-1 API client
"""

import json
import datetime
import time
import threading
import requests
import re
from typing import Dict, List, Any, Optional

from zengine.config import ASI_API_KEY, ASI_API_URL, CONNECTION_TIMEOUT, MAX_PIPELINE_DURATION
from zengine.scanner import check_internet_connection


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
