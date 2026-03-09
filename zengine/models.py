"""
Data models for Z-Engine
"""

import datetime
import uuid
from typing import Dict, List, Any, Optional
from enum import Enum


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @classmethod
    def from_value(cls, value):
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).lower())
        except ValueError:
            return cls.LOW
    
    def get_color(self) -> str:
        colors = {
            RiskLevel.LOW: "#00ff00",
            RiskLevel.MEDIUM: "#ffff00",
            RiskLevel.HIGH: "#ff8800",
            RiskLevel.CRITICAL: "#ff0000"
        }
        return colors.get(self, "#ffffff")


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


# Store the command to use
        self.actual_command = self.safe_command if self.safe_command else self.original_command

    def get_execution_command(self, safe_mode: bool = True) -> str:                          
        if safe_mode:
            return self.safe_command or self.original_command
        return self.original_command

    def get_risk_badge(self) -> str:
```

The whole `OptimizationTask` class should look like this structure:
```
class OptimizationTask:
    def __init__(...)       ← 4 spaces
    def get_execution_command(...)  
    def get_risk_badge(...)        
    def get_risk_color(...)         


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
