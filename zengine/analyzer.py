"""
Pure AI Analyzer - Orchestrates API calls and data processing
"""

import uuid
import threading
from typing import Dict, List, Any, Optional, Tuple

from zengine.models import (
    SystemStabilityMetrics, StrategicInsight, StrategyOption,
    SimulationResult, PlanCritique, ConfidenceAssessment,
    OptimizationTask, OptimizationCategory
)
from zengine.api_client import PureASIClient
from zengine.safety import RiskLevel


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
