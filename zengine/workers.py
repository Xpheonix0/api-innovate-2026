"""
Worker threads for background operations
"""

import threading
from PySide6.QtCore import QThread, Signal

from zengine.scanner import system_scanner


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
