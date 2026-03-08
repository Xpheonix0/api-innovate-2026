"""
Main window for Z-Engine
"""

import datetime
import os
import threading
from typing import List, Optional

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QGroupBox, QTabWidget, QScrollArea,
    QStackedWidget, QToolBox, QTextEdit, QMessageBox, QFileDialog,
    QMenuBar, QMenu, QAction
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont

from zengine.config import ASI_API_KEY
from zengine.analyzer import PureAIAnalyzer
from zengine.backup import BackupManager, RestorePointCreator
from zengine.models import (
    SimulationResult, RiskLevel, OptimizationCategory,
    OptimizationTask
)
from zengine.script import LiveRiskCalculator
from zengine.workers import (
    ScanWorker, AnalyzeWorker, InsightWorker, PlanWorker,
    CritiqueWorker, RegenerateWorker, SimulationWorker, ConfidenceWorker
)
from zengine.ui.widgets import (
    FlowIndicator, CleanGraphWidget, ThreeBarChartWidget,
    StrategyComparisonWidget, ScriptDiffWidget, ScriptPreviewWidget,
    LiveRiskWidget, RiskDeltaWidget, CategoryWidget
)
from zengine.ui.dialogs import SystemDetailsDialog, ThoughtTraceWidget


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
        self
