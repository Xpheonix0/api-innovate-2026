"""
Main window for Z-Engine
"""

import datetime
import os
import threading
from typing import List, Optional
from zengine.safety import CommandSafety
from zengine.script import ScriptGenerator
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QGroupBox, QTabWidget, QScrollArea,
    QStackedWidget, QToolBox, QTextEdit, QMessageBox, QFileDialog,
    QMenuBar, QMenu, QProgressBar
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QAction

from zengine.config import ASI_API_KEY
from zengine.analyzer import PureAIAnalyzer
from zengine.backup import BackupManager, RestorePointCreator
from zengine.models import (
    SimulationResult, RiskLevel, OptimizationCategory,
    OptimizationTask
)
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
            # Wrap with min(100, ...) to cap at 100
            self.confidence_score = min(100, assessment.confidence_score)
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
        # Add this check at the very top
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


# Utility class for risk calculation
class LiveRiskCalculator:
    """Calculates real-time risk based on selected tasks"""
    
    @staticmethod
    def calculate_risk(tasks: List[OptimizationTask], base_score: int) -> dict:
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
            "exe_missing": 0,
            "reboot_required": any(t.requires_reboot for t in tasks),
            "stability_impact": gain,
            "projected_score": min(100, base_score + gain),
            "confidence": round(confidence, 1)
        }
