"""
Reusable UI widgets for Z-Engine
"""

import datetime
import os

from PySide6.QtWidgets import (
    QFrame, QLabel, QHBoxLayout, QVBoxLayout, QGridLayout,
    QPushButton, QCheckBox, QProgressBar, QPlainTextEdit,
    QGroupBox, QScrollArea, QToolBox, QWidget, QMessageBox
)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont

from zengine.models import OptimizationTask, OptimizationCategory, StrategyOption
from zengine.safety import CommandSafety, RiskLevel
from zengine.script import ScriptGenerator, ScriptRunner, LiveRiskCalculator


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
        
        desc_text = f"{self.task.description}"
        desc = QLabel(desc_text)
        desc.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        desc.setWordWrap(True)
        desc.setMinimumWidth(200)
        details.addWidget(desc)
        
        meta = QHBoxLayout()
        meta.setSpacing(10)
        
        if self.task.impact_on_stability > 0:
            gain = QLabel(f"+{self.task.impact_on_stability}")
            gain.setFont(QFont("Arial", 12, QFont.Weight.Bold))
            gain.setStyleSheet("color: #00ff00;")
            meta.addWidget(gain)
            meta.addWidget(QLabel("stability"))
        
        if not self.task.is_safe_command:
            warning = QLabel(" UNSAFE ")
            warning.setStyleSheet("background: #ff0000; color: white; font-weight: bold; padding: 2px 4px; border-radius: 3px;")
            meta.addWidget(warning)
        else:
            safe_badge = QLabel(" SAFE ")
            safe_badge.setStyleSheet("background: #00ff00; color: black; font-weight: bold; padding: 2px 4px; border-radius: 3px;")
            meta.addWidget(safe_badge)
            
        risk_color = self.task.get_risk_color()
        risk = QLabel(f" {self.task.get_risk_badge()} ")
        risk.setStyleSheet(f"background: {risk_color}; color: black; font-weight: bold; padding: 2px 4px; border-radius: 3px;")
        meta.addWidget(risk)
        
        if self.task.requires_reboot:
            reboot = QLabel(" REBOOT ")
            reboot.setStyleSheet("background: #ff8800; color: black; font-weight: bold; padding: 2px 4px; border-radius: 3px;")
            meta.addWidget(reboot)
        
        if self.plan_type == "refined":
            refined_badge = QLabel(" REFINED ")
            refined_badge.setStyleSheet("background: #00ffff; color: black; font-weight: bold; padding: 2px 4px; border-radius: 3px;")
            meta.addWidget(refined_badge)
        
     
        
        meta.addStretch()
        details.addLayout(meta)
        layout.addLayout(details)
        layout.addStretch()
        self.setLayout(layout)
    
    def mousePressEvent(self, event):
        self.selected = not self.selected
        self.setProperty("selected", self.selected)
        self.style().polish(self)
        self.indicator.setText("✓" if self.selected else "  ")
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
            priority_badge = QLabel("⚡ FOCUS AREA")
            priority_badge.setStyleSheet("""
                background: #00ff00;
                color: black;
                font-weight: bold;
                padding: 4px 8px;
                border-radius: 4px;
                max-width: 120px;
            """)
            layout.addWidget(priority_badge)
        
        if self.plan_type == "refined":
            refined_badge = QLabel("✨ IMPROVED")
            refined_badge.setStyleSheet("""
                background: #00ffff;
                color: black;
                font-weight: bold;
                padding: 4px 8px;
                border-radius: 4px;
                max-width: 120px;
            """)
            layout.addWidget(refined_badge)
        
        if self.category.reasoning:
            reasoning = QLabel(f" {self.category.reasoning}")
            reasoning.setWordWrap(True)
            reasoning.setMinimumWidth(200)
            reasoning.setStyleSheet("color: #88ff88; font-style: italic; padding: 4px;")
            layout.addWidget(reasoning)
        
        safe_tasks = self.category.get_safe_tasks()
        advanced_tasks = self.category.get_unsafe_tasks()
        
        if safe_tasks:
            safe_header = QLabel("🟢 SAFE OPTIMIZATIONS")
            safe_header.setStyleSheet("color: #00ff00; font-weight: bold; margin-top: 8px;")
            layout.addWidget(safe_header)
            
            for task in safe_tasks:
                card = ClickableTaskCard(task, self.plan_type)
                card.toggled.connect(self._on_task_toggled)
                layout.addWidget(card)
                self.cards[task.id] = card
        
        if advanced_tasks:
            if safe_tasks:
                layout.addSpacing(10)
            
            advanced_header = QLabel("🟠 ADVANCED / CAUTION")
            advanced_header.setStyleSheet("color: #ffaa00; font-weight: bold; margin-top: 8px;")
            layout.addWidget(advanced_header)
            
            for task in advanced_tasks:
                card = ClickableTaskCard(task, self.plan_type)
                card.toggled.connect(self._on_task_toggled)
                layout.addWidget(card)
                self.cards[task.id] = card
        
        self.setLayout(layout)
    
    def _on_task_toggled(self, task_id: str, checked: bool):
        self.changed.emit()
    
    def get_selected(self) -> list:
        return [t for t in self.category.tasks if t.id in self.cards and self.cards[t.id].selected]


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
        
        header = QLabel("⚡ Live Risk Analysis")
        header.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        header.setStyleSheet("color: #ffaa00;")
        layout.addWidget(header)
        
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
        
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(5)
        
        grid.addWidget(QLabel("⚠️ High Risk:"), 0, 0)
        self.high_risk_label = QLabel("0")
        self.high_risk_label.setStyleSheet("color: #ff8800; font-weight: bold;")
        grid.addWidget(self.high_risk_label, 0, 1)
        
        grid.addWidget(QLabel("🔴 Unsafe:"), 1, 0)
        self.unsafe_label = QLabel("0")
        self.unsafe_label.setStyleSheet("color: #ff0000; font-weight: bold;")
        grid.addWidget(self.unsafe_label, 1, 1)
        
        grid.addWidget(QLabel("🔄 Reboot:"), 2, 0)
        self.reboot_label = QLabel("No")
        self.reboot_label.setStyleSheet("color: #88ff88;")
        grid.addWidget(self.reboot_label, 2, 1)
        
        grid.addWidget(QLabel("📈 Gain:"), 3, 0)
        self.gain_label = QLabel("+0")
        self.gain_label.setStyleSheet("color: #00ff00; font-weight: bold;")
        grid.addWidget(self.gain_label, 3, 1)
        
        grid.addWidget(QLabel("🎯 Confidence:"), 4, 0)
        self.confidence_label = QLabel("100%")
        self.confidence_label.setStyleSheet("color: #ffff00;")
        grid.addWidget(self.confidence_label, 4, 1)
        
        layout.addLayout(grid)
        self.setLayout(layout)
    
    def update_risk(self, tasks: list, base_score: int):
        self.current_tasks = tasks
        self.base_score = base_score
        
        if not tasks:
            self.hide()
            return
        
        risk_data = LiveRiskCalculator.calculate_risk(tasks, base_score)
        
        self.risk_meter.setValue(int(risk_data["total_risk"]))
        
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
        self.reboot_label.setText("Yes" if risk_data["reboot_required"] else "No")
        self.reboot_label.setStyleSheet("color: #ff8800; font-weight: bold;" if risk_data["reboot_required"] else "color: #88ff88;")
        self.gain_label.setText(f"+{risk_data['stability_impact']}")
        self.confidence_label.setText(f"{risk_data['confidence']}%")
        
        self.show()


class RiskDeltaWidget(QFrame):
    def __init__(self):
        super().__init__()
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
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(8)
        
        header = QLabel("📊 Before vs After")
        header.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffff;")
        layout.addWidget(header)
        
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(5)
        
        grid.addWidget(QLabel("Original:"), 0, 0)
        self.original_label = QLabel("--")
        self.original_label.setStyleSheet("color: #ffaa00; font-size: 14pt; font-weight: bold;")
        grid.addWidget(self.original_label, 0, 1)
        
        grid.addWidget(QLabel("Refined:"), 1, 0)
        self.refined_label = QLabel("--")
        self.refined_label.setStyleSheet("color: #00ffff; font-size: 14pt; font-weight: bold;")
        grid.addWidget(self.refined_label, 1, 1)
        
        grid.addWidget(QLabel("Risk ↓:"), 2, 0)
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
        self.improvements.setMinimumWidth(150)
        self.improvements.setStyleSheet("color: #88ff88; padding: 5px; border-top: 1px solid #00ffff;")
        layout.addWidget(self.improvements)
        
        self.setLayout(layout)
    
    def update_delta(self, original: int, refined: int, risk_reduction: float,
                    confidence: float, improvements: list):
        self.original_label.setText(f"{original}")
        self.refined_label.setText(f"{refined}")
        self.risk_label.setText(f"{risk_reduction:.1f}%")
        self.confidence_label.setText(f"{confidence:.1f}%")
        
        if improvements:
            self.improvements.setText("✓ " + "\n✓ ".join(improvements[:3]))
        
        self.show()


class ScriptPreviewWidget(QFrame):
    """Widget to preview, export and run PowerShell scripts"""
    
    def __init__(self):
        super().__init__()
        self.current_script = ""
        self.current_tasks = []
        self.current_script_path = None
        self.setup_ui()
    
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
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(8)
        
        header = QHBoxLayout()
        
        title = QLabel("📜 PowerShell Script Preview")
        title.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ffff;")
        header.addWidget(title)
        
        header.addStretch()
        
        self.safe_mode_cb = QCheckBox("🛡️ Safe Mode")
        self.safe_mode_cb.setChecked(True)
        self.safe_mode_cb.setStyleSheet("color: #88ff88;")
        self.safe_mode_cb.stateChanged.connect(self._update_preview)
        header.addWidget(self.safe_mode_cb)
        
        self.save_btn = QPushButton("💾 Export")
        self.save_btn.clicked.connect(self._save_script)
        self.save_btn.setEnabled(False)
        header.addWidget(self.save_btn)
        
        self.run_btn = QPushButton("▶️ Run")
        self.run_btn.clicked.connect(self._run_script)
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
        
        layout.addLayout(header)
        
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
        
        self.tasks_count = QLabel("📋 Tasks: 0")
        self.tasks_count.setStyleSheet("color: #88ff88; font-weight: bold;")
        stats_layout.addWidget(self.tasks_count)
        
        stats_layout.addWidget(QLabel("|"))
        
        self.mode_label = QLabel("🛡️ Safe Mode: Enabled")
        self.mode_label.setStyleSheet("color: #88ff88;")
        stats_layout.addWidget(self.mode_label)
        
        stats_layout.addWidget(QLabel("|"))
        
        self.risk_label = QLabel("📊 Risk: Low")
        self.risk_label.setStyleSheet("color: #88ff88;")
        stats_layout.addWidget(self.risk_label)
        
        stats_layout.addStretch()
        layout.addWidget(self.stats_bar)
        
        self.safety_warning = QLabel()
        self.safety_warning.setWordWrap(True)
        self.safety_warning.setStyleSheet("color: #ff8800; font-weight: bold; padding: 5px; background: #332200; border-radius: 3px;")
        self.safety_warning.hide()
        layout.addWidget(self.safety_warning)
        
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setMinimumHeight(200)
        self.preview.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.preview.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.preview.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        layout.addWidget(self.preview)
        
        self.status_label = QLabel("Select tasks to generate script")
        self.status_label.setStyleSheet("color: #888888; font-style: italic;")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
    
    def _update_preview(self):
        if self.current_tasks:
            self.update_script(self.current_tasks)
    
    def update_script(self, tasks: list):
        self.current_tasks = tasks
        
        if not tasks:
            self.preview.clear()
            self.save_btn.setEnabled(False)
            self.run_btn.setEnabled(False)
            self.status_label.setText("No tasks selected")
            self.safety_warning.hide()
            self.tasks_count.setText("📋 Tasks: 0")
            self.current_script_path = None
            return
        
        safe_mode = self.safe_mode_cb.isChecked()
        self.current_script = ScriptGenerator.generate_script(tasks, safe_mode)
        self.preview.setPlainText(self.current_script)
        self.save_btn.setEnabled(True)
        
        self.current_script_path = ScriptRunner.create_temp_script(self.current_script)
        self.run_btn.setEnabled(self.current_script_path is not None)
        
        self.tasks_count.setText(f"📋 Tasks: {len(tasks)}")
        self.mode_label.setText(f"🛡️ Safe Mode: {'Enabled' if safe_mode else 'Disabled'}")
        
        high_risk = sum(1 for t in tasks if t.risk == RiskLevel.HIGH or t.risk == RiskLevel.CRITICAL)
        if high_risk > 0:
            risk_text = "High"
            self.risk_label.setStyleSheet("color: #ff8800; font-weight: bold;")
        elif sum(1 for t in tasks if t.risk == RiskLevel.MEDIUM) > 0:
            risk_text = "Medium"
            self.risk_label.setStyleSheet("color: #ffff00; font-weight: bold;")
        else:
            risk_text = "Low"
            self.risk_label.setStyleSheet("color: #88ff88;")
        self.risk_label.setText(f"📊 Risk: {risk_text}")
        
        unsafe_commands = []
        for task in tasks:
            is_safe, risk, reason = CommandSafety.is_command_safe(task.original_command)
            if not is_safe:
                unsafe_commands.append((task.description, risk, reason))
        
        if unsafe_commands and not safe_mode:
            warning_text = "⚠️ UNSAFE COMMANDS DETECTED:\n" + "\n".join([
                f"  • {desc} ({risk} risk)" for desc, risk, _ in unsafe_commands
            ])
            self.safety_warning.setText(warning_text)
            self.safety_warning.show()
            self.status_label.setText(f"{len(tasks)} tasks selected ({len(unsafe_commands)} unsafe) - Enable Safe Mode")
            self.status_label.setStyleSheet("color: #ff0000; font-style: italic; font-weight: bold;")
        elif unsafe_commands and safe_mode:
            self.safety_warning.setText(f"⚠️ {len(unsafe_commands)} unsafe commands will be modified for safety")
            self.safety_warning.show()
            self.status_label.setText(f"{len(tasks)} tasks selected (safe mode active)")
            self.status_label.setStyleSheet("color: #88ff88; font-style: italic;")
        else:
            self.safety_warning.hide()
            self.status_label.setText(f"{len(tasks)} safe tasks selected - Ready to export or run")
            self.status_label.setStyleSheet("color: #88ff88; font-style: italic;")
    
    def _save_script(self):
        if not self.current_script:
            return
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"Z-Engine_{timestamp}.ps1"
        
        file_path = ScriptGenerator.save_script(self.current_script, default_name)
        if file_path:
            self.current_script_path = file_path
            QMessageBox.information(self, "Success", f"Script saved to:\n{file_path}")
    
    def _run_script(self):
        if not self.current_script_path or not os.path.exists(self.current_script_path):
            QMessageBox.critical(self, "Error", "No script available to run. Please generate a script first.")
            return
        
        ScriptRunner.run_script(self.current_script_path, self)


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
        layout.setSpacing(4)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        title = QLabel("Z-ENGINE")
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ffff;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        subtitle = QLabel("Generates · Engineers · Deploys")
        subtitle.setFont(QFont("Arial", 10))
        subtitle.setStyleSheet("color: #88ff88;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)
        
        self.score_label = QLabel("--")
        self.score_label.setFont(QFont("Arial", 36, QFont.Weight.Bold))
        self.score_label.setStyleSheet("color: #00ff00; padding: 5px;")
        self.score_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.score_label)
        
        self.setLayout(layout)
    
    def set_score(self, score: int):
        self.score_label.setText(str(score))


class FlowIndicator(QFrame):
    """Shows current stage of the optimization flow"""
    
    def __init__(self):
        super().__init__()
        self.current_stage = 0
        self.stages = ["Scan", "Analyze", "Strategize", "Review", "Refine"]
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
            num_label = QLabel(f"{i+1}")
            num_label.setFixedSize(28, 28)
            num_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            num_label.setStyleSheet("""
                QLabel {
                    background: #2a3a2a;
                    color: #88ff88;
                    border: 2px solid #335533;
                    border-radius: 14px;
                    font-weight: bold;
                }
            """)
            
            name_label = QLabel(stage)
            name_label.setStyleSheet("color: #888888; font-weight: bold;")
            
            container = QWidget()
            container_layout = QHBoxLayout(container)
            container_layout.setContentsMargins(0, 0, 0, 0)
            container_layout.addWidget(num_label)
            container_layout.addWidget(name_label)
            
            self.indicators.append({"num": num_label, "name": name_label, "container": container})
            
            layout.addWidget(container)
            
            if i < len(self.stages) - 1:
                arrow = QLabel("→")
                arrow.setStyleSheet("color: #335533; font-size: 16px; font-weight: bold;")
                layout.addWidget(arrow)
        
        layout.addStretch()
        self.setLayout(layout)
        self.set_stage(0)
    
    def set_stage(self, stage: int):
        self.current_stage = stage
        for i, ind in enumerate(self.indicators):
            if i < stage:
                ind["num"].setStyleSheet("""
                    QLabel {
                        background: #00ff00;
                        color: black;
                        border: 2px solid #00ff00;
                        border-radius: 14px;
                        font-weight: bold;
                    }
                """)
                ind["name"].setStyleSheet("color: #00ff00; font-weight: bold;")
            elif i == stage:
                ind["num"].setStyleSheet("""
                    QLabel {
                        background: #ffff00;
                        color: black;
                        border: 2px solid #ffff00;
                        border-radius: 14px;
                        font-weight: bold;
                    }
                """)
                ind["name"].setStyleSheet("color: #ffff00; font-weight: bold;")
            else:
                ind["num"].setStyleSheet("""
                    QLabel {
                        background: #2a3a2a;
                        color: #666666;
                        border: 2px solid #335533;
                        border-radius: 14px;
                        font-weight: bold;
                    }
                """)
                ind["name"].setStyleSheet("color: #666666; font-weight: bold;")


class StrategyComparisonWidget(QFrame):
    """Widget to display and compare different optimization strategies"""
    
    def __init__(self):
        super().__init__()
        self.strategies = []
        self.selected_index = -1
        self.setup_ui()
    
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
        
        header = QLabel("🎯 Strategy Comparison")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffff;")
        layout.addWidget(header)
        
        subtitle = QLabel("AI evaluated multiple approaches and selected optimal balance")
        subtitle.setStyleSheet("color: #88ff88; font-style: italic; margin-bottom: 10px;")
        layout.addWidget(subtitle)
        
        self.cards_layout = QVBoxLayout()
        self.cards_layout.setSpacing(8)
        layout.addLayout(self.cards_layout)
        
        self.reasoning_label = QLabel()
        self.reasoning_label.setWordWrap(True)
        self.reasoning_label.setMinimumWidth(200)
        self.reasoning_label.setStyleSheet("color: #ffff88; padding: 10px; border-top: 1px solid #335533; margin-top: 10px;")
        layout.addWidget(self.reasoning_label)
        
        self.setLayout(layout)
    
    def update_strategies(self, strategies: list, selected_index: int, reasoning: str):
        self.strategies = strategies
        self.selected_index = selected_index
        
        self._clear_layout(self.cards_layout)
        
        for i, strategy in enumerate(strategies):
            card = self._create_strategy_card(strategy, i == selected_index)
            self.cards_layout.addWidget(card)
        
        self.reasoning_label.setText(f"🧠 AI Reasoning: {reasoning}")
        self.show()
    
    def _create_strategy_card(self, strategy, is_selected):
        card = QFrame()
        card.setObjectName("strategy_card")
        card.setProperty("selected", is_selected)
        card.setFrameStyle(QFrame.Shape.Box)
        
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
        
        header_layout = QHBoxLayout()
        
        name = QLabel(strategy.name)
        name.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        name.setStyleSheet("color: white;")
        header_layout.addWidget(name)
        
        if is_selected:
            selected_badge = QLabel("✓ SELECTED")
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
        
        stats_layout = QGridLayout()
        stats_layout.setHorizontalSpacing(15)
        
        gain_label = QLabel("Gain:")
        gain_label.setStyleSheet("color: #88ff88;")
        stats_layout.addWidget(gain_label, 0, 0)
        
        gain_value = QLabel(f"+{strategy.gain}")
        gain_value.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        gain_value.setStyleSheet("color: #00ff00;")
        stats_layout.addWidget(gain_value, 0, 1)
        
        risk_label = QLabel("Risk:")
        risk_label.setStyleSheet("color: #ff8888;")
        stats_layout.addWidget(risk_label, 0, 2)
        
        risk_color = {
            "Very Low": "#88ff88", "Low": "#88ff88", "Medium": "#ffff00",
            "High": "#ff8800", "Critical": "#ff0000"
        }.get(strategy.risk_level, "#ffffff")
        
        risk_value = QLabel(strategy.risk_level)
        risk_value.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        risk_value.setStyleSheet(f"color: {risk_color};")
        stats_layout.addWidget(risk_value, 0, 3)
        
        confidence_label = QLabel("Confidence:")
        confidence_label.setStyleSheet("color: #8888ff;")
        stats_layout.addWidget(confidence_label, 1, 0)
        
        confidence_value = QLabel(f"{strategy.confidence}%")
        confidence_value.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        confidence_value.setStyleSheet("color: #8888ff;")
        stats_layout.addWidget(confidence_value, 1, 1)
        
        ratio_label = QLabel("Gain/Risk:")
        ratio_label.setStyleSheet("color: #ff88ff;")
        stats_layout.addWidget(ratio_label, 1, 2)
        
        ratio_value = QLabel(f"{strategy.stability_risk_ratio:.2f}")
        ratio_value.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        ratio_value.setStyleSheet("color: #ff88ff;")
        stats_layout.addWidget(ratio_value, 1, 3)
        
        stats_layout.setColumnStretch(4, 1)
        layout.addLayout(stats_layout)
        
        if strategy.description:
            desc = QLabel(strategy.description)
            desc.setWordWrap(True)
            desc.setMinimumWidth(200)
            desc.setStyleSheet("color: #cccccc; font-style: italic; padding: 5px;")
            layout.addWidget(desc)
        
        card.setLayout(layout)
        return card
    
    def _clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()


class ScriptDiffWidget(QFrame):
    """Widget to show differences between original and refined plans"""
    
    def __init__(self):
        super().__init__()
        self.diff_data = None
        self.setup_ui()
    
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
        
        header = QLabel("🔄 Plan Comparison: Original vs Refined")
        header.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffff;")
        layout.addWidget(header)
        
        self.stats_label = QLabel()
        self.stats_label.setWordWrap(True)
        self.stats_label.setMinimumWidth(200)
        self.stats_label.setStyleSheet("color: #88ff88; padding: 5px; background: #0a1a0a; border-radius: 3px;")
        layout.addWidget(self.stats_label)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setMinimumHeight(150)
        scroll.setStyleSheet("border: 1px solid #335533; border-radius: 3px;")
        
        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setSpacing(8)
        scroll.setWidget(self.content)
        layout.addWidget(scroll)
        
        self.setLayout(layout)
    
    def update_diff(self, original_tasks: list, refined_tasks: list):
        self.stats_label.setText(f"📊 Original: {len(original_tasks)} tasks | Refined: {len(refined_tasks)} tasks")
        self.show()


class ThreeBarChartWidget(QFrame):
    """Widget showing before vs after comparison with 3 bars"""
    
    def __init__(self):
        super().__init__()
        self.current_score = None
        self.original_projected = None
        self.refined_projected = None
        self.live_projected = None
        self._refresh_attempts = 0
        self._max_refresh_attempts = 10
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
        
        header = QLabel("System Stability Improvement")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ff00;")
        layout.addWidget(header)
        
        self.subtitle = QLabel("AI reasoning improves system stability")
        self.subtitle.setStyleSheet("color: #88ff88; font-style: italic; margin-bottom: 10px;")
        layout.addWidget(self.subtitle)
        
        chart_widget = QWidget()
        chart_layout = QVBoxLayout(chart_widget)
        chart_layout.setSpacing(15)
        
        # Bar 1 - Current Score
        bar1_layout = QHBoxLayout()
        bar1_layout.addWidget(QLabel("Current"), 1)
        self.bar1_container = QWidget()
        self.bar1_container.setMinimumHeight(25)
        self.bar1_container.setStyleSheet("background: #2a2a2a; border-radius: 3px;")
        bar1_container_layout = QHBoxLayout(self.bar1_container)
        bar1_container_layout.setContentsMargins(0, 0, 0, 0)
        self.bar1 = QFrame()
        self.bar1.setFixedHeight(25)
        self.bar1.setStyleSheet("background: #00ff00; border-radius: 3px;")
        bar1_container_layout.addWidget(self.bar1)
        bar1_container_layout.addStretch()
        self.bar1_label = QLabel("0")
        self.bar1_label.setFixedWidth(40)
        self.bar1_label.setStyleSheet("color: white; font-weight: bold;")
        bar1_layout.addWidget(self.bar1_container, 8)
        bar1_layout.addWidget(self.bar1_label, 1)
        chart_layout.addLayout(bar1_layout)
        
        # Bar 2 - Original Plan
        bar2_layout = QHBoxLayout()
        bar2_layout.addWidget(QLabel("AI Plan"), 1)
        self.bar2_container = QWidget()
        self.bar2_container.setMinimumHeight(25)
        self.bar2_container.setStyleSheet("background: #2a2a2a; border-radius: 3px;")
        bar2_container_layout = QHBoxLayout(self.bar2_container)
        bar2_container_layout.setContentsMargins(0, 0, 0, 0)
        self.bar2 = QFrame()
        self.bar2.setFixedHeight(25)
        self.bar2.setStyleSheet("background: #ffaa00; border-radius: 3px;")
        bar2_container_layout.addWidget(self.bar2)
        bar2_container_layout.addStretch()
        self.bar2_label = QLabel("0")
        self.bar2_label.setFixedWidth(40)
        self.bar2_label.setStyleSheet("color: white; font-weight: bold;")
        bar2_layout.addWidget(self.bar2_container, 8)
        bar2_layout.addWidget(self.bar2_label, 1)
        chart_layout.addLayout(bar2_layout)
        
        # Bar 3 - Refined Plan
        bar3_layout = QHBoxLayout()
        bar3_layout.addWidget(QLabel("Refined"), 1)
        self.bar3_container = QWidget()
        self.bar3_container.setMinimumHeight(25)
        self.bar3_container.setStyleSheet("background: #2a2a2a; border-radius: 3px;")
        bar3_container_layout = QHBoxLayout(self.bar3_container)
        bar3_container_layout.setContentsMargins(0, 0, 0, 0)
        self.bar3 = QFrame()
        self.bar3.setFixedHeight(25)
        self.bar3.setStyleSheet("background: #00ffff; border-radius: 3px;")
        bar3_container_layout.addWidget(self.bar3)
        bar3_container_layout.addStretch()
        self.bar3_label = QLabel("0")
        self.bar3_label.setFixedWidth(40)
        self.bar3_label.setStyleSheet("color: white; font-weight: bold;")
        bar3_layout.addWidget(self.bar3_container, 8)
        bar3_layout.addWidget(self.bar3_label, 1)
        chart_layout.addLayout(bar3_layout)
        
        # Bar 4 - Live Selection
        bar4_layout = QHBoxLayout()
        bar4_layout.addWidget(QLabel("Selection"), 1)
        self.bar4_container = QWidget()
        self.bar4_container.setMinimumHeight(25)
        self.bar4_container.setStyleSheet("background: #2a2a2a; border-radius: 3px;")
        bar4_container_layout = QHBoxLayout(self.bar4_container)
        bar4_container_layout.setContentsMargins(0, 0, 0, 0)
        self.bar4 = QFrame()
        self.bar4.setFixedHeight(25)
        self.bar4.setStyleSheet("background: #ffff00; border-radius: 3px;")
        bar4_container_layout.addWidget(self.bar4)
        bar4_container_layout.addStretch()
        self.bar4_label = QLabel("0")
        self.bar4_label.setFixedWidth(40)
        self.bar4_label.setStyleSheet("color: white; font-weight: bold;")
        bar4_layout.addWidget(self.bar4_container, 8)
        bar4_layout.addWidget(self.bar4_label, 1)
        chart_layout.addLayout(bar4_layout)
        self.bar4_container.hide()
        
        self.gain_label = QLabel()
        self.gain_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.gain_label.setStyleSheet("color: #00ff00; font-weight: bold; padding: 2px;")
        chart_layout.addWidget(self.gain_label)
        
        chart_layout.addStretch()
        layout.addWidget(chart_widget)
        self.setLayout(layout)
    
    def update_scores(self, current: int, original_projected: int = None,
                     refined_projected: int = None, live_projected: int = None):
        self.current_score = current
        self.original_projected = original_projected
        self.refined_projected = refined_projected
        self.live_projected = live_projected
        self._refresh_attempts = 0
        
        if current:
            self.bar1_label.setText(str(current))
        if original_projected:
            self.bar2_label.setText(str(original_projected))
        if refined_projected:
            self.bar3_label.setText(str(refined_projected))
        
        if live_projected and live_projected not in [current, original_projected, refined_projected]:
            self.bar4_container.show()
            self.bar4_label.setText(str(live_projected))
        else:
            self.bar4_container.hide()
        
        if current and refined_projected:
            gain = refined_projected - current
            if gain > 0:
                self.gain_label.setText(f"+{gain} points")
                self.gain_label.setStyleSheet("color: #00ff00; font-weight: bold; padding: 2px;")
            else:
                self.gain_label.setText("")
        
        self.show()
        self._refresh_bars()
    
    def _refresh_bars(self):
        w = self.bar1_container.width()
        if w <= 0:
            self._refresh_attempts += 1
            if self._refresh_attempts < self._max_refresh_attempts:
                QTimer.singleShot(100, self._refresh_bars)
            return
        
        self._refresh_attempts = 0
        
        if self.current_score:
            self.bar1.setFixedWidth(int(w * self.current_score / 100))
        
        w = self.bar2_container.width()
        if w > 0 and self.original_projected:
            self.bar2.setFixedWidth(int(w * self.original_projected / 100))
        
        w = self.bar3_container.width()
        if w > 0 and self.refined_projected:
            self.bar3.setFixedWidth(int(w * self.refined_projected / 100))
        
        if self.bar4_container.isVisible():
            w = self.bar4_container.width()
            if w > 0 and self.live_projected:
                self.bar4.setFixedWidth(int(w * self.live_projected / 100))
    
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._refresh_bars()
    
    def showEvent(self, event):
        super().showEvent(event)
        self._refresh_bars()
