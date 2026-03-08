"""
Dialog windows for Z-Engine
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QTabWidget, QTableWidget, QTableWidgetItem, QWidget,
    QTextEdit, QTreeWidget, QTreeWidgetItem, QDialogButtonBox,
    QPushButton
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont
from typing import Dict, Any, List


class SystemDetailsDialog(QDialog):
    def __init__(self, snapshot: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.snapshot = snapshot
        self.setWindowTitle("System Details - Z-Engine")
        self.setGeometry(200, 200, 800, 600)
        self.setStyleSheet("""
            QDialog {
                background-color: #1a1a1a;
            }
            QLabel {
                color: white;
            }
            QTabWidget::pane {
                border: 2px solid #00ff00;
                border-radius: 5px;
                background: #1a1a1a;
            }
            QTabBar::tab {
                background-color: #2a2a2a;
                color: white;
                border: 1px solid #00ff00;
                padding: 5px 10px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #00ff00;
                color: black;
            }
            QTableWidget {
                background-color: #2a2a2a;
                color: white;
                border: 1px solid #00ff00;
            }
            QHeaderView::section {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #00ff00;
            }
            QPushButton {
                background-color: #2a2a2a;
                color: white;
                border: 1px solid #00ff00;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #3a3a3a;
            }
        """)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        tabs = QTabWidget()
        
        sys_tab = QWidget()
        sys_layout = QVBoxLayout(sys_tab)
        sys_layout.setSpacing(8)
        
        if self.snapshot.get("error"):
            sys_layout.addWidget(QLabel(f"Error: {self.snapshot['error']}"))
        else:
            grid = QGridLayout()
            grid.setHorizontalSpacing(15)
            grid.setVerticalSpacing(8)
            row = 0
            
            sys_info = self.snapshot.get("system", {})
            sys_items = [
                ("OS", sys_info.get("os", "Unknown")),
                ("Processor", sys_info.get("processor", "Unknown")[:60]),
                ("Hostname", sys_info.get("hostname", "Unknown")),
                ("Boot Time", sys_info.get("boot_time", "Unknown")),
                ("Uptime", f"{sys_info.get('uptime_days', 0)} days")
            ]
            
            for label, value in sys_items:
                lbl = QLabel(f"{label}:")
                lbl.setStyleSheet("font-weight: bold; color: #00ff00;")
                grid.addWidget(lbl, row, 0)
                val = QLabel(str(value))
                val.setStyleSheet("color: white;")
                grid.addWidget(val, row, 1)
                row += 1
            
            cpu_info = self.snapshot.get("cpu", {})
            if cpu_info:
                cpu_label = QLabel("CPU:")
                cpu_label.setStyleSheet("font-weight: bold; color: #00ff00; margin-top: 10px;")
                sys_layout.addWidget(cpu_label)
                
                cpu_items = [
                    ("Cores", f"{cpu_info.get('cores_physical', 0)} physical / {cpu_info.get('cores_logical', 0)} logical"),
                    ("Usage", f"{cpu_info.get('usage_percent', 0)}%"),
                    ("Frequency", f"{cpu_info.get('frequency_mhz', 'Unknown')} MHz")
                ]
                
                for label, value in cpu_items:
                    hbox = QHBoxLayout()
                    hbox.addWidget(QLabel(f"  {label}:"))
                    hbox.addWidget(QLabel(str(value)))
                    hbox.addStretch()
                    sys_layout.addLayout(hbox)
            
            mem_info = self.snapshot.get("memory", {})
            if mem_info:
                mem_label = QLabel("Memory:")
                mem_label.setStyleSheet("font-weight: bold; color: #00ff00; margin-top: 10px;")
                sys_layout.addWidget(mem_label)
                
                mem_items = [
                    ("Total", f"{mem_info.get('total_gb', 0)} GB"),
                    ("Used", f"{mem_info.get('used_gb', 0)} GB ({mem_info.get('usage_percent', 0)}%)"),
                    ("Swap", f"{mem_info.get('swap_used_gb', 0)} GB / {mem_info.get('swap_total_gb', 0)} GB")
                ]
                
                for label, value in mem_items:
                    hbox = QHBoxLayout()
                    hbox.addWidget(QLabel(f"  {label}:"))
                    hbox.addWidget(QLabel(str(value)))
                    hbox.addStretch()
                    sys_layout.addLayout(hbox)
        
        sys_layout.addStretch()
        tabs.addTab(sys_tab, "System")
        
        storage_tab = QWidget()
        storage_layout = QVBoxLayout(storage_tab)
        storage_layout.setSpacing(8)
        storage_table = QTableWidget()
        storage_table.setColumnCount(4)
        storage_table.setHorizontalHeaderLabels(["Drive", "Total (GB)", "Used %", "Free (GB)"])
        
        storage_data = self.snapshot.get("storage", [])
        storage_table.setRowCount(len(storage_data))
        
        for i, disk in enumerate(storage_data):
            storage_table.setItem(i, 0, QTableWidgetItem(disk.get("drive", "")))
            storage_table.setItem(i, 1, QTableWidgetItem(str(disk.get("total", 0))))
            storage_table.setItem(i, 2, QTableWidgetItem(f"{disk.get('percent', 0)}%"))
            storage_table.setItem(i, 3, QTableWidgetItem(str(disk.get("free", 0))))
        
        storage_table.resizeColumnsToContents()
        storage_layout.addWidget(storage_table)
        tabs.addTab(storage_tab, "Storage")
        
        proc_tab = QWidget()
        proc_layout = QVBoxLayout(proc_tab)
        proc_layout.setSpacing(8)
        proc_table = QTableWidget()
        proc_table.setColumnCount(2)
        proc_table.setHorizontalHeaderLabels(["Process", "Memory %"])
        
        proc_data = self.snapshot.get("processes", [])
        proc_table.setRowCount(len(proc_data))
        
        for i, proc in enumerate(proc_data):
            proc_table.setItem(i, 0, QTableWidgetItem(proc.get("name", "")))
            proc_table.setItem(i, 1, QTableWidgetItem(str(proc.get("mem", 0))))
        
        proc_table.resizeColumnsToContents()
        proc_layout.addWidget(proc_table)
        tabs.addTab(proc_tab, "Top Processes")
        
        layout.addWidget(tabs)
        
        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btn_box.rejected.connect(self.accept)
        layout.addWidget(btn_box)


class ThoughtTraceWidget(QWidget):
    closed = Signal()
    
    def __init__(self):
        super().__init__()
        # Add this line right after super().__init__()
        self.setWindowFlags(Qt.WindowType.Window)
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle("AI Reasoning Trace - Z-Engine")
        self.setGeometry(100, 100, 600, 400)
        self.setStyleSheet("""
            QWidget {
                background-color: #1a1a1a;
            }
            QLabel {
                color: white;
            }
            QTreeWidget {
                background-color: #2a2a2a;
                color: white;
                border: 1px solid #00ff00;
            }
            QTextEdit {
                background-color: #2a2a2a;
                color: #00ff00;
                border: 1px solid #00ff00;
                font-family: monospace;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        
        header = QLabel("🧠 AI Reasoning Trace")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffff;")
        layout.addWidget(header)
        
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Stage", "Status", "Time", "Summary"])
        layout.addWidget(self.tree)
        
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(150)
        layout.addWidget(self.detail)
        
        self.tree.itemClicked.connect(self._show_trace_detail)
    
    def closeEvent(self, event):
        self.closed.emit()
        super().closeEvent(event)
    
    def _show_trace_detail(self, item):
        entry = item.data(0, Qt.ItemDataRole.UserRole)
        if not entry:
            return
        
        detail = f"""
=== {entry.get('pass', 'Unknown')} ===
Time: {entry.get('timestamp', 'Unknown')}
Status: {entry.get('status', 'Unknown')}

=== REQUEST ===
{entry.get('request', 'No request')}

=== RESPONSE ===
{entry.get('response', 'No response')}

=== ERROR ===
{entry.get('error', 'None')}
"""
        self.detail.setText(detail)
    
    def update_trace(self, trace: List[Dict]):
        self.tree.clear()
        
        for entry in trace:
            item = QTreeWidgetItem()
            item.setText(0, entry.get("pass", "Unknown"))
            item.setText(1, entry.get("status", "unknown").upper())
            item.setText(2, entry.get("timestamp", "")[11:19])
            
            if entry.get("status") == "success":
                item.setForeground(1, QBrush(QColor("#00ff00")))
            elif entry.get("status") == "error":
                item.setForeground(1, QBrush(QColor("#ff0000")))
            
            summary = entry.get("request", "")[:60] + "..." if len(entry.get("request", "")) > 60 else entry.get("request", "")
            item.setText(3, summary)
            
            item.setData(0, Qt.ItemDataRole.UserRole, entry)
            self.tree.addTopLevelItem(item)
