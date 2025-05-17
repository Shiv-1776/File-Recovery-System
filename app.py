import sys
import os
import hashlib
import threading
import psutil
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QTextEdit,
    QVBoxLayout, QFileDialog, QMessageBox, QHBoxLayout, QCheckBox, QProgressBar, QComboBox
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject
from PyQt5.QtGui import QFont
from PIL import Image
from monitor import start_monitoring
from recovery import recover_raw_files

class GuiCommunicator(QObject):
    log_signal = pyqtSignal(str)
    alert_signal = pyqtSignal(str, str)
    recovery_status_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)

class SmartGuardApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SmartGuard: File Corruption & Recovery System")
        self.setGeometry(200, 200, 750, 600)
        self.selected_file = None
        self.raw_output_folder = None
        self.dark_mode = False

        self.comm = GuiCommunicator()
        self.comm.log_signal.connect(self.log_message)
        self.comm.alert_signal.connect(self.show_alert)
        self.comm.recovery_status_signal.connect(self.update_recovery_status)
        self.comm.progress_signal.connect(self.update_progress)

        self.initUI()
        start_monitoring(self)
        self.set_high_priority()

    def initUI(self):
        self.set_dark_mode(self.dark_mode)

        # Header
        header = QLabel("🛡️ SmartGuard")
        header.setFont(QFont("Segoe UI", 24, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)

        sub_label = QLabel("Corruption Detection • Raw Deleted File Recovery")
        sub_label.setAlignment(Qt.AlignCenter)
        sub_label.setFont(QFont("Segoe UI", 11))
        sub_label.setStyleSheet("color: gray;")

        # Main buttons
        self.select_button = QPushButton(" Select File")
        self.select_button.clicked.connect(self.select_file)

        self.check_button = QPushButton(" Check Integrity")
        self.check_button.setEnabled(False)
        self.check_button.clicked.connect(self.start_check)

        self.monitor_button = QPushButton(" Select Folder to Monitor")
        self.monitor_button.clicked.connect(self.select_monitor_folder)

        self.theme_switch = QCheckBox("🌙 Dark Mode")
        self.theme_switch.setChecked(self.dark_mode)
        self.theme_switch.stateChanged.connect(self.toggle_theme)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.select_button)
        button_layout.addWidget(self.check_button)
        button_layout.addWidget(self.monitor_button)
        button_layout.addStretch()
        button_layout.addWidget(self.theme_switch)

        # Raw recovery controls
        self.drive_selector = QComboBox()
        self.drive_selector.addItems([d + ":" for d in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(d + ":\\")])
        self.drive_selector.setFixedWidth(70)

        self.raw_output_button = QPushButton(" Set Output Folder")
        self.raw_output_button.clicked.connect(self.select_raw_output_folder)

        self.raw_recover_button = QPushButton(" Recover Raw Files")
        self.raw_recover_button.clicked.connect(self.trigger_raw_recovery)

        raw_layout = QHBoxLayout()
        raw_layout.addWidget(QLabel("Drive:"))
        raw_layout.addWidget(self.drive_selector)
        raw_layout.addWidget(self.raw_output_button)
        raw_layout.addWidget(self.raw_recover_button)

        # Logs, progress, and status
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setFont(QFont("Consolas", 11))

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setVisible(True)

        self.recovery_status = QLabel("Recovery Status: None")
        self.recovery_status.setAlignment(Qt.AlignCenter)
        self.recovery_status.setStyleSheet("font-weight: bold; color: #555;")

        layout = QVBoxLayout()
        layout.addWidget(header)
        layout.addWidget(sub_label)
        layout.addLayout(button_layout)
        layout.addLayout(raw_layout)
        layout.addWidget(self.log_box)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.recovery_status)

        self.setLayout(layout)

    def set_dark_mode(self, enabled):
        self.setStyleSheet("""
            QWidget { background-color: #121212; color: #eeeeee; }
            QTextEdit { background-color: #1e1e1e; color: #eeeeee; }
            QPushButton { background-color: #3a3a3a; color: #eeeeee; }
            QPushButton:hover { background-color: #4c4c4c; }
            QProgressBar { background-color: #2c2c2c; color: white; }
            QCheckBox, QComboBox { color: #eeeeee; }
        """ if enabled else "")

    def toggle_theme(self, state):
        self.dark_mode = bool(state)
        self.set_dark_mode(self.dark_mode)

    def set_high_priority(self):
        try:
            pid = os.getpid()
            p = psutil.Process(pid)
            p.nice(psutil.REALTIME_PRIORITY_CLASS)
            self.comm.log_signal.emit("[PRIORITY] Process priority set to REALTIME.")
        except Exception as e:
            self.comm.log_signal.emit(f"[WARNING] Could not set priority: {e}")

    def log_message(self, text):
        self.log_box.append(text)

    def update_recovery_status(self, message):
        self.recovery_status.setText(f"Recovery Status: {message}")

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def select_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select a File")
        if path:
            self.selected_file = path
            self.comm.log_signal.emit(f"[SELECTED] File: {path}")
            self.check_button.setEnabled(True)

    def select_monitor_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select Folder to Monitor")
        if path:
            self.comm.log_signal.emit(f"[INFO] Monitoring folder set to: {path}")
            start_monitoring(self, path)

    def select_raw_output_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select Output Folder for Raw Files")
        if path:
            self.raw_output_folder = path
            self.comm.log_signal.emit(f"[INFO] Raw output folder set to: {path}")

    def start_check(self):
        if self.selected_file:
            self.comm.log_signal.emit("[ACTION] Starting file integrity check...")
            thread = threading.Thread(target=self.check_file_corruption, args=(self.selected_file,))
            thread.start()

    def check_file_corruption(self, path=None):
        try:
            file_path = path or self.selected_file
            size = os.path.getsize(file_path)
            with open(file_path, 'rb') as f:
                data = f.read()
                file_hash = hashlib.sha256(data).hexdigest()

            self.comm.log_signal.emit(f"File Size: {size} bytes")
            self.comm.log_signal.emit(f"SHA-256: {file_hash}")

            if self.check_corruption(file_path):
                self.comm.log_signal.emit("[RESULT] File is CORRUPTED.")
                self.comm.alert_signal.emit("This file may be corrupted. Do you want to attempt recovery?", file_path)
            else:
                self.comm.log_signal.emit("[RESULT] File is NOT corrupted.")
        except Exception as e:
            self.comm.log_signal.emit(f"[ERROR] {e}")

    def check_corruption(self, file_path):
        try:
            size = os.path.getsize(file_path)
            if size == 0:
                return True
            ext = os.path.splitext(file_path)[1].lower()
            if ext in ['.jpg', '.jpeg', '.png']:
                with Image.open(file_path) as img:
                    img.verify()
                return False
            elif ext == '.pdf':
                with open(file_path, 'rb') as f:
                    return not f.read(4).startswith(b'%PDF')
            elif ext in ['.zip', '.docx']:
                with open(file_path, 'rb') as f:
                    return not f.read(4).startswith(b'PK\x03\x04')
            return False
        except Exception:
            return True

    def show_alert(self, message, file_path):
        reply = QMessageBox.question(self, "Corruption Detected", message,
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if reply == QMessageBox.Yes:
            self.log_message(f"[ACTION] Recovery triggered for: {file_path}")
            self.comm.recovery_status_signal.emit("Recovery started...")

    def trigger_raw_recovery(self):
        if not self.raw_output_folder:
            self.comm.log_signal.emit("[ERROR] Please set output folder for raw recovery.")
            return
        drive = self.drive_selector.currentText().strip(":")
        thread = threading.Thread(target=recover_raw_files, args=(self.comm, drive, self.raw_output_folder))
        thread.start()

    def closeEvent(self, event):
        reply = QMessageBox.question(self, "Exit SmartGuard", "Are you sure you want to exit?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
            QApplication.quit()
        else:
            event.ignore()

if __name__ == "__main__":
    import ctypes
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    if not is_admin():
        try:
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        except Exception as e:
            print(f"Failed to elevate privileges: {e}")
        sys.exit(0)
    else:
        app = QApplication(sys.argv)
        window = SmartGuardApp()
        window.show()
        sys.exit(app.exec_())
