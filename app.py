import sys
import os
import hashlib
import threading
import psutil
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QTextEdit,
    QVBoxLayout, QFileDialog, QMessageBox, QHBoxLayout, QCheckBox, QProgressBar, QComboBox,
    QFrame, QSplitter
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QIcon, QPixmap, QPalette, QColor
from PIL import Image
from monitor import start_monitoring
from recovery import recover_raw_files
from file_recovery import recover_file  # Import the new recovery module

# Theme Colors
THEME_BLACK = "#121212"
THEME_DARKER = "#0a0a0a"
THEME_DARK_GRAY = "#1e1e1e"
THEME_MEDIUM_GRAY = "#2d2d2d"
THEME_ACCENT_RED = "#8b0000"  # Dark red
THEME_ACCENT_RED_HOVER = "#a50000"
THEME_WHITE = "#f5f5f5"
THEME_LIGHT_GRAY = "#cccccc"

class StyledButton(QPushButton):
    """Custom styled button with hover effects"""
    def __init__(self, text="", icon=None, parent=None):
        super(StyledButton, self).__init__(text, parent)
        self.setFont(QFont("Segoe UI", 10))
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(40)
        
        # Apply styling
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {THEME_ACCENT_RED}; 
                color: {THEME_WHITE};
                border: none;
                border-radius: 3px;
                padding: 8px 16px;
                text-align: left;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {THEME_ACCENT_RED_HOVER};
            }}
            QPushButton:pressed {{
                background-color: {THEME_ACCENT_RED};
            }}
            QPushButton:disabled {{
                background-color: {THEME_MEDIUM_GRAY};
                color: {THEME_LIGHT_GRAY};
            }}
        """)
        
        if icon:
            self.setIcon(icon)
            self.setIconSize(QSize(18, 18))

class GuiCommunicator(QObject):
    log_signal = pyqtSignal(str)
    alert_signal = pyqtSignal(str, str)
    recovery_status_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)

class SmartGuardApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SmartGuard: Advanced File Recovery System")
        self.setGeometry(200, 100, 1200, 800)
        self.selected_file = None
        self.raw_output_folder = None
        
        # Set app icon
        self.setWindowIcon(QIcon("shield_icon.png"))  # Add an icon file to your project
        
        self.comm = GuiCommunicator()
        self.comm.log_signal.connect(self.log_message)
        self.comm.alert_signal.connect(self.show_alert)
        self.comm.recovery_status_signal.connect(self.update_recovery_status)
        self.comm.progress_signal.connect(self.update_progress)

        self.initUI()
        start_monitoring(self)
        self.set_high_priority()

    def initUI(self):
        # Apply global dark styling
        self.setStyleSheet(f"""
            QWidget {{ 
                background-color: {THEME_BLACK}; 
                color: {THEME_WHITE}; 
                font-family: 'Segoe UI';
            }}
            QTextEdit {{ 
                background-color: {THEME_DARK_GRAY}; 
                color: {THEME_WHITE}; 
                border: 1px solid {THEME_MEDIUM_GRAY};
                border-radius: 5px;
                padding: 5px;
            }}
            QLabel {{ color: {THEME_WHITE}; }}
            QProgressBar {{
                border: 1px solid {THEME_MEDIUM_GRAY};
                border-radius: 3px;
                background-color: {THEME_DARK_GRAY};
                color: {THEME_WHITE};
                text-align: center;
            }}
            QProgressBar::chunk {{
                background-color: {THEME_ACCENT_RED};
                width: 10px;
            }}
            QComboBox {{
                background-color: {THEME_MEDIUM_GRAY};
                color: {THEME_WHITE};
                border: 1px solid {THEME_DARK_GRAY};
                border-radius: 3px;
                padding: 5px;
            }}
            QComboBox QAbstractItemView {{
                background-color: {THEME_DARK_GRAY};
                color: {THEME_WHITE};
                selection-background-color: {THEME_ACCENT_RED};
            }}
            QCheckBox {{
                color: {THEME_WHITE};
                spacing: 5px;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
            }}
            QCheckBox::indicator:checked {{
                background-color: {THEME_ACCENT_RED};
                border: 2px solid {THEME_WHITE};
            }}
            QSplitter::handle {{
                background-color: {THEME_MEDIUM_GRAY};
            }}
            QFrame#separator {{
                background-color: {THEME_ACCENT_RED};
            }}
        """)

        # Main layout with splitter
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        
        splitter = QSplitter(Qt.Horizontal)
        
        # Left side - Logo, stats and log
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(15)
        
        # Logo and title
        title_layout = QHBoxLayout()
        
        # Create the logo (a stylized "S" as shield)
        logo_label = QLabel()
        # You can replace this with actual logo file
        # logo_label.setPixmap(QPixmap("smartguard_logo.png").scaled(80, 80, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo_label.setStyleSheet(f"""
            background-color: {THEME_ACCENT_RED};
            border-radius: 40px;
            color: white;
            font-size: 32px;
            font-weight: bold;
        """)
        logo_label.setFixedSize(80, 80)
        logo_label.setAlignment(Qt.AlignCenter)
        logo_label.setText("S")
        
        title_text = QVBoxLayout()
        title = QLabel("SMARTGUARD")
        title.setFont(QFont("Segoe UI", 24, QFont.Bold))
        subtitle = QLabel("Advanced File Protection System")
        subtitle.setFont(QFont("Segoe UI", 12))
        subtitle.setStyleSheet(f"color: {THEME_ACCENT_RED};")
        
        title_text.addWidget(title)
        title_text.addWidget(subtitle)
        title_text.setSpacing(5)
        
        title_layout.addWidget(logo_label)
        title_layout.addLayout(title_text)
        title_layout.addStretch()
        
        left_layout.addLayout(title_layout)
        
        # Add a styled separator
        separator = QFrame()
        separator.setObjectName("separator")
        separator.setFrameShape(QFrame.HLine)
        separator.setFixedHeight(2)
        left_layout.addWidget(separator)
        
        # Status panel
        status_frame = QFrame()
        status_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {THEME_DARK_GRAY}; 
                border-radius: 5px;
                padding: 10px;
            }}
        """)
        status_layout = QVBoxLayout(status_frame)
        
        self.recovery_status = QLabel("Recovery Status: None")
        self.recovery_status.setFont(QFont("Segoe UI", 11))
        self.recovery_status.setStyleSheet(f"color: {THEME_WHITE}; font-weight: bold;")
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(10)
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        
        status_layout.addWidget(self.recovery_status)
        status_layout.addWidget(self.progress_bar)
        
        left_layout.addWidget(status_frame)
        
        # Log box with title
        log_title = QLabel("ACTIVITY LOG")
        log_title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        left_layout.addWidget(log_title)
        
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setFont(QFont("Consolas", 10))
        self.log_box.setMinimumWidth(500)
        self.log_box.setStyleSheet(f"""
            QTextEdit {{
                background-color: {THEME_DARKER};
                border: 1px solid {THEME_MEDIUM_GRAY};
                border-radius: 5px;
                padding: 10px;
                color: {THEME_WHITE};
            }}
        """)
        
        left_layout.addWidget(self.log_box)
        
        # Right side - Controls
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(20)
        
        # Control categories
        file_section_label = QLabel("FILE OPERATIONS")
        file_section_label.setFont(QFont("Segoe UI", 12, QFont.Bold))
        file_section_label.setStyleSheet(f"color: {THEME_ACCENT_RED};")
        right_layout.addWidget(file_section_label)
        
        # File operations buttons
        self.select_button = StyledButton(" Select File")
        self.select_button.clicked.connect(self.select_file)
        
        self.check_button = StyledButton(" Check Integrity")
        self.check_button.setEnabled(False)
        self.check_button.clicked.connect(self.start_check)
        
        self.monitor_button = StyledButton(" Select Folder to Monitor")
        self.monitor_button.clicked.connect(self.select_monitor_folder)
        
        right_layout.addWidget(self.select_button)
        right_layout.addWidget(self.check_button)
        right_layout.addWidget(self.monitor_button)
        
        # Add spacer
        right_layout.addSpacing(10)
        
        # Recovery section
        recovery_section_label = QLabel("RECOVERY OPTIONS")
        recovery_section_label.setFont(QFont("Segoe UI", 12, QFont.Bold))
        recovery_section_label.setStyleSheet(f"color: {THEME_ACCENT_RED};")
        right_layout.addWidget(recovery_section_label)
        
        # Drive selector with label
        drive_layout = QHBoxLayout()
        drive_label = QLabel("Select Drive:")
        drive_label.setFixedWidth(100)
        self.drive_selector = QComboBox()
        self.drive_selector.addItems([d + ":" for d in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(d + ":\\")])
        self.drive_selector.setFixedHeight(40)
        
        drive_layout.addWidget(drive_label)
        drive_layout.addWidget(self.drive_selector)
        right_layout.addLayout(drive_layout)
        
        # Raw recovery buttons
        self.raw_output_button = StyledButton(" Set Output Folder")
        self.raw_output_button.clicked.connect(self.select_raw_output_folder)
        
        self.raw_recover_button = StyledButton(" Recover Raw Files")
        self.raw_recover_button.clicked.connect(self.trigger_raw_recovery)
        
        right_layout.addWidget(self.raw_output_button)
        right_layout.addWidget(self.raw_recover_button)
        
        # Add spacer
        right_layout.addSpacing(10)
        
        # Settings section
        settings_section_label = QLabel("SETTINGS")
        settings_section_label.setFont(QFont("Segoe UI", 12, QFont.Bold))
        settings_section_label.setStyleSheet(f"color: {THEME_ACCENT_RED};")
        right_layout.addWidget(settings_section_label)
        
        # Settings controls
        self.theme_switch = QCheckBox("Always use dark theme")
        self.theme_switch.setChecked(True)
        self.theme_switch.setEnabled(False)  # Disabled since we're always using dark theme
        right_layout.addWidget(self.theme_switch)
        
        # Add stretching space at the bottom
        right_layout.addStretch()
        
        # Add version info at the bottom
        version_label = QLabel("SmartGuard v1.0")
        version_label.setAlignment(Qt.AlignRight)
        version_label.setStyleSheet("color: #555555; font-size: 10px;")
        right_layout.addWidget(version_label)
        
        # Add both sides to splitter
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        
        # Set initial sizes (60% left, 40% right)
        splitter.setSizes([600, 400])
        
        main_layout.addWidget(splitter)
        self.setLayout(main_layout)

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
        # Auto-scroll to bottom
        self.log_box.verticalScrollBar().setValue(self.log_box.verticalScrollBar().maximum())

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
        # Create a custom styled message box
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Corruption Detected")
        msg_box.setText(message)
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg_box.setDefaultButton(QMessageBox.Yes)
        
        # Apply styling
        msg_box.setStyleSheet(f"""
            QMessageBox {{
                background-color: {THEME_BLACK};
                color: {THEME_WHITE};
            }}
            QPushButton {{
                background-color: {THEME_ACCENT_RED};
                color: {THEME_WHITE};
                border: none;
                border-radius: 3px;
                padding: 8px 16px;
                min-width: 80px;
            }}
            QPushButton:hover {{
                background-color: {THEME_ACCENT_RED_HOVER};
            }}
        """)
        
        reply = msg_box.exec_()
        
        if reply == QMessageBox.Yes:
            self.log_message(f"[ACTION] Recovery triggered for: {file_path}")
            self.comm.recovery_status_signal.emit("Recovery started...")
            
            # Start the recovery process in a separate thread
            thread = threading.Thread(target=self.attempt_file_recovery, args=(file_path,))
            thread.start()

    def attempt_file_recovery(self, file_path):
        """Attempt to recover corrupted file using the recovery module"""
        try:
            self.comm.log_signal.emit(f"[RECOVERY] Starting recovery for {file_path}")
            self.comm.progress_signal.emit(10)  # Show some initial progress
            
            # Call the recovery function
            recovered_path = recover_file(self.comm, file_path)
            
            self.comm.progress_signal.emit(100)  # Complete the progress
            
            if recovered_path:
                self.comm.log_signal.emit(f"[SUCCESS] File recovered and saved to: {recovered_path}")
                self.comm.recovery_status_signal.emit("Recovery successful")
                
                # Show success message with option to open the recovered file
                self.show_success_message(recovered_path)
            else:
                self.comm.log_signal.emit("[FAILURE] Could not recover the file")
                self.comm.recovery_status_signal.emit("Recovery failed")
        except Exception as e:
            self.comm.log_signal.emit(f"[ERROR] Recovery error: {str(e)}")
            self.comm.recovery_status_signal.emit("Recovery error")
            self.comm.progress_signal.emit(0)  # Reset progress

    def show_success_message(self, recovered_path):
        """Show a stylized success message dialog"""
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Recovery Successful")
        msg_box.setText(f"File has been recovered and saved to:\n{recovered_path}")
        msg_box.setStandardButtons(QMessageBox.Ok)
        
        # Apply styling
        msg_box.setStyleSheet(f"""
            QMessageBox {{
                background-color: {THEME_BLACK};
                color: {THEME_WHITE};
            }}
            QPushButton {{
                background-color: {THEME_ACCENT_RED};
                color: {THEME_WHITE};
                border: none;
                border-radius: 3px;
                padding: 8px 16px;
                min-width: 80px;
            }}
            QPushButton:hover {{
                background-color: {THEME_ACCENT_RED_HOVER};
            }}
        """)
        
        msg_box.exec_()

    def trigger_raw_recovery(self):
        if not self.raw_output_folder:
            self.comm.log_signal.emit("[ERROR] Please set output folder for raw recovery.")
            return
        drive = self.drive_selector.currentText().strip(":")
        thread = threading.Thread(target=recover_raw_files, args=(self.comm, drive, self.raw_output_folder))
        thread.start()

    def closeEvent(self, event):
        # Custom styled exit dialog
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Exit SmartGuard")
        msg_box.setText("Are you sure you want to exit?")
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg_box.setDefaultButton(QMessageBox.No)
        
        # Apply styling
        msg_box.setStyleSheet(f"""
            QMessageBox {{
                background-color: {THEME_BLACK};
                color: {THEME_WHITE};
            }}
            QPushButton {{
                background-color: {THEME_ACCENT_RED};
                color: {THEME_WHITE};
                border: none;
                border-radius: 3px;
                padding: 8px 16px;
                min-width: 80px;
            }}
            QPushButton:hover {{
                background-color: {THEME_ACCENT_RED_HOVER};
            }}
        """)
        
        reply = msg_box.exec_()
        
        if reply == QMessageBox.Yes:
            event.accept()
            QApplication.quit()
        else:
            event.ignore()

if __name__ == "__main__":
    import ctypes
    from PyQt5.QtCore import QSize
    
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
        
        # Set application-wide dark palette
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(THEME_BLACK))
        dark_palette.setColor(QPalette.WindowText, QColor(THEME_WHITE))
        dark_palette.setColor(QPalette.Base, QColor(THEME_DARK_GRAY))
        dark_palette.setColor(QPalette.AlternateBase, QColor(THEME_MEDIUM_GRAY))
        dark_palette.setColor(QPalette.ToolTipBase, QColor(THEME_WHITE))
        dark_palette.setColor(QPalette.ToolTipText, QColor(THEME_WHITE))
        dark_palette.setColor(QPalette.Text, QColor(THEME_WHITE))
        dark_palette.setColor(QPalette.Button, QColor(THEME_MEDIUM_GRAY))
        dark_palette.setColor(QPalette.ButtonText, QColor(THEME_WHITE))
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(THEME_ACCENT_RED))
        dark_palette.setColor(QPalette.Highlight, QColor(THEME_ACCENT_RED))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        app.setPalette(dark_palette)
        
        window = SmartGuardApp()
        window.show()
        sys.exit(app.exec_())