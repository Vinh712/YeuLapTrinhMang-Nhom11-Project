import sys
import time
import requests
import pyperclip
import keyboard
import json
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QObject, QSize
from PyQt5.QtGui import QIcon, QCursor, QFont, QFontDatabase
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QStackedWidget, QTabWidget,
    QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QLineEdit, QPushButton,
    QComboBox, QMessageBox, QTableWidget, QTableWidgetItem, QScrollArea,
    QRadioButton, QButtonGroup, QHeaderView, QDesktopWidget, QFrame, QStyle, QTextEdit,
    QSystemTrayIcon, QMenu
)

# Import AES encryption for end-to-end communication
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

class AESCrypto:
    def __init__(self, key=None):
        if key is None:
            self.key = get_random_bytes(32)
        else:
            if isinstance(key, str):
                key = key.encode("utf-8")
            if len(key) < 32:
                key = key + b'0' * (32 - len(key))
            elif len(key) > 32:
                key = key[:32]
            self.key = key
    
    def encrypt(self, data):
        if isinstance(data, dict) or isinstance(data, list):
            data = json.dumps(data, ensure_ascii=False)
        
        if isinstance(data, str):
            data = data.encode("utf-8")
        
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        padded_data = pad(data, AES.block_size)
        
        encrypted_data = cipher.encrypt(padded_data)
        
        result = base64.b64encode(iv + encrypted_data).decode("utf-8")
        return result
    
    def decrypt(self, encrypted_data):
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode("utf-8"))
            
            iv = encrypted_bytes[:16]
            encrypted_content = encrypted_bytes[16:]
            
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(encrypted_content)
            
            decrypted_data = unpad(decrypted_padded, AES.block_size)
            
            result = decrypted_data.decode("utf-8")
            
            try:
                return json.loads(result)
            except json.JSONDecodeError:
                return result
                
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

# Shared AES encryption key for client-server communication
SHARED_AES_KEY = "SuperFastLTM_2025_SecureKey_32B!"  # 32 bytes key

def create_shared_crypto():
    """
    Tạo AES crypto instance với shared key cho client-server communication
    """
    # Tạo key 32 bytes từ shared secret
    key = hashlib.sha256(SHARED_AES_KEY.encode('utf-8')).digest()
    return AESCrypto(key)

def encrypt_communication_data(data):
    """
    Mã hóa dữ liệu cho communication giữa client và server
    """
    crypto = create_shared_crypto()
    return crypto.encrypt(data)

def decrypt_communication_data(encrypted_data):
    """
    Giải mã dữ liệu từ communication giữa client và server
    """
    crypto = create_shared_crypto()
    return crypto.decrypt(encrypted_data)

API_BASE = "http://127.0.0.1:8000" # Changed to point to load balancer

class Worker(QObject):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func; self.args = args; self.kwargs = kwargs
    def run(self):
        try:
            self.finished.emit(self.func(*self.args, **self.kwargs))
        except Exception as e:
            self.error.emit(str(e))


class TranslationPopup(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_ShowWithoutActivating)

        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        
        self.container = QWidget()
        self.container.setObjectName("popupContainer")
        self.container_layout = QVBoxLayout(self.container)
        self.container_layout.setContentsMargins(16, 16, 16, 16)
        self.container_layout.setSpacing(8)

        self.close_button = QPushButton("✕")
        self.close_button.setObjectName("popupCloseButton")
        self.close_button.clicked.connect(self.hide)
        self.close_button.setFixedSize(20, 20)

        self.open_main_btn = QPushButton("≡")
        self.open_main_btn.setObjectName("popupOpenButton")
        self.open_main_btn.clicked.connect(self.show_main_window)
        self.open_main_btn.setFixedSize(20, 20)
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.open_main_btn)
        button_layout.addWidget(self.close_button, alignment=Qt.AlignRight)
        button_layout.setContentsMargins(0, 0, 0, 0)

        self.trans_text = QLabel()
        self.trans_text.setWordWrap(True)
        self.trans_text.setObjectName("popupTransText")
        
        self.phonetic = QLabel()
        self.phonetic.setObjectName("popupPhonetic")
        
        self.definitions = QLabel()
        self.definitions.setWordWrap(True)
        self.definitions.setObjectName("popupDefinitions")
        
        self.alternatives = QLabel()
        self.alternatives.setWordWrap(True) 
        self.alternatives.setObjectName("popupAlternatives")

        self.container_layout.addLayout(button_layout)
        self.container_layout.addWidget(self.trans_text)
        self.container_layout.addWidget(self.phonetic)
        self.container_layout.addWidget(self.definitions)
        self.container_layout.addWidget(self.alternatives)
        
        self.main_layout.addWidget(self.container)

        self.hide_timer = QTimer(self)
        self.hide_timer.setSingleShot(True)
        self.hide_timer.timeout.connect(self.hide)

        self.setStyleSheet("""
            #popupContainer {
                background-color: #2D2D2D;
                border: 1px solid #404040;
                border-radius: 8px;
            }
            
            #popupTransText {
                color: #E0E0E0;
                font-size: 13pt;
                font-weight: 500;
            }
            
            #popupPhonetic {
                color: #888888;
                font-size: 11pt;
                font-style: italic;
            }
            
            #popupDefinitions {
                color: #61AFEF;
                font-size: 11pt;
                margin-top: 4px;
            }
            
            #popupAlternatives {
                color: #98C379;
                font-size: 11pt;
                margin-top: 4px;
            }

            #popupCloseButton {
                background-color: transparent;
                color: white;
                border: none;
                font-size: 12pt;
                font-weight: bold;
            }

            #popupCloseButton:hover {
                color: #FF5C5C;
            }

            #popupCloseButton:pressed {
                color: #FF0000;
            }

            #popupOpenButton {
                background-color: transparent;
                color: white;
                border: none;
                font-size: 12pt;
                font-weight: bold;
            }
            #popupOpenButton:hover {
                color: #61AFEF;
            }
        """)
        self.setMinimumSize(300, 150)
        self.setMaximumSize(600, 400)
        
        self.default_size = QSize(400, 250)
        self.resize(self.default_size)

        self.is_translating = False
        
    def show_loading(self):
        self.is_translating = True
        self.trans_text.setText("Translating...")
        self.phonetic.setVisible(False)
        self.definitions.setVisible(False)
        self.alternatives.setVisible(False)
        self.show()
        
    def show_translation(self, data):
        self.is_translating = False
        # Updated to handle both basic and advanced translation formats
        if data.get("translation_type") == "basic":
            self.trans_text.setText(data.get("translated_text", ""))
            if data.get("word_translations"):
                first_word_translation = data["word_translations"][0]["translation"]
                self.phonetic.setText(first_word_translation.get("phonetic", ""))
                self.phonetic.setVisible(bool(first_word_translation.get("phonetic")))
                
                definitions = first_word_translation.get("all_translations", [])
                if definitions:
                    def_text = '\n'.join(f"• {d["part_of_speech"]}: {d["translation"]}" for d in definitions)
                    self.definitions.setText(def_text)
                    self.definitions.setVisible(True)
                else:
                    self.definitions.setVisible(False)
                self.alternatives.setVisible(False) # Basic translation doesn't have alternatives
            else:
                self.phonetic.setVisible(False)
                self.definitions.setVisible(False)
                self.alternatives.setVisible(False)
        else: # Advanced translation
            self.trans_text.setText(data.get("translated_text", ""))
            
            phonetic = data.get("phonetic")
            self.phonetic.setText(phonetic if phonetic else "")
            self.phonetic.setVisible(bool(phonetic))
            
            definitions = data.get("meanings", [])
            if definitions:
                def_text = '\n'.join(f"• {d["part_of_speech"]}: {d["definition"]}" for d in definitions)
                self.definitions.setText(def_text)
                self.definitions.setVisible(True)
            else:
                self.definitions.setVisible(False)
                
            alternatives = data.get("alternatives", [])
            if alternatives:
                alt_text = "Alternatives: " + ", ".join(alternatives)
                self.alternatives.setText(alt_text)
                self.alternatives.setVisible(True)
            else:
                self.alternatives.setVisible(False)
            
        self.show()

    def show_at_cursor(self, text_or_data):
        if self.isVisible():
            self.hide()
            QTimer.singleShot(100, lambda: self._show_new_popup(text_or_data))
        else:
            self._show_new_popup(text_or_data)

    def _show_new_popup(self, text_or_data):
        if isinstance(text_or_data, str):
            self.trans_text.setText(text_or_data)
            self.phonetic.setVisible(False)
            self.definitions.setVisible(False)
            self.alternatives.setVisible(False)
        else:
            self.show_translation(text_or_data)
            
        pos = QCursor.pos()
        screen_geo = QDesktopWidget().availableGeometry(pos)
        
        if pos.x() + self.width() > screen_geo.right():
            pos.setX(screen_geo.right() - self.width())
        if pos.y() + self.height() > screen_geo.bottom():
            pos.setY(screen_geo.bottom() - self.height())
            
        self.move(pos)
        self.show()
        self.hide_timer.start(10000)

    def show_main_window(self):
        self.main_window.show()
        self.main_window.activateWindow()


class HotkeyListener(QThread):
    selection_captured = pyqtSignal(str)

    def run(self):
        last_clip = ""
        try:
            last_clip = pyperclip.paste()
        except pyperclip.PyperclipException:
            pass
            
        while True:
            keyboard.wait("ctrl+b")
            keyboard.press_and_release("ctrl+c")
            time.sleep(0.05)
            try:
                txt = pyperclip.paste()
                pyperclip.copy(last_clip)
                last_clip = txt
                self.selection_captured.emit(txt)
            except pyperclip.PyperclipException:
                self.selection_captured.emit("")


class ClientUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SuperFastLTM Client")
        self.resize(800, 600)
        self.token = None
        self.threadpool = {}
        self.quiz_answers = {}
        self.quiz_button_groups = []

        self._apply_stylesheet()
        
        self.tray_icon = QSystemTrayIcon(self)
        icon = QIcon(self.style().standardIcon(QStyle.SP_MessageBoxInformation))
        self.tray_icon.setIcon(icon)
        self.tray_icon.setToolTip("SuperFastLTM Client")
        
        tray_menu = QMenu()
        show_action = tray_menu.addAction("Show")
        show_action.triggered.connect(self.show)
        quit_action = tray_menu.addAction("Quit")
        quit_action.triggered.connect(self.quit_application)
        self.tray_icon.setContextMenu(tray_menu)
        
        self.tray_icon.show()
        
        self.tray_icon.activated.connect(self.tray_icon_activated)

        self.translation_popup = TranslationPopup(self)
        
        self.hide()
        
        self.tray_icon.activated.connect(self.tray_icon_activated)

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.login_widget = self._create_login_widget()
        self.main_widget = self._create_main_widget()

        self.stack.addWidget(self.login_widget)
        self.stack.addWidget(self.main_widget)
        self.stack.setCurrentWidget(self.login_widget)

        self.hotkey_thread = HotkeyListener()
        self.hotkey_thread.selection_captured.connect(self.on_hotkey_translate)
        self.hotkey_thread.start()

    def _apply_stylesheet(self):
        for widget in self.findChildren(QWidget):
            widget.setFocusPolicy(Qt.NoFocus)
        self.setFont(QFont("Roboto", 10))
        self.setStyleSheet("""
            QWidget {
                outline: none;
            }
                           
            QMainWindow, QWidget {
                background-color: #1E1E1E;
                color: #E0E0E0;
            }
            
            QLabel {
                font-size: 10pt;
                color: #FFFFFF;
            }
            
            QLineEdit, QTextEdit, QComboBox {
                background-color: #2D2D2D;
                border: 2px solid #3D3D3D;
                border-radius: 6px;
                padding: 8px;
                font-size: 10pt;
                color: #FFFFFF;
                outline: none;
            }
            
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
                border: 2px solid #0078D4;
                background-color: #333333;
                outline: none;
            }
            
            QPushButton {
                background-color: #0078D4;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-size: 10pt;
                font-weight: 500;
                font-family: 'Segoe UI';
                outline: none;
            }
                           
            QPushButton:focus {
                outline: none;
                border: none;
            }
                           
            QPushButton:hover {
                background-color: #1484D7;
            }
            
            QPushButton:pressed {
                background-color: #006CBC;
            }
            
            QTableWidget {
                outline: none;
                border: 2px solid #3D3D3D;
            }
            
            QTableWidget:focus {
                outline: none;
                border: 2px solid #3D3D3D;
            }
            
            /* ComboBox styles */
            QComboBox {
                outline: none;
            }
            
            QComboBox:focus {
                outline: none;
                border: 2px solid #3D3D3D;
            }
                           
            QTabWidget::pane {
                border-top: 2px solid #3D3D3D;
                background-color: #1E1E1E;
            }
            
            QTabBar::tab {
                background: #2D2D2D;
                border: 1px solid #3D3D3D;
                border-bottom: none;
                padding: 10px 25px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
                color: #B0B0B0;
            }
            
            QTabBar::tab:selected {
                background: #0078D4;
                color: white;
            }
            
            QTableWidget {
                background-color: #2D2D2D;
                gridline-color: #3D3D3D;
                border: 2px solid #3D3D3D;
                border-radius: 6px;
            }
            
            QTableWidget::item {
                padding: 5px;
                border-bottom: 1px solid #3D3D3D;
            }
            
            QHeaderView::section {
                background-color: #252525;
                padding: 8px;
                border: none;
                border-right: 1px solid #3D3D3D;
                border-bottom: 2px solid #3D3D3D;
                font-weight: bold;
                color: #FFFFFF;
            }
            
            QScrollBar:vertical {
                border: none;
                background-color: #2D2D2D;
                width: 10px;
                border-radius: 5px;
            }
            
            QScrollBar::handle:vertical {
                background-color: #4D4D4D;
                border-radius: 5px;
            }
            
            QScrollBar::handle:vertical:hover {
                background-color: #666666;
            }
            
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #FFFFFF;
                margin-right: 5px;
            }
            
            QRadioButton {
                color: #E0E0E0;
                spacing: 8px;
            }
            
            QRadioButton::indicator {
                width: 18px;
                height: 18px;
                border-radius: 9px;
                border: 2px solid #4D4D4D;
            }
            
            QRadioButton::indicator:checked {
                background-color: #0078D4;
                border: 2px solid #0078D4;
            }
            
            QRadioButton::indicator:unchecked:hover {
                border: 2px solid #0078D4;
            }
            
            QRadioButton {
                outline: none;
            }
            
            QRadioButton:focus {
                outline: none;
            }
            
            QTabWidget::pane {
                outline: none;
                border-top: 2px solid #3D3D3D;
            }
            
            QTabBar::tab {
                outline: none;
            }
            
            QTabBar::tab:focus {
                outline: none;
            }

            #welcomeTitle {
                font-size: 24pt;
                font-weight: 600;
                color: #61AFEF;
                margin-bottom: 20px;
            }
        """)
    def _configure_widget_focus(self, widget):
        widget.setFocusPolicy(Qt.NoFocus)
        for child in widget.findChildren(QWidget):
            child.setFocusPolicy(Qt.NoFocus)

    def _create_login_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(16)

        title = QLabel("Welcome to SuperFastLTM")
        title.setObjectName("welcomeTitle")
        title.setAlignment(Qt.AlignCenter)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.username_input.setFixedSize(300, 40)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setFixedSize(300, 40)

        login_button = QPushButton("Login")
        login_button.setFixedSize(300, 40)
        login_button.clicked.connect(self.login)

        register_button = QPushButton("Register")
        register_button.setFixedSize(300, 40)
        register_button.clicked.connect(self.register)

        layout.addWidget(title)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_input)
        layout.addWidget(login_button)
        layout.addWidget(register_button)

        return widget

    def _create_main_widget(self):
        widget = QWidget()
        main_layout = QVBoxLayout(widget)

        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(self._create_translate_tab(), "Translate")
        self.tab_widget.addTab(self._create_quiz_tab(), "Quiz")
        self.tab_widget.addTab(self._create_history_tab(), "History")
        self.tab_widget.addTab(self._create_note_tab(), "Notes")
        self.tab_widget.addTab(self._create_ranking_tab(), "Ranking")

        main_layout.addWidget(self.tab_widget)

        return widget

    def _create_translate_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Input section
        input_group = QFrame()
        input_group.setFrameShape(QFrame.StyledPanel)
        input_layout = QVBoxLayout(input_group)
        input_layout.addWidget(QLabel("Text to Translate:"))
        self.translate_input = QTextEdit()
        self.translate_input.setPlaceholderText("Enter text here...")
        input_layout.addWidget(self.translate_input)

        # Translation type selection
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Translation Type:"))
        self.basic_radio = QRadioButton("Basic (Local Dictionary)")
        self.basic_radio.setChecked(True)
        self.advanced_radio = QRadioButton("Advanced (Gemini AI)")
        type_layout.addWidget(self.basic_radio)
        type_layout.addWidget(self.advanced_radio)
        type_layout.addStretch(1)
        input_layout.addLayout(type_layout)

        translate_button = QPushButton("Translate")
        translate_button.clicked.connect(self.translate_text)
        input_layout.addWidget(translate_button)

        layout.addWidget(input_group)

        # Output section
        output_group = QFrame()
        output_group.setFrameShape(QFrame.StyledPanel)
        output_layout = QVBoxLayout(output_group)
        output_layout.addWidget(QLabel("Translation Result:"))
        self.translate_output = QTextEdit()
        self.translate_output.setReadOnly(True)
        output_layout.addWidget(self.translate_output)

        layout.addWidget(output_group)
        layout.addStretch(1)
        return tab

    def _create_quiz_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Difficulty selection
        difficulty_layout = QHBoxLayout()
        difficulty_layout.addWidget(QLabel("Difficulty:"))
        self.difficulty_combo = QComboBox()
        self.difficulty_combo.addItems(["A1", "A2", "B1", "B2", "C1", "C2"])
        difficulty_layout.addWidget(self.difficulty_combo)
        difficulty_layout.addStretch(1)
        layout.addLayout(difficulty_layout)

        generate_quiz_button = QPushButton("Generate Quiz")
        generate_quiz_button.clicked.connect(self.generate_quiz)
        layout.addWidget(generate_quiz_button)

        self.quiz_area = QScrollArea()
        self.quiz_area.setWidgetResizable(True)
        self.quiz_content_widget = QWidget()
        self.quiz_content_layout = QVBoxLayout(self.quiz_content_widget)
        self.quiz_area.setWidget(self.quiz_content_widget)
        layout.addWidget(self.quiz_area)

        self.submit_quiz_button = QPushButton("Submit Quiz")
        self.submit_quiz_button.clicked.connect(self.submit_quiz)
        self.submit_quiz_button.hide() # Hide until quiz is generated
        layout.addWidget(self.submit_quiz_button)

        self.quiz_result_button = QPushButton("View Quiz Result")
        self.quiz_result_button.clicked.connect(self.show_quiz_result)
        self.quiz_result_button.hide() # Hide until quiz is submitted
        layout.addWidget(self.quiz_result_button)

        return tab

    def _create_history_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        refresh_button = QPushButton("Refresh History")
        refresh_button.clicked.connect(self.load_history)
        layout.addWidget(refresh_button)

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(3)
        self.history_table.setHorizontalHeaderLabels(["Date", "Type", "Content"]) # Updated columns
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.history_table)

        return tab

    def _create_note_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        note_input_layout = QHBoxLayout()
        self.note_input = QLineEdit()
        self.note_input.setPlaceholderText("Enter your note here...")
        note_input_layout.addWidget(self.note_input)

        save_note_button = QPushButton("Save Note")
        save_note_button.clicked.connect(self.save_note)
        note_input_layout.addWidget(save_note_button)
        layout.addLayout(note_input_layout)

        refresh_notes_button = QPushButton("Refresh Notes")
        refresh_notes_button.clicked.connect(self.load_notes)
        layout.addWidget(refresh_notes_button)

        self.notes_table = QTableWidget()
        self.notes_table.setColumnCount(2)
        self.notes_table.setHorizontalHeaderLabels(["Date", "Note"]) # Updated columns
        self.notes_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.notes_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.notes_table)

        return tab

    def _create_ranking_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        refresh_ranking_button = QPushButton("Refresh Ranking")
        refresh_ranking_button.clicked.connect(self.load_ranking)
        layout.addWidget(refresh_ranking_button)

        self.ranking_table = QTableWidget()
        self.ranking_table.setColumnCount(3)
        self.ranking_table.setHorizontalHeaderLabels(["Rank", "Username", "Points"])
        self.ranking_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.ranking_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.ranking_table)

        self.ranking_stats_label = QLabel("")
        layout.addWidget(self.ranking_stats_label)

        return tab

    def show_message(self, title, message, icon=QMessageBox.Information):
        msg_box = QMessageBox(self)
        msg_box.setIcon(icon)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.exec_()

    def run_in_thread(self, func, callback, error_callback=None, *args, **kwargs):
        thread = QThread()
        worker = Worker(func, *args, **kwargs)
        worker.moveToThread(thread)
        
        # Store references to prevent premature garbage collection
        # Use a unique ID for each thread/worker pair
        thread_id = id(thread)
        self.threadpool[thread_id] = {
            'thread': thread,
            'worker': worker
        }

        thread.started.connect(worker.run)
        worker.finished.connect(callback)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        
        # Clean up references when thread finishes
        thread.finished.connect(lambda: self.threadpool.pop(thread_id, None))
        thread.finished.connect(thread.deleteLater)
        
        if error_callback:
            worker.error.connect(error_callback)
        thread.start()
        return thread

    def encrypted_api_call(self, endpoint, method='POST', data=None):
        """
        Thực hiện API call với mã hóa AES đầu cuối
        """
        try:
            # Mã hóa dữ liệu trước khi gửi
            if data:
                encrypted_data = encrypt_communication_data(data)
                payload = {"encrypted_data": encrypted_data}
            else:
                payload = None
            
            # Gửi request
            if method == 'POST':
                if payload:
                    response = requests.post(f"{API_BASE}{endpoint}", json=payload)
                else:
                    response = requests.post(f"{API_BASE}{endpoint}")
            elif method == 'GET':
                response = requests.get(f"{API_BASE}{endpoint}")
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            response.raise_for_status()
            
            # Xử lý response
            response_data = response.json()
            
            # Kiểm tra xem response có được mã hóa không
            if isinstance(response_data, dict) and 'encrypted_data' in response_data:
                # Giải mã response
                decrypted_response = decrypt_communication_data(response_data['encrypted_data'])
                return decrypted_response
            else:
                # Response không được mã hóa (backward compatibility)
                return response_data
                
        except Exception as e:
            raise Exception(f"API call failed: {str(e)}")

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        self.run_in_thread(self._login_request, self._login_callback, None, username, password)

    def _login_request(self, username, password):
        return self.encrypted_api_call('/login', 'POST', {"username": username, "password": password})

    def _login_callback(self, data):
        if "token" in data:
            self.token = data["token"]
            self.stack.setCurrentWidget(self.main_widget)
            self.show_message("Login Success", "Logged in successfully!")
            self.load_history() # Load history after login
            self.load_notes() # Load notes after login
            self.load_ranking() # Load ranking after login
        else:
            self.show_message("Login Failed", data.get("error", "Unknown error"), QMessageBox.Warning)

    def register(self):
        username = self.username_input.text()
        password = self.password_input.text()
        self.run_in_thread(self._register_request, self._register_callback, None, username, password)

    def _register_request(self, username, password):
        return self.encrypted_api_call('/register', 'POST', {"username": username, "password": password})

    def _register_callback(self, data):
        if "message" in data:
            self.show_message("Registration Success", data["message"])
        else:
            self.show_message("Registration Failed", data.get("error", "Unknown error"), QMessageBox.Warning)

    def translate_text(self):
        text = self.translate_input.toPlainText()
        if not text:
            self.show_message("Error", "Please enter text to translate.", QMessageBox.Warning)
            return
        
        if self.basic_radio.isChecked():
            self.run_in_thread(self._translate_basic_request, self._translate_callback, None, text)
        else:
            self.run_in_thread(self._translate_advanced_request, self._translate_callback, None, text)

    def _translate_basic_request(self, text):
        return self.encrypted_api_call('/translate_basic', 'POST', {
            "token": self.token,
            "text": text
        })

    def _translate_advanced_request(self, text):
        return self.encrypted_api_call('/translate_advanced', 'POST', {
            "token": self.token,
            "text": text,
            "from_lang": "en", # Assuming English input for now
            "to_lang": "vi"
        })

    def _translate_callback(self, data):
        if "translated_data" in data:
            # Handle both basic and advanced translation formats
            translated_data = data["translated_data"]
            if translated_data.get("translation_type") == "basic":
                self.translate_output.setText(translated_data.get("translated_text", ""))
            else:
                self.translate_output.setText(translated_data.get("translated_text", ""))
            self.load_history() # Refresh history after translation
        else:
            self.show_message("Translation Error", data.get("error", "Unknown error"), QMessageBox.Warning)

    def on_hotkey_translate(self, text):
        if not text:
            return
        if not self.token:
            self.tray_icon.showMessage("SuperFastLTM", "Please login to use translation feature.", QSystemTrayIcon.Warning)
            return
        
        self.translation_popup.show_loading()
        self.run_in_thread(self._translate_advanced_request, self._hotkey_translate_callback, self._hotkey_translate_error, text)

    def _hotkey_translate_callback(self, data):
        if "translated_data" in data:
            self.translation_popup.show_translation(data["translated_data"])
            self.load_history() # Refresh history after hotkey translation
        else:
            self.translation_popup.show_at_cursor(data.get("error", "Translation Error"))

    def _hotkey_translate_error(self, error_msg):
        self.translation_popup.show_at_cursor(f"Error: {error_msg}")

    def generate_quiz(self):
        if not self.token:
            self.show_message("Error", "Please login to generate quiz.", QMessageBox.Warning)
            return
        difficulty = self.difficulty_combo.currentText()
        self.run_in_thread(self._generate_quiz_request, self._generate_quiz_callback, None, difficulty)

    def _generate_quiz_request(self, difficulty):
        return self.encrypted_api_call('/generate_quiz', 'POST', {
            "token": self.token,
            "difficulty": difficulty
        })

    def _generate_quiz_callback(self, data):
        if "questions" in data:
            self.current_quiz_data = data # Store quiz data for submission
            self.quiz_answers = {}
            self.quiz_button_groups = []
            
            # Clear previous quiz
            for i in reversed(range(self.quiz_content_layout.count())):
                widget = self.quiz_content_layout.itemAt(i).widget()
                if widget:
                    widget.setParent(None)
            
            for i, question_data in enumerate(data["questions"]):
                question_label = QLabel(f"Question {i+1}: {question_data['question']}")
                self.quiz_content_layout.addWidget(question_label)
                
                button_group = QButtonGroup(self)
                self.quiz_button_groups.append(button_group)
                
                for option_idx, option_text in enumerate(question_data["options"]):
                    radio_button = QRadioButton(option_text)
                    radio_button.answer_index = option_idx # Store index for easy lookup
                    button_group.addButton(radio_button, option_idx)
                    self.quiz_content_layout.addWidget(radio_button)
            
            self.submit_quiz_button.show()
            self.quiz_result_button.hide() # Hide result button until submitted
        else:
            self.show_message("Quiz Generation Error", data.get("error", "Unknown error"), QMessageBox.Warning)

    def submit_quiz(self):
        if not self.token:
            self.show_message("Error", "Please login to submit quiz.", QMessageBox.Warning)
            return
        
        if not hasattr(self, "current_quiz_data") or not self.current_quiz_data:
            self.show_message("Error", "No quiz generated yet.", QMessageBox.Warning)
            return
        
        user_answers = {}
        for i, button_group in enumerate(self.quiz_button_groups):
            checked_button = button_group.checkedButton()
            if checked_button:
                user_answers[str(i)] = checked_button.text() # Store the text of the selected option
            else:
                user_answers[str(i)] = "" # No answer selected
        
        difficulty = self.difficulty_combo.currentText()
        self.run_in_thread(self._submit_quiz_request, self._submit_quiz_callback, None, self.current_quiz_data, user_answers, difficulty)

    def _submit_quiz_request(self, quiz_data, user_answers, difficulty):
        return self.encrypted_api_call('/submit_quiz', 'POST', {
            "token": self.token,
            "quiz_data": quiz_data,
            "user_answers": user_answers,
            "difficulty": difficulty
        })

    def _submit_quiz_callback(self, data):
        if "result" in data:
            self.last_quiz_result = data["result"] # Store result for viewing
            self.show_message("Quiz Submitted", data["message"])
            self.submit_quiz_button.hide()
            self.quiz_result_button.show()
            self.load_ranking() # Refresh ranking after quiz submission
            self.load_history() # Refresh history after quiz submission
        else:
            self.show_message("Quiz Submission Error", data.get("error", "Unknown error"), QMessageBox.Warning)

    def show_quiz_result(self):
        if not hasattr(self, "last_quiz_result") or not self.last_quiz_result:
            self.show_message("Error", "No quiz result to display.", QMessageBox.Warning)
            return
        
        result = self.last_quiz_result
        result_message = f"Score: {result['score']} points\n"
        result_message += f"Correct: {result['correct_count']}/{result['total_questions']}\n"
        result_message += f"Percentage: {result['percentage']:.2f}%\n\n"
        
        result_message += "Correct Answers:\n"
        for ans in result["correct_answers"]:
            result_message += f"- Q: {ans['question']}\n  Your Answer: {ans['user_answer']}\n  Correct: {ans['correct_answer']}\n\n"
            
        result_message += "Incorrect Answers:\n"
        for ans in result["incorrect_answers"]:
            result_message += f"- Q: {ans['question']}\n  Your Answer: {ans['user_answer']}\n  Correct: {ans['correct_answer']}\n\n"
            
        self.show_message("Quiz Result", result_message)

    def load_history(self):
        if not self.token:
            return
        self.run_in_thread(self._load_history_request, self._load_history_callback)

    def _load_history_request(self):
        return self.encrypted_api_call('/view_history', 'POST', {
            "token": self.token
        })

    def _load_history_callback(self, data):
        if "history" in data:
            self.history_table.setRowCount(0)
            for row, entry in enumerate(data["history"]):
                self.history_table.insertRow(row)
                content_data = entry["content"]
                
                # Try to parse content_data if it's a string (decrypted JSON)
                if isinstance(content_data, str):
                    try:
                        content_data = json.loads(content_data)
                    except json.JSONDecodeError:
                        pass # Keep as string if not JSON

                history_type = content_data.get("type", "N/A")
                history_input = content_data.get("input", "N/A")
                history_output = content_data.get("output", "N/A")

                display_content = ""
                if history_type == "translate_basic" or history_type == "translate_advanced":
                    display_content = f"Input: {history_input}\nOutput: {history_output.get('translated_text', 'N/A')}"
                elif history_type == "generate_quiz":
                    display_content = f"Difficulty: {content_data.get('difficulty', 'N/A')}\nQuestions: {len(content_data.get('quiz_data', {}).get('questions', []))}"
                elif history_type == "submit_quiz":
                    display_content = f"Difficulty: {content_data.get('difficulty', 'N/A')}\nScore: {content_data.get('result', {}).get('score', 'N/A')}"
                else:
                    display_content = str(content_data)

                self.history_table.setItem(row, 0, QTableWidgetItem(entry["created_day"]))
                self.history_table.setItem(row, 1, QTableWidgetItem(history_type))
                self.history_table.setItem(row, 2, QTableWidgetItem(display_content))
            self.history_table.resizeRowsToContents()
        else:
            self.show_message("History Error", data.get("error", "Unknown error"), QMessageBox.Warning)

    def save_note(self):
        if not self.token:
            self.show_message("Error", "Please login to save notes.", QMessageBox.Warning)
            return
        content = self.note_input.text()
        if not content:
            self.show_message("Error", "Note content cannot be empty.", QMessageBox.Warning)
            return
        self.run_in_thread(self._save_note_request, self._save_note_callback, None, content)

    def _save_note_request(self, content):
        return self.encrypted_api_call('/save_note', 'POST', {
            "token": self.token,
            "content": content
        })

    def _save_note_callback(self, data):
        if "message" in data:
            self.show_message("Note Saved", data["message"])
            self.note_input.clear()
            self.load_notes() # Refresh notes after saving
        else:
            self.show_message("Save Note Error", data.get("error", "Unknown error"), QMessageBox.Warning)

    def load_notes(self):
        if not self.token:
            return
        self.run_in_thread(self._load_notes_request, self._load_notes_callback)

    def _load_notes_request(self):
        return self.encrypted_api_call('/view_note', 'POST', {
            "token": self.token
        })

    def _load_notes_callback(self, data):
        if "notes" in data:
            self.notes_table.setRowCount(0)
            for row, entry in enumerate(data["notes"]):
                self.notes_table.insertRow(row)
                self.notes_table.setItem(row, 0, QTableWidgetItem(entry["created_day"]))
                self.notes_table.setItem(row, 1, QTableWidgetItem(entry["content"]))
            self.notes_table.resizeRowsToContents()
        else:
            self.show_message("Notes Error", data.get("error", "Unknown error"), QMessageBox.Warning)

    def load_ranking(self):
        self.run_in_thread(self._load_ranking_request, self._load_ranking_callback)

    def _load_ranking_request(self):
        return self.encrypted_api_call('/get_ranking', 'GET')

    def _load_ranking_callback(self, data):
        if "top_users" in data:
            self.ranking_table.setRowCount(0)
            for row, user in enumerate(data["top_users"]):
                self.ranking_table.insertRow(row)
                self.ranking_table.setItem(row, 0, QTableWidgetItem(str(user["rank"])))
                self.ranking_table.setItem(row, 1, QTableWidgetItem(user["username"]))
                self.ranking_table.setItem(row, 2, QTableWidgetItem(str(user["point"])))
            
            stats = data.get("stats", {})
            stats_text = f"Total Users: {stats.get('total_users', 0)}\n"
            if stats.get("top_user"):
                stats_text += f"Top User: {stats['top_user']['username']} ({stats['top_user']['point']} points)\n"
            stats_text += f"Average Points: {stats.get('average_points', 0):.2f}"
            self.ranking_stats_label.setText(stats_text)
        else:
            self.show_message("Ranking Error", data.get("error", "Unknown error"), QMessageBox.Warning)

    def tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            if self.isHidden():
                self.show()
            else:
                self.hide()

    def quit_application(self):
        self.hotkey_thread.quit()
        self.hotkey_thread.wait()
        QApplication.quit()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # Load custom font
    QFontDatabase.addApplicationFont("Roboto-Regular.ttf") # Assuming font file is present
    QFontDatabase.addApplicationFont("Roboto-Bold.ttf")
    QFontDatabase.addApplicationFont("Roboto-Italic.ttf")
    
    client_ui = ClientUI()
    sys.exit(app.exec_())


