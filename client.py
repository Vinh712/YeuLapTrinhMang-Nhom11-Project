import sys
import time
import requests
import pyperclip
import keyboard
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QObject, QSize
from PyQt5.QtGui import QIcon, QCursor, QFont, QFontDatabase
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QStackedWidget, QTabWidget,
    QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QLineEdit, QPushButton,
    QComboBox, QMessageBox, QTableWidget, QTableWidgetItem, QScrollArea,
    QRadioButton, QButtonGroup, QHeaderView, QDesktopWidget, QFrame, QStyle, QTextEdit,
    QSystemTrayIcon, QMenu
)

API_BASE = "http://127.0.0.1:8000"

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
        self.trans_text.setText(data.get('translated_text', ''))
        
        phonetic = data.get('phonetic')
        self.phonetic.setText(phonetic if phonetic else '')
        self.phonetic.setVisible(bool(phonetic))
        
        definitions = data.get('meanings', [])
        if definitions:
            def_text = '\n'.join(f"• {d['part_of_speech']}: {d['definition']}" for d in definitions)
            self.definitions.setText(def_text)
            self.definitions.setVisible(True)
        else:
            self.definitions.setVisible(False)
            
        alternatives = data.get('alternatives', [])
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
            keyboard.wait('ctrl+b')
            keyboard.press_and_release('ctrl+c')
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
        self.tray_icon.setToolTip('SuperFastLTM Client')
        
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

        font = QFont("Roboto", 12)
        self.login_user = QLineEdit()
        self.login_user.setPlaceholderText("Username")
        self.login_user.setFixedWidth(300)
        self.login_user.setMinimumHeight(40)
        self.login_user.setFont(font)

        self.login_pass = QLineEdit()
        self.login_pass.setPlaceholderText("Password")
        self.login_pass.setEchoMode(QLineEdit.Password)
        self.login_pass.setFixedWidth(300)
        self.login_pass.setMinimumHeight(40)
        self.login_pass.setFont(font)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        login_btn = QPushButton("Login")
        login_btn.setMinimumHeight(40)
        login_btn.setFixedWidth(145)
        login_btn.clicked.connect(self.do_login)

        register_btn = QPushButton("Register")
        register_btn.setMinimumHeight(40)
        register_btn.setFixedWidth(145)
        register_btn.clicked.connect(self.do_register)

        btn_layout.addWidget(login_btn)
        btn_layout.addWidget(register_btn)

        layout.addWidget(title)
        layout.addWidget(self.login_user, alignment=Qt.AlignCenter)
        layout.addWidget(self.login_pass, alignment=Qt.AlignCenter)
        layout.addLayout(btn_layout)
        layout.setContentsMargins(20, 20, 20, 20)

        return widget

    def _create_main_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.tabs = QTabWidget()
        
        style = self.style()
        self.tabs.addTab(self._create_translate_tab(), QIcon(style.standardIcon(QStyle.SP_TitleBarContextHelpButton)), "Translate")
        self.tabs.addTab(self._create_quiz_tab(), QIcon(style.standardIcon(QStyle.SP_DialogApplyButton)), "Quiz")
        self.tabs.addTab(self._create_history_tab(), QIcon(style.standardIcon(QStyle.SP_DialogYesButton)), "History")
        self.tabs.addTab(self._create_notes_tab(), QIcon(style.standardIcon(QStyle.SP_FileIcon)), "Notes")
        
        layout.addWidget(self.tabs)
        widget.setLayout(layout)
        return widget

    def _create_translate_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        content_panel = QWidget()
        content_layout = QHBoxLayout(content_panel)
        content_panel.setObjectName("translationPanel")
        
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_panel.setObjectName("translationSidePanel")
        
        input_header = QHBoxLayout()
        from_label = QLabel("From:")
        from_label.setObjectName("translationLabel")
        self.from_combo = QComboBox()
        self.from_combo.addItems(["auto", "en", "vi", "fr", "es"])
        self.from_combo.setObjectName("translationCombo")
        
        input_header.addWidget(from_label)
        input_header.addWidget(self.from_combo)
        input_header.addStretch()
        
        self.translate_input = QTextEdit()
        self.translate_input.setObjectName("translationInput")
        self.translate_input.setPlaceholderText("Enter text to translate...")
        
        left_layout.addLayout(input_header)
        left_layout.addWidget(self.translate_input)
        
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_panel.setObjectName("translationSidePanel")
        
        output_header = QHBoxLayout()
        to_label = QLabel("To:")
        to_label.setObjectName("translationLabel")
        self.to_combo = QComboBox()
        self.to_combo.addItems(["vi", "en", "fr", "es"])
        self.to_combo.setObjectName("translationCombo")
        
        output_header.addWidget(to_label)
        output_header.addWidget(self.to_combo)
        output_header.addStretch()
        
        self.translate_output = QTextEdit()
        self.translate_output.setObjectName("translationOutput")
        self.translate_output.setReadOnly(True)
        
        self.phonetic_output = QLabel()
        self.phonetic_output.setObjectName("phoneticOutput")
        self.definitions_output = QLabel()
        self.definitions_output.setObjectName("definitionsOutput")
        self.alternatives_output = QLabel()
        self.alternatives_output.setObjectName("alternativesOutput")
        
        right_layout.addLayout(output_header)
        right_layout.addWidget(self.translate_output)
        right_layout.addWidget(self.phonetic_output)
        right_layout.addWidget(self.definitions_output)
        right_layout.addWidget(self.alternatives_output)
        
        content_layout.addWidget(left_panel)
        content_layout.addWidget(right_panel)
        
        layout.addWidget(content_panel)
        
        btn_trans = QPushButton("Translate")
        btn_trans.setObjectName("translationButton")
        btn_trans.clicked.connect(self.do_translate)
        layout.addWidget(btn_trans)
        
        return tab
    
    def on_translate_success(self, response_data):
        self.translate_output.clear()
        self.phonetic_output.clear()
        self.definitions_output.clear()
        self.alternatives_output.clear()

        translated_data_from_server = response_data.get('translated_text', {}) 
        
        translation = translated_data_from_server.get('translated_text', '')
        phonetic = translated_data_from_server.get('phonetic', '')
        meanings = translated_data_from_server.get('meanings', [])
        alternatives = translated_data_from_server.get('alternatives', [])
        
        self.translate_output.setText(translation)
        self.phonetic_output.setText(f"IPA: {phonetic}" if phonetic else "")

        if meanings:
            meanings_text = '\n'.join(f"• {m['part_of_speech']}: {m['definition']}" for m in meanings)
            self.definitions_output.setText(meanings_text)
        else:
            self.definitions_output.setText("")

        if alternatives:
            alternatives_text = "Alternatives: " + ", ".join(alternatives)
            self.alternatives_output.setText(alternatives_text)
        else:
            self.alternatives_output.setText("")

    def _create_quiz_tab(self):
        tab = QWidget()
        self._configure_widget_focus(tab)
        layout = QVBoxLayout(tab)
        
        top_layout = QHBoxLayout()
        top_layout.addWidget(QLabel("Difficulty Level:"))
        self.quiz_level_combo = QComboBox(); self.quiz_level_combo.addItems(["A1", "A2", "B1", "B2", "C1", "C2"])
        top_layout.addWidget(self.quiz_level_combo)
        btn_quiz = QPushButton("Generate New Quiz"); btn_quiz.clicked.connect(self.generate_quiz)
        top_layout.addWidget(btn_quiz)
        layout.addLayout(top_layout)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        self.quiz_content_widget = QWidget()
        self.quiz_questions_layout = QVBoxLayout(self.quiz_content_widget)
        self.quiz_questions_layout.setAlignment(Qt.AlignTop)
        scroll_area.setWidget(self.quiz_content_widget)

        layout.addWidget(scroll_area)
        return tab

    def _create_history_tab(self):
        tab = QWidget()
        self._configure_widget_focus(tab)
        layout = QVBoxLayout(tab)
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(4)
        self.history_table.setHorizontalHeaderLabels(["Time", "Type", "Input", "Output"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        btn_load_history = QPushButton("Reload History"); btn_load_history.clicked.connect(self.load_history)
        layout.addWidget(btn_load_history)
        layout.addWidget(self.history_table)
        return tab

    def _create_notes_tab(self):
        tab = QWidget()
        self._configure_widget_focus(tab)
        layout = QVBoxLayout(tab)
        self.note_table = QTableWidget()
        self.note_table.setColumnCount(2)
        self.note_table.setHorizontalHeaderLabels(["Date", "Content"])
        self.note_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.note_input = QLineEdit(); self.note_input.setPlaceholderText("Enter a new note...")
        btn_save_note = QPushButton("Save Note"); btn_save_note.clicked.connect(self.save_note)
        btn_load_notes = QPushButton("Reload Notes"); btn_load_notes.clicked.connect(self.load_notes)
        
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(btn_load_notes)
        btn_layout.addWidget(btn_save_note)
        
        layout.addLayout(btn_layout)
        layout.addWidget(self.note_table)
        layout.addWidget(self.note_input)
        return tab

    def _execute_network_task(self, task_key, func, *args, **kwargs):
        worker = Worker(func, *args, **kwargs)
        thread = QThread()
        worker.moveToThread(thread)
        
        worker.error.connect(lambda e: self._on_task_error(task_key, e))
        thread.started.connect(worker.run)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        self.threadpool[task_key] = (thread, worker)
        return thread, worker

    def _on_task_error(self, task_key, error_msg):
        QMessageBox.critical(self, f"Error in {task_key}", error_msg)
        if task_key == "popup_translate":
            self.translation_popup.show_at_cursor("Translation Error")
            
    def do_login(self):
        payload = {"username": self.login_user.text(), "password": self.login_pass.text()}
        thread, worker = self._execute_network_task("login", requests.post, f"{API_BASE}/login", json=payload)
        worker.finished.connect(self.on_login_success)
        thread.start()

    def on_login_success(self, r):
        if r.status_code == 200:
            self.token = r.json().get('token')
            self.stack.setCurrentWidget(self.main_widget)
            self.load_history()
            self.load_notes()
        else:
            QMessageBox.warning(self, "Login Failed", r.json().get("error", "Unknown error"))
    
    def do_register(self):
        payload = {"username": self.login_user.text(), "password": self.login_pass.text()}
        thread, worker = self._execute_network_task("register", requests.post, f"{API_BASE}/register", json=payload)
        worker.finished.connect(self.on_register_success)
        thread.start()

    def on_register_success(self, r):
        if r.status_code == 201:
            QMessageBox.information(self, "Success", "Registration successful! Please login.")
        else:
            QMessageBox.warning(self, "Registration Failed", r.json().get("error", "Unknown error"))

    def do_translate(self):
        payload = {
            "token": self.token,
            "text": self.translate_input.toPlainText(),
            "from_lang": self.from_combo.currentText(),
            "to_lang": self.to_combo.currentText()
        }
        thread, worker = self._execute_network_task("translate", requests.post, f"{API_BASE}/translate", json=payload)
        worker.finished.connect(lambda r: self.on_translate_success(r.json()))
        thread.start()

    def generate_quiz(self):
        while self.quiz_questions_layout.count():
            item = self.quiz_questions_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self.quiz_answers.clear()
        self.quiz_button_groups.clear()

        payload = {"token": self.token, "difficulty": self.quiz_level_combo.currentText()}
        thread, worker = self._execute_network_task("quiz", requests.post, f"{API_BASE}/generate_quiz", json=payload)
        worker.finished.connect(self.on_quiz_generated)
        thread.start()

    def on_quiz_generated(self, r):
        if r.status_code == 200:
            self.display_quiz(r.json().get('questions', []))
        else:
            QMessageBox.warning(self, "API Error", r.json().get("error", "Failed to generate quiz"))

    def display_quiz(self, questions):
        for i, q_data in enumerate(questions):
            q_label = QLabel(f"<b>{i+1}. {q_data['question']}</b>"); q_label.setWordWrap(True)
            self.quiz_questions_layout.addWidget(q_label)
            
            self.quiz_answers[i] = q_data['answer']
            button_group = QButtonGroup(self)
            self.quiz_button_groups.append(button_group)

            for option_text in q_data['options']:
                radio_btn = QRadioButton(option_text)
                button_group.addButton(radio_btn)
                self.quiz_questions_layout.addWidget(radio_btn)

        submit_btn = QPushButton("Submit Answers")
        submit_btn.clicked.connect(self.check_quiz_answers)
        self.quiz_questions_layout.addWidget(submit_btn)

    def check_quiz_answers(self):
        for i, group in enumerate(self.quiz_button_groups):
            selected_btn = group.checkedButton()
            correct_answer = self.quiz_answers[i]
            
            for button in group.buttons():
                if button.text() == correct_answer:
                    button.setStyleSheet("""
                        QRadioButton {
                            color: #98C379;
                            font-weight: bold;
                        }
                        QRadioButton::indicator:checked {
                            background-color: #98C379;
                            border: 2px solid #98C379;
                        }
                    """)
                elif button == selected_btn and button.text() != correct_answer:
                    button.setStyleSheet("""
                        QRadioButton {
                            color: #E06C75;
                            font-weight: bold;
                        }
                        QRadioButton::indicator:checked {
                            background-color: #E06C75;
                            border: 2px solid #E06C75;
                        }
                    """)
                
    def load_history(self):
        payload = {"token": self.token}
        thread, worker = self._execute_network_task("history", requests.post, f"{API_BASE}/view_history", json=payload)
        worker.finished.connect(self.on_history_loaded)
        thread.start()
    
    def on_history_loaded(self, r):
        data = r.json()
        self.history_table.setRowCount(0)
        for item in data.get('history', []):
            if isinstance(item, dict):
                row = self.history_table.rowCount()
                self.history_table.insertRow(row)
                self.history_table.setItem(row, 0, QTableWidgetItem(str(item.get('timestamp', ''))))
                self.history_table.setItem(row, 1, QTableWidgetItem(str(item.get('type', ''))))
                self.history_table.setItem(row, 2, QTableWidgetItem(str(item.get('input', ''))))
                self.history_table.setItem(row, 3, QTableWidgetItem(str(item.get('output', ''))))

    def save_note(self):
        payload = {"token": self.token, "content": self.note_input.text()}
        thread, worker = self._execute_network_task("save_note", requests.post, f"{API_BASE}/save_note", json=payload)
        worker.finished.connect(lambda r: self.load_notes() if r.status_code == 200 else None)
        thread.start()
        self.note_input.clear()

    def load_notes(self):
        payload = {"token": self.token}
        thread, worker = self._execute_network_task("load_notes", requests.post, f"{API_BASE}/view_note", json=payload)
        worker.finished.connect(self.on_notes_loaded)
        thread.start()

    def on_notes_loaded(self, r):
        data = r.json()
        dates = data.get("created_day", [])
        content = data.get("content", [])
        self.note_table.setRowCount(0)
        for d, c in zip(dates, content):
            row = self.note_table.rowCount()
            self.note_table.insertRow(row)
            self.note_table.setItem(row, 0, QTableWidgetItem(d))
            self.note_table.setItem(row, 1, QTableWidgetItem(c))

    def on_hotkey_translate(self, txt):
        if not txt:
            self.translation_popup.show_at_cursor("Please select text to translate.")
            return
        
        # Kiểm tra nếu đang trong quá trình dịch
        if self.translation_popup.is_translating:
            self.translation_popup.show_at_cursor("Please wait for current translation to complete.")
            return
                
        self.translation_popup.show_loading()
        payload = {
            "text": txt,
            "from_lang": "auto", 
            "to_lang": "vi"
        }

        thread, worker = self._execute_network_task(
            "popup_translate", 
            requests.post, 
            f"{API_BASE}/translate_without_auth", 
            json=payload
        )
        worker.finished.connect(self.on_popup_translate_finished)
        thread.start()

    def on_popup_translate_finished(self, r):
        if r.status_code == 200:
            response_data = r.json().get('translated_text', {})
            self.translation_popup.show_at_cursor(response_data)
        else:
            self.translation_popup.show_at_cursor(f"Error: {r.json().get('error', 'Unknown')}")
        self.translation_popup.is_translating = False

    def closeEvent(self, event):
        if self.tray_icon.isVisible():
            self.hide()
            self.tray_icon.showMessage(
                "SuperFastLTM Client",
                "Application was minimized to tray",
                QSystemTrayIcon.Information,
                2000
            )
            event.ignore()

    def quit_application(self):
        self.tray_icon.hide()
        QApplication.quit()

    def tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            self.activateWindow()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    app.setQuitOnLastWindowClosed(False)
    
    window = ClientUI()
    window.tray_icon.showMessage(
        "SuperFastLTM Client",
        "Application is running in the background. Double-click the tray icon to show the home page window.",
        QSystemTrayIcon.Information,
        3000
    )
    sys.exit(app.exec_())