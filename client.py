# client.py

import sys
import time
import requests
import pyperclip
import keyboard  # pip install keyboard pyperclip
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QStackedWidget, QTabWidget,
    QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit,
    QComboBox, QMessageBox, QTableWidget, QTableWidgetItem
)

API_BASE = "http://127.0.0.1:8000"


class HotkeyListener(QThread):
    selection_captured = pyqtSignal(str)

    def run(self):
        last_clip = pyperclip.paste()
        while True:
            keyboard.wait('ctrl+b')
            keyboard.press_and_release('ctrl+c')
            time.sleep(0.05)
            txt = pyperclip.paste()
            # Restore previous clipboard
            pyperclip.copy(last_clip)
            last_clip = txt
            self.selection_captured.emit(txt)


class ClientUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SuperFastLTM Client")
        self.resize(800, 600)
        self.token = None

        # Stacked widget: login/register page vs main app
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.login_widget = self._create_login_widget()
        self.main_widget = self._create_main_widget()

        self.stack.addWidget(self.login_widget)
        self.stack.addWidget(self.main_widget)

        # Start hotkey listener thread
        self.hotkey_thread = HotkeyListener()
        self.hotkey_thread.selection_captured.connect(self.on_selection)
        self.hotkey_thread.start()

    def _create_login_widget(self):
        w = QWidget()
        layout = QVBoxLayout(w)

        tabs = QTabWidget()
        layout.addWidget(tabs)

        # --- Login tab ---
        login_tab = QWidget()
        ll = QVBoxLayout(login_tab)
        self.login_user = QLineEdit(); self.login_user.setPlaceholderText("Username")
        self.login_pass = QLineEdit(); self.login_pass.setPlaceholderText("Password")
        self.login_pass.setEchoMode(QLineEdit.Password)
        btn_login = QPushButton("Login")
        btn_login.clicked.connect(self.login)

        ll.addWidget(QLabel("Username"))
        ll.addWidget(self.login_user)
        ll.addWidget(QLabel("Password"))
        ll.addWidget(self.login_pass)
        ll.addWidget(btn_login)

        # --- Register tab ---
        reg_tab = QWidget()
        rl = QVBoxLayout(reg_tab)
        self.reg_user = QLineEdit(); self.reg_user.setPlaceholderText("Username")
        self.reg_pass = QLineEdit(); self.reg_pass.setPlaceholderText("Password")
        self.reg_pass.setEchoMode(QLineEdit.Password)
        btn_reg = QPushButton("Register")
        btn_reg.clicked.connect(self.register)

        rl.addWidget(QLabel("Username"))
        rl.addWidget(self.reg_user)
        rl.addWidget(QLabel("Password"))
        rl.addWidget(self.reg_pass)
        rl.addWidget(btn_reg)

        tabs.addTab(login_tab, "Login")
        tabs.addTab(reg_tab,   "Register")

        return w

    def _create_main_widget(self):
        w = QWidget()
        layout = QVBoxLayout(w)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # --- Translate tab ---
        t_tab = QWidget()
        tl = QVBoxLayout(t_tab)
        self.from_combo = QComboBox(); self.from_combo.addItems(["auto", "en", "fr", "es"])
        self.to_combo   = QComboBox(); self.to_combo.addItems(["vi", "en", "fr"])
        self.translate_input  = QTextEdit()
        self.translate_output = QTextEdit(); self.translate_output.setReadOnly(True)
        btn_trans = QPushButton("Translate")
        btn_trans.clicked.connect(self.do_translate)

        tl.addWidget(QLabel("From"))
        tl.addWidget(self.from_combo)
        tl.addWidget(QLabel("To"))
        tl.addWidget(self.to_combo)
        tl.addWidget(QLabel("Text to translate"))
        tl.addWidget(self.translate_input)
        tl.addWidget(btn_trans)
        tl.addWidget(QLabel("Result"))
        tl.addWidget(self.translate_output)

        self.tabs.addTab(t_tab, "Translate")

        # --- Quiz tab ---
        quiz_tab = QWidget()
        ql = QVBoxLayout(quiz_tab)
        self.quiz_combo  = QComboBox(); self.quiz_combo.addItems(["A1", "A2", "B1", "B2", "C1", "C2"])
        self.quiz_output = QTextEdit();  self.quiz_output.setReadOnly(True)
        btn_quiz = QPushButton("Generate Quiz")
        btn_quiz.clicked.connect(self.generate_quiz)

        ql.addWidget(QLabel("Difficulty"))
        ql.addWidget(self.quiz_combo)
        ql.addWidget(btn_quiz)
        ql.addWidget(QLabel("Quiz"))
        ql.addWidget(self.quiz_output)

        self.tabs.addTab(quiz_tab, "Quiz")

        # --- History tab ---
        hist_tab = QWidget()
        hl = QVBoxLayout(hist_tab)
        btn_hist = QPushButton("Load History")
        btn_hist.clicked.connect(self.load_history)
        self.hist_table = QTableWidget(0, 2)
        self.hist_table.setHorizontalHeaderLabels(["Date", "Content"])

        hl.addWidget(btn_hist)
        hl.addWidget(self.hist_table)
        self.tabs.addTab(hist_tab, "History")

        # --- Notes tab ---
        note_tab = QWidget()
        nl = QVBoxLayout(note_tab)
        self.note_input = QTextEdit()
        btn_add_note  = QPushButton("Add Note")
        btn_add_note.clicked.connect(self.add_note)
        btn_load_note = QPushButton("Load Notes")
        btn_load_note.clicked.connect(self.load_notes)
        self.note_table = QTableWidget(0, 2)
        self.note_table.setHorizontalHeaderLabels(["Date", "Content"])

        nl.addWidget(QLabel("New Note"))
        nl.addWidget(self.note_input)
        nl.addWidget(btn_add_note)
        nl.addWidget(btn_load_note)
        nl.addWidget(self.note_table)

        self.tabs.addTab(note_tab, "Notes")

        return w

    def register(self):
        u = self.reg_user.text().strip()
        p = self.reg_pass.text().strip()
        if not u or not p:
            QMessageBox.warning(self, "Error", "Username & password required")
            return
        try:
            r = requests.post(f"{API_BASE}/register", json={"username": u, "password": p})
            if r.status_code == 201:
                QMessageBox.information(self, "Success", "Registered successfully")
                self.reg_user.clear()
                self.reg_pass.clear()
            else:
                QMessageBox.warning(self, "Failed", r.json().get("error", "Error"))
        except Exception as e:
            QMessageBox.critical(self, "Network Error", str(e))

    def login(self):
        u = self.login_user.text().strip()
        p = self.login_pass.text().strip()
        if not u or not p:
            QMessageBox.warning(self, "Error", "Username & password required")
            return
        try:
            r = requests.post(f"{API_BASE}/login", json={"username": u, "password": p})
            if r.status_code == 200:
                self.token = r.json().get("token")
                QMessageBox.information(self, "Success", "Login successful")
                self.stack.setCurrentIndex(1)
            else:
                QMessageBox.warning(self, "Failed", r.json().get("error", "Error"))
        except Exception as e:
            QMessageBox.critical(self, "Network Error", str(e))

    def do_translate(self):
        text = self.translate_input.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "Error", "Please enter text to translate.")
            return
        payload = {
            "text": text,
            "from_lang": self.from_combo.currentText(),
            "to_lang":   self.to_combo.currentText()
        }
        try:
            r = requests.post(f"{API_BASE}/translate", json=payload)
            data = r.json()
            if r.status_code == 200:
                self.translate_output.setPlainText(data["translated_text"])
            else:
                QMessageBox.critical(self, "API Error", data.get("error", "Unknown error"))
        except Exception as e:
            QMessageBox.critical(self, "Network Error", str(e))

    def generate_quiz(self):
        level = self.quiz_combo.currentText()
        try:
            r = requests.post(f"{API_BASE}/generate_quiz", json={"difficulty": level})
            data = r.json()
            if r.status_code == 200:
                self.quiz_output.setPlainText(data["quiz"])
            else:
                QMessageBox.warning(self, "API Error", data.get("error", ""))
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def load_history(self):
        try:
            r = requests.post(f"{API_BASE}/view_history", json={"token": self.token})
            data = r.json()
            dates   = data.get("created_day", [])
            content = data.get("content", [])
            self.hist_table.setRowCount(0)
            for d, c in zip(dates, content):
                row = self.hist_table.rowCount()
                self.hist_table.insertRow(row)
                self.hist_table.setItem(row, 0, QTableWidgetItem(d))
                self.hist_table.setItem(row, 1, QTableWidgetItem(c))
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def add_note(self):
        text = self.note_input.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "Error", "Please enter a note.")
            return
        try:
            r = requests.post(
                f"{API_BASE}/add_note",
                json={"token": self.token, "content": text}
            )
            if r.status_code == 200:
                QMessageBox.information(self, "Success", "Note added.")
                self.note_input.clear()
            else:
                QMessageBox.warning(self, "Error", r.json().get("error", ""))
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def load_notes(self):
        try:
            r = requests.post(f"{API_BASE}/view_note", json={"token": self.token})
            data = r.json()
            dates   = data.get("created_day", [])
            content = data.get("content", [])
            self.note_table.setRowCount(0)
            for d, c in zip(dates, content):
                row = self.note_table.rowCount()
                self.note_table.insertRow(row)
                self.note_table.setItem(row, 0, QTableWidgetItem(d))
                self.note_table.setItem(row, 1, QTableWidgetItem(c))
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_selection(self, txt):
        if not txt:
            return

        # 1) Nếu app đang bị thu nhỏ hoặc đang ở trang login, khôi phục và show main
        self.showNormal()              # bỏ minimize
        self.activateWindow()          # active window
        self.raise_()                  # kéo lên trên cùng
        self.stack.setCurrentIndex(1)  # đảm bảo đang ở main_widget  

        # 2) Chuyển sang tab Translate (index 0 trong main_widget)
        self.tabs.setCurrentIndex(0)
        self.translate_input.setPlainText(txt)

        # 3) Delay rồi gọi API dịch
        QTimer.singleShot(100, self.do_translate)



if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ClientUI()
    window.show()
    sys.exit(app.exec_())
