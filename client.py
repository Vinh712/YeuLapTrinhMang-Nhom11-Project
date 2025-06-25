import sys
import time
import requests
import pyperclip
import keyboard
import json
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
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

# Asyncio support
import asyncio
from functools import partial
import qasync
from qasync import asyncSlot

# Shared AES encryption key for client-server communication
SHARED_AES_KEY = "SuperFastLTM_2025_SecureKey_32B!"  # 32-byte secret
API_BASE = "http://127.0.0.1:8000"

class AESCrypto:
    def __init__(self, key=None):
        if key is None:
            self.key = get_random_bytes(32)
        else:
            if isinstance(key, str):
                key = key.encode('utf-8')
            # pad or truncate to 32 bytes
            key = (key + b'0'*32)[:32]
            self.key = key

    def encrypt(self, data):
        # convert dict/list to JSON string
        if isinstance(data, (dict, list)):
            data = json.dumps(data, ensure_ascii=False)
        # to bytes
        if isinstance(data, str):
            data = data.encode('utf-8')
        # random IV
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded = pad(data, AES.block_size)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(iv + encrypted).decode('utf-8')

    def decrypt(self, encrypted_data):
        raw = base64.b64decode(encrypted_data)
        iv, ct = raw[:16], raw[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ct)
        data = unpad(padded, AES.block_size)
        text = data.decode('utf-8')
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text


def create_shared_crypto():
    # derive key from secret
    key = hashlib.sha256(SHARED_AES_KEY.encode('utf-8')).digest()
    return AESCrypto(key)


def encrypt_communication_data(data):
    return create_shared_crypto().encrypt(data)


def decrypt_communication_data(data):
    return create_shared_crypto().decrypt(data)

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

class TranslationPopup(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        # frameless always-on-top popup
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_ShowWithoutActivating)

        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)

        # container with dark background
        self.container = QWidget()
        self.container.setObjectName('popupContainer')
        self.container.setStyleSheet(
            '#popupContainer { background-color: #2D2D2D; border:1px solid #404040; border-radius:8px; }'
        )
        self.container_layout = QVBoxLayout(self.container)
        self.container_layout.setContentsMargins(16,16,16,16)

        # close and open buttons
        btn_layout = QHBoxLayout()
        self.open_btn = QPushButton('≡')
        self.open_btn.setFixedSize(20,20)
        self.open_btn.clicked.connect(self.show_main)
        self.close_btn = QPushButton('✕')
        self.close_btn.setFixedSize(20,20)
        self.close_btn.clicked.connect(self.hide)
        btn_layout.addWidget(self.open_btn)
        btn_layout.addWidget(self.close_btn, alignment=Qt.AlignRight)
        self.container_layout.addLayout(btn_layout)

        # content labels
        self.trans_text = QLabel()
        self.trans_text.setObjectName('popupTransText')
        self.trans_text.setWordWrap(True)
        self.phonetic = QLabel()
        self.defs = QLabel()
        self.alts = QLabel()
        for w in (self.trans_text, self.phonetic, self.defs, self.alts):
            self.container_layout.addWidget(w)

        self.main_layout.addWidget(self.container)

        self.hide_timer = QTimer(self)
        self.hide_timer.setSingleShot(True)
        self.hide_timer.timeout.connect(self.hide)

        self.resize(400,250)

    def show_main(self):
        self.main_window.show()
        self.main_window.activateWindow()

    def show_loading(self):
        self.trans_text.setText('Translating...')
        self.phonetic.hide(); self.defs.hide(); self.alts.hide()
        self.show()

    def show_translation(self, data):
        # unified display logic for basic & advanced
        self.trans_text.setText(data.get('translated_text',''))
        # phonetic & definitions
        phon = data.get('phonetic') or None
        if phon:
            self.phonetic.setText(phon)
            self.phonetic.show()
        else:
            self.phonetic.hide()
        meanings = data.get('meanings') or []
        if meanings:
            text = '\n'.join(f"• {m['part_of_speech']}: {m['definition']}" for m in meanings)
            self.defs.setText(text); self.defs.show()
        else:
            self.defs.hide()
        alts = data.get('alternatives') or []
        if alts:
            self.alts.setText('Alternatives: '+', '.join(alts)); self.alts.show()
        else:
            self.alts.hide()
        self.show(); self.hide_timer.start(10000)

    def show_at_cursor(self, data):
        self.show_translation(data)

class ClientUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.token = None
        self.setup_ui()
        # start hotkey listener
        self.hotkey = HotkeyListener()
        self.hotkey.selection_captured.connect(self.on_hotkey_translate)
        self.hotkey.start()

    def setup_ui(self):
        self.setWindowTitle('SuperFastLTM Client')
        self.resize(800,600)
        # system tray
        tray = QSystemTrayIcon(self)
        tray.setIcon(QIcon(self.style().standardIcon(QStyle.SP_MessageBoxInformation)))
        menu = QMenu()
        menu.addAction('Show', self.show)
        menu.addAction('Quit', self.quit_application)
        tray.setContextMenu(menu)
        tray.show()

        # translation popup
        self.popup = TranslationPopup(self)

        # stacked widgets
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        self.login_widget = self._create_login_widget()
        self.main_widget = self._create_main_widget()
        self.stack.addWidget(self.login_widget)
        self.stack.addWidget(self.main_widget)
        self.stack.setCurrentWidget(self.login_widget)

    def _create_login_widget(self):
        w = QWidget(); l = QVBoxLayout(w)
        l.setAlignment(Qt.AlignCenter)
        title = QLabel('Welcome to SuperFastLTM'); title.setStyleSheet('font:24pt; color:#61AFEF;')
        l.addWidget(title)
        self.username_input = QLineEdit(); self.username_input.setPlaceholderText('Username')
        self.username_input.setFixedSize(300,40); l.addWidget(self.username_input)
        self.password_input = QLineEdit(); self.password_input.setPlaceholderText('Password')
        self.password_input.setEchoMode(QLineEdit.Password); self.password_input.setFixedSize(300,40)
        l.addWidget(self.password_input)
        login_btn = QPushButton('Login'); login_btn.setFixedSize(300,40)
        login_btn.clicked.connect(lambda: asyncio.create_task(self.login()))
        register_btn = QPushButton('Register'); register_btn.setFixedSize(300,40)
        register_btn.clicked.connect(lambda: asyncio.create_task(self.register()))
        l.addWidget(login_btn); l.addWidget(register_btn)
        return w

    def _create_main_widget(self):
        w = QWidget(); l = QVBoxLayout(w)
        tabs = QTabWidget(); l.addWidget(tabs)
        tabs.addTab(self._create_translate_tab(), 'Translate')
        tabs.addTab(self._create_quiz_tab(), 'Quiz')
        tabs.addTab(self._create_history_tab(), 'History')
        tabs.addTab(self._create_note_tab(), 'Notes')
        tabs.addTab(self._create_ranking_tab(), 'Ranking')
        return w

    def _create_translate_tab(self):
        tab = QWidget(); l = QVBoxLayout(tab)
        # input
        frame = QFrame(); il = QVBoxLayout(frame)
        il.addWidget(QLabel('Text to Translate:'))
        self.translate_input = QTextEdit(); il.addWidget(self.translate_input)
        # type selection
        hl = QHBoxLayout(); hl.addWidget(QLabel('Type:'))
        self.basic_radio = QRadioButton('Basic'); self.basic_radio.setChecked(True)
        self.advanced_radio = QRadioButton('Advanced'); hl.addWidget(self.basic_radio); hl.addWidget(self.advanced_radio); hl.addStretch()
        il.addLayout(hl)
        trans_btn = QPushButton('Translate'); trans_btn.clicked.connect(lambda: asyncio.create_task(self.translate_text()))
        il.addWidget(trans_btn)
        l.addWidget(frame)
        # output
        frame2 = QFrame(); ol = QVBoxLayout(frame2)
        ol.addWidget(QLabel('Result:'))
        self.translate_output = QTextEdit(); self.translate_output.setReadOnly(True)
        ol.addWidget(self.translate_output); l.addWidget(frame2)
        return tab

    def _create_quiz_tab(self):
        tab = QWidget(); l = QVBoxLayout(tab)
        hl = QHBoxLayout(); hl.addWidget(QLabel('Difficulty:'))
        self.difficulty_combo = QComboBox(); self.difficulty_combo.addItems(['A1','A2','B1','B2','C1','C2']); hl.addWidget(self.difficulty_combo); hl.addStretch(); l.addLayout(hl)
        gen_btn = QPushButton('Generate Quiz'); gen_btn.clicked.connect(lambda: asyncio.create_task(self.generate_quiz())); l.addWidget(gen_btn)
        self.quiz_area = QScrollArea(); content = QWidget(); self.quiz_layout = QVBoxLayout(content)
        self.quiz_area.setWidgetResizable(True); self.quiz_area.setWidget(content); l.addWidget(self.quiz_area)
        self.submit_quiz_btn = QPushButton('Submit Quiz'); self.submit_quiz_btn.clicked.connect(lambda: asyncio.create_task(self.submit_quiz())); self.submit_quiz_btn.hide(); l.addWidget(self.submit_quiz_btn)
        self.view_result_btn = QPushButton('View Quiz Result'); self.view_result_btn.clicked.connect(self.show_quiz_result); self.view_result_btn.hide(); l.addWidget(self.view_result_btn)
        return tab

    def _create_history_tab(self):
        tab = QWidget(); l = QVBoxLayout(tab)
        refresh_btn = QPushButton('Refresh History'); refresh_btn.clicked.connect(lambda: asyncio.create_task(self.load_history())); l.addWidget(refresh_btn)
        self.history_table = QTableWidget(); self.history_table.setColumnCount(2); self.history_table.setHorizontalHeaderLabels(['Date','Type','Content'])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); l.addWidget(self.history_table)
        return tab

    def _create_note_tab(self):
        tab = QWidget(); l = QVBoxLayout(tab)
        hl = QHBoxLayout(); self.note_input = QLineEdit(); self.note_input.setPlaceholderText('Enter your note here...'); hl.addWidget(self.note_input)
        save_btn = QPushButton('Save Note'); save_btn.clicked.connect(lambda: asyncio.create_task(self.save_note())); hl.addWidget(save_btn); l.addLayout(hl)
        refresh_btn = QPushButton('Refresh Notes'); refresh_btn.clicked.connect(lambda: asyncio.create_task(self.load_notes())); l.addWidget(refresh_btn)
        self.notes_table = QTableWidget(); self.notes_table.setColumnCount(2); self.notes_table.setHorizontalHeaderLabels(['Date','Note'])
        self.notes_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); l.addWidget(self.notes_table)
        return tab

    def _create_ranking_tab(self):
        tab = QWidget(); l = QVBoxLayout(tab)
        refresh_btn = QPushButton('Refresh Ranking'); refresh_btn.clicked.connect(lambda: asyncio.create_task(self.load_ranking())); l.addWidget(refresh_btn)
        self.ranking_table = QTableWidget(); self.ranking_table.setColumnCount(3); self.ranking_table.setHorizontalHeaderLabels(['Rank','Username','Points'])
        self.ranking_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); l.addWidget(self.ranking_table)
        self.ranking_stats_label = QLabel(''); l.addWidget(self.ranking_stats_label)
        return tab

    async def async_api_call(self, endpoint, method='POST', data=None):
        loop = asyncio.get_event_loop()
        fn = partial(self.encrypted_api_call, endpoint, method, data)
        return await loop.run_in_executor(None, fn)

    def encrypted_api_call(self, endpoint, method='POST', data=None):
        try:
            payload = {'encrypted_data': encrypt_communication_data(data)} if data else None
            if method == 'POST':
                response = requests.post(API_BASE+endpoint, json=payload)
            else:
                response = requests.get(API_BASE+endpoint)
            response.raise_for_status()
            resp = response.json()
            if isinstance(resp, dict) and 'encrypted_data' in resp:
                return decrypt_communication_data(resp['encrypted_data'])
            return resp
        except Exception as e:
            raise Exception(f'API call failed: {e}')

    async def login(self):
        try:
            data = await self.async_api_call('/login', 'POST', {'username': self.username_input.text(), 'password': self.password_input.text()})
            if 'token' in data:
                self.token = data['token']
                self.stack.setCurrentWidget(self.main_widget)
                self.show_message('Login Success', 'Logged in successfully!')
                await self.load_history(); await self.load_notes(); await self.load_ranking()
            else:
                self.show_message('Login Failed', data.get('error', 'Unknown error'), QMessageBox.Warning)
        except Exception as e:
            self.show_message('Login Error', str(e), QMessageBox.Warning)

    async def register(self):
        try:
            data = await self.async_api_call('/register', 'POST', {'username': self.username_input.text(), 'password': self.password_input.text()})
            self.show_message('Registration Success', data.get('message', ''))
        except Exception as e:
            self.show_message('Registration Error', str(e), QMessageBox.Warning)

    async def translate_text(self):
        text = self.translate_input.toPlainText().strip()
        if not text:
            self.show_message('Error', 'Please enter text to translate.', QMessageBox.Warning)
            return
        endpoint = '/translate_basic' if self.basic_radio.isChecked() else '/translate_advanced'
        try:
            data = await self.async_api_call(endpoint, 'POST', {'token': self.token, 'text': text, 'from_lang': 'en', 'to_lang': 'vi'})
            translated = data.get('translated_data', {}).get('translated_text', '')
            self.translate_output.setText(translated)
            await self.load_history()
        except Exception as e:
            self.show_message('Translation Error', str(e), QMessageBox.Warning)

    async def generate_quiz(self):
        try:
            data = await self.async_api_call('/generate_quiz', 'POST', {'token': self.token, 'difficulty': self.difficulty_combo.currentText()})
            questions = data.get('questions', [])
            # clear old
            for i in reversed(range(self.quiz_layout.count())):
                widget = self.quiz_layout.itemAt(i).widget()
                if widget: widget.setParent(None)
            self.button_groups = []
            for idx, q in enumerate(questions):
                lbl = QLabel(f'Q{idx+1}: {q["question"]}')
                self.quiz_layout.addWidget(lbl)
                group = QButtonGroup(self)
                self.button_groups.append(group)
                for opt in q.get('options', []):
                    rb = QRadioButton(opt)
                    group.addButton(rb)
                    self.quiz_layout.addWidget(rb)
            self.submit_quiz_btn.show()
        except Exception as e:
            self.show_message('Quiz Generation Error', str(e), QMessageBox.Warning)

    async def submit_quiz(self):
        answers = {}
        for idx, group in enumerate(self.button_groups):
            btn = group.checkedButton()
            answers[str(idx)] = btn.text() if btn else ''
        try:
            data = await self.async_api_call('/submit_quiz', 'POST', {'token': self.token, 'user_answers': answers, 'difficulty': self.difficulty_combo.currentText()})
            self.last_quiz_result = data.get('result', {})
            self.show_message('Quiz Submitted', data.get('message', ''))
            self.submit_quiz_btn.hide()
            self.view_result_btn.show()
            await self.load_ranking(); await self.load_history()
        except Exception as e:
            self.show_message('Quiz Submit Error', str(e), QMessageBox.Warning)

    def show_quiz_result(self):
        r = getattr(self, 'last_quiz_result', None)
        if not r:
            self.show_message('Error', 'No result to show.', QMessageBox.Warning)
            return
        text = f"Score: {r.get('score')}\nCorrect: {r.get('correct_count')}/{r.get('total_questions')}\nPercentage: {r.get('percentage'): .2f}%\n"
        self.show_message('Quiz Result', text)

    async def load_history(self):
        try:
            data = await self.async_api_call('/view_history', 'POST', {'token': self.token})
            history = data.get('history', [])
            self.history_table.setRowCount(0)
            for i, entry in enumerate(history):
                self.history_table.insertRow(i)
                self.history_table.setItem(i, 0, QTableWidgetItem(entry.get('created_day','')))
                c = entry.get('content', {})
                t = c.get('type','')
                self.history_table.setItem(i,1,QTableWidgetItem(t))
                self.history_table.setItem(i,2,QTableWidgetItem(str(c)))
        except:
            pass

    async def save_note(self):
        note = self.note_input.text().strip()
        if not note:
            self.show_message('Error','Note cannot be empty.', QMessageBox.Warning)
            return
        try:
            data = await self.async_api_call('/save_note','POST',{'token': self.token,'content': note})
            self.show_message('Note Saved',data.get('message',''))
            await self.load_notes()
        except Exception as e:
            self.show_message('Save Note Error', str(e), QMessageBox.Warning)

    async def load_notes(self):
        try:
            data = await self.async_api_call('/view_note','POST',{'token': self.token})
            notes = data.get('notes', [])
            self.notes_table.setRowCount(0)
            for i,n in enumerate(notes):
                self.notes_table.insertRow(i)
                self.notes_table.setItem(i,0,QTableWidgetItem(n.get('created_day','')))
                self.notes_table.setItem(i,1,QTableWidgetItem(n.get('content','')))
        except:
            pass

    async def load_ranking(self):
        try:
            data = await self.async_api_call('/get_ranking','GET')
            users = data.get('top_users', [])
            self.ranking_table.setRowCount(0)
            for i,u in enumerate(users):
                self.ranking_table.insertRow(i)
                self.ranking_table.setItem(i,0,QTableWidgetItem(str(u.get('rank',''))))
                self.ranking_table.setItem(i,1,QTableWidgetItem(u.get('username','')))
                self.ranking_table.setItem(i,2,QTableWidgetItem(str(u.get('point',''))))
            stats = data.get('stats', {})
            text = f"Total: {stats.get('total_users',0)} | Top: {stats.get('top_user',{}).get('username','')}"  
            self.ranking_stats_label.setText(text)
        except:
            pass

    def show_message(self, title, msg, icon=QMessageBox.Information):
        box = QMessageBox(self)
        box.setIcon(icon)
        box.setWindowTitle(title)
        box.setText(msg)
        box.exec_()

    @asyncSlot(str)
    def on_hotkey_translate(self, text):
        if not self.token:
            return
        self.popup.show_loading()
        asyncio.create_task(self._do_hotkey_translate(text))

    async def _do_hotkey_translate(self, text):
        try:
            data = await self.async_api_call('/translate_advanced','POST',{'token': self.token,'text': text,'from_lang':'en','to_lang':'vi'})
            self.popup.show_translation(data.get('translated_data', {}))
            await self.load_history()
        except Exception as e:
            self.popup.show_at_cursor(str(e))

    def quit_application(self):
        self.hotkey.quit(); self.hotkey.wait()
        QApplication.quit()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)
    window = ClientUI()
    window.show()
    with loop:
        loop.run_forever()
