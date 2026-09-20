from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from PySide6.QtCore import QSettings, QStandardPaths, Qt, QThreadPool, QTimer
from PySide6.QtGui import QAction, QClipboard
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QFileDialog, QFormLayout, QFrame,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit,
    QProgressBar, QPushButton, QSpinBox, QStackedWidget, QTableWidget,
    QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

from cryptography.hazmat.primitives.asymmetric import ed25519

from cryptovault import __version__
from cryptovault.core.container import decrypt_container, decrypt_file, dumps_container, encrypt_bytes, encrypt_file, loads_container, validate_container_checksum
from cryptovault.core.hashing import compare_digest, hash_file
from cryptovault.core.keys import generate_private_key, key_description, load_private_key, load_public_key, save_private_key, save_public_key
from cryptovault.core.learning import caesar, random_substitution_alphabet, substitution, vigenere, xor_cipher
from cryptovault.core.passwords import assess_password
from cryptovault.core.signatures import create_detached_signature, verify_detached_signature
from cryptovault.security.auth import SessionGuard
from cryptovault.storage.archives import pack_folder, unpack_folder
from cryptovault.storage.history import HistoryStore
from .theme import APP_STYLE
from .widgets import PathPicker, Worker, card, page_header


def _open_file(edit: QLineEdit, pattern: str = "All files (*)"):
    path, _ = QFileDialog.getOpenFileName(edit, "Select file", "", pattern)
    if path:
        edit.setText(path)


def _open_folder(edit: QLineEdit):
    path = QFileDialog.getExistingDirectory(edit, "Select folder")
    if path:
        edit.setText(path)


def _save_file(edit: QLineEdit, pattern: str = "All files (*)"):
    path, _ = QFileDialog.getSaveFileName(edit, "Save as", "", pattern)
    if path:
        edit.setText(path)


class CryptoOptions(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        form = QFormLayout(self)
        self.algorithm = QComboBox(); self.algorithm.addItems(["AES-256-GCM", "ChaCha20-Poly1305"])
        self.protection = QComboBox(); self.protection.addItems(["Password", "RSA-4096", "X25519 ECDH"])
        self.kdf = QComboBox(); self.kdf.addItems(["Argon2id", "scrypt", "PBKDF2-SHA256"])
        self.password = QLineEdit(); self.password.setEchoMode(QLineEdit.Password); self.password.setPlaceholderText("Never stored")
        self.key_path = PathPicker("Recipient public key (.pem)", lambda edit: _open_file(edit, "PEM keys (*.pem);;All files (*)"))
        self.strength = QLabel("Enter a strong passphrase")
        self.strength.setObjectName("Muted")
        form.addRow("Content cipher", self.algorithm)
        form.addRow("Key protection", self.protection)
        form.addRow("Password KDF", self.kdf)
        form.addRow("Password", self.password)
        form.addRow("Strength", self.strength)
        form.addRow("Recipient public key", self.key_path)
        self.protection.currentTextChanged.connect(self._update_visibility)
        self.password.textChanged.connect(self._strength)
        self._update_visibility()

    def _update_visibility(self):
        password_mode = self.protection.currentText() == "Password"
        self.kdf.setEnabled(password_mode)
        self.password.setEnabled(password_mode)
        self.key_path.setEnabled(not password_mode)

    def _strength(self, value: str):
        result = assess_password(value)
        colors = ["#ef6b73", "#ff8c69", "#ffca6b", "#65e3bd", "#36d7a5"]
        self.strength.setText(result.label + (" — " + "; ".join(result.suggestions) if result.suggestions else ""))
        self.strength.setStyleSheet(f"color: {colors[result.score]};")

    def kwargs(self):
        protection = self.protection.currentText()
        args = {"algorithm": self.algorithm.currentText(), "protection": protection}
        if protection == "Password":
            args.update(password=self.password.text(), kdf=self.kdf.currentText())
        else:
            if not self.key_path.text():
                raise ValueError("Select the recipient public key")
            args["public_key"] = load_public_key(self.key_path.text())
        return args


class DecryptionCredentials(QWidget):
    def __init__(self):
        super().__init__()
        form = QFormLayout(self)
        self.password = QLineEdit(); self.password.setEchoMode(QLineEdit.Password)
        self.key_path = PathPicker("Private key (.pem), if required", lambda edit: _open_file(edit, "PEM keys (*.pem);;All files (*)"))
        self.key_password = QLineEdit(); self.key_password.setEchoMode(QLineEdit.Password)
        form.addRow("Container password", self.password)
        form.addRow("Private key", self.key_path)
        form.addRow("Private key password", self.key_password)

    def kwargs(self):
        key = None
        if self.key_path.text():
            key = load_private_key(self.key_path.text(), self.key_password.text() or None)
        return {"password": self.password.text(), "private_key": key}


class DashboardPage(QWidget):
    def __init__(self, history: HistoryStore):
        super().__init__(); self.history = history
        layout = QVBoxLayout(self); layout.addLayout(page_header("Security dashboard", "Local-only authenticated encryption. No files or credentials leave this device."))
        row = QHBoxLayout()
        for title, value, color in (("Default cipher", "AES-256-GCM", "#65e3bd"), ("Container format", "v1 • Authenticated", "#6cb6ff"), ("Password KDF", "Argon2id", "#c9a7ff")):
            frame, body = card(title); label = QLabel(value); label.setStyleSheet(f"font-size: 16pt; color: {color};"); body.addWidget(label); row.addWidget(frame)
        layout.addLayout(row)
        recent, body = card("Recent operations")
        self.table = QTableWidget(0, 5); self.table.setHorizontalHeaderLabels(["Time (UTC)", "Action", "Item", "Algorithm", "Status"]); self.table.horizontalHeader().setStretchLastSection(True); self.table.setAlternatingRowColors(True)
        body.addWidget(self.table); layout.addWidget(recent, 1)
        export = QPushButton("Export audit report…"); export.clicked.connect(self.export_report); layout.addWidget(export, 0, Qt.AlignRight)
        self.refresh()

    def refresh(self):
        records = self.history.list(50); self.table.setRowCount(len(records))
        for row, record in enumerate(records):
            for col, value in enumerate((record.timestamp, record.action, record.item, record.algorithm, record.status)):
                self.table.setItem(row, col, QTableWidgetItem(value))

    def export_report(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export audit report", "cryptovault-audit.csv", "CSV (*.csv)")
        if path: self.history.export(path)


class EncryptPage(QWidget):
    def __init__(self, window):
        super().__init__(); self.window = window
        layout = QVBoxLayout(self); layout.addLayout(page_header("Encrypt", "Create portable .cvault packages using a fresh random session key for every operation."))
        self.tabs = QTabWidget(); layout.addWidget(self.tabs, 1)
        self.tabs.addTab(self._text_tab(), "Text message"); self.tabs.addTab(self._file_tab(), "File"); self.tabs.addTab(self._folder_tab(), "Folder")

    def _text_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); self.text_input = QPlainTextEdit(); self.text_input.setPlaceholderText("Enter plaintext…")
        self.text_options = CryptoOptions(); self.text_output = QPlainTextEdit(); self.text_output.setReadOnly(True); self.text_output.setPlaceholderText("Encrypted .cvault JSON appears here")
        buttons = QHBoxLayout(); encrypt = QPushButton("Encrypt text"); encrypt.setObjectName("Primary"); encrypt.clicked.connect(self.encrypt_text); copy = QPushButton("Copy output"); copy.clicked.connect(lambda: QApplication.clipboard().setText(self.text_output.toPlainText())); export = QPushButton("Export .cvault…"); export.clicked.connect(self.export_text)
        buttons.addWidget(encrypt); buttons.addWidget(copy); buttons.addWidget(export); buttons.addStretch()
        layout.addWidget(QLabel("Plaintext")); layout.addWidget(self.text_input); layout.addWidget(self.text_options); layout.addLayout(buttons); layout.addWidget(QLabel("Encrypted container")); layout.addWidget(self.text_output)
        return page

    def _file_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); self.file_source = PathPicker("Any file", lambda edit: _open_file(edit)); self.file_destination = PathPicker("Output .cvault", lambda edit: _save_file(edit, "CryptoVault (*.cvault)")); self.file_options = CryptoOptions(); self.file_progress = QProgressBar()
        run = QPushButton("Encrypt file"); run.setObjectName("Primary"); run.clicked.connect(self.encrypt_file)
        layout.addWidget(QLabel("Source file")); layout.addWidget(self.file_source); layout.addWidget(QLabel("Destination")); layout.addWidget(self.file_destination); layout.addWidget(self.file_options); layout.addWidget(self.file_progress); layout.addWidget(run, 0, Qt.AlignLeft); layout.addStretch(); return page

    def _folder_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); warning = QLabel("Folder contents are packaged into a ZIP64 archive, then encrypted as one authenticated .cvault file. Symbolic links are skipped."); warning.setWordWrap(True); warning.setObjectName("Warning")
        self.folder_source = PathPicker("Folder to protect", _open_folder); self.folder_destination = PathPicker("Output .cvault", lambda edit: _save_file(edit, "CryptoVault (*.cvault)")); self.folder_options = CryptoOptions(); self.folder_progress = QProgressBar(); run = QPushButton("Encrypt folder"); run.setObjectName("Primary"); run.clicked.connect(self.encrypt_folder)
        layout.addWidget(warning); layout.addWidget(self.folder_source); layout.addWidget(self.folder_destination); layout.addWidget(self.folder_options); layout.addWidget(self.folder_progress); layout.addWidget(run, 0, Qt.AlignLeft); layout.addStretch(); return page

    def encrypt_text(self):
        try:
            data = self.text_input.toPlainText().encode("utf-8")
            if not data: raise ValueError("Enter text to encrypt")
            container = encrypt_bytes(data, content_type="text", **self.text_options.kwargs())
            self.text_output.setPlainText(dumps_container(container).decode("utf-8")); self.window.record("Encrypt text", "message.cvault", container["algorithm"]); self.window.info("Text encrypted", "The authenticated container is ready to copy or export.")
        except Exception as exc: self.window.error(str(exc))

    def export_text(self):
        if not self.text_output.toPlainText(): return self.window.error("Encrypt text first")
        path, _ = QFileDialog.getSaveFileName(self, "Export encrypted message", "message.cvault", "CryptoVault (*.cvault)")
        if path: Path(path).write_text(self.text_output.toPlainText(), encoding="utf-8")

    def encrypt_file(self):
        try:
            source, destination = self.file_source.text(), self.file_destination.text()
            if not source or not destination: raise ValueError("Select source and destination files")
            kwargs = self.file_options.kwargs(); algorithm = kwargs["algorithm"]
            self.window.run_worker(encrypt_file, (source, destination), kwargs, self.file_progress, lambda _: self.window.record("Encrypt file", source, algorithm))
        except Exception as exc: self.window.error(str(exc))

    def encrypt_folder(self):
        try:
            source, destination = self.folder_source.text(), self.folder_destination.text()
            if not source or not destination: raise ValueError("Select source folder and destination")
            kwargs = self.folder_options.kwargs(); algorithm = kwargs["algorithm"]
            def task(progress=None):
                progress(5); data = pack_folder(source, lambda p: progress(5 + p // 3)); progress(40)
                container = encrypt_bytes(data, filename=Path(source).name + ".zip", content_type="folder", **kwargs); progress(80)
                from cryptovault.core.utils import atomic_write
                atomic_write(destination, dumps_container(container)); validate_container_checksum(loads_container(Path(destination).read_bytes())); progress(100)
            self.window.run_worker(task, (), {}, self.folder_progress, lambda _: self.window.record("Encrypt folder", source, algorithm))
        except Exception as exc: self.window.error(str(exc))


class DecryptPage(QWidget):
    def __init__(self, window):
        super().__init__(); self.window = window; layout = QVBoxLayout(self); layout.addLayout(page_header("Decrypt", "Authenticated decryption rejects wrong credentials and modified or corrupted containers."))
        self.tabs = QTabWidget(); self.tabs.addTab(self._text_tab(), "Text / message"); self.tabs.addTab(self._file_tab(), "File / folder"); layout.addWidget(self.tabs, 1)

    def _text_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); self.container_text = QPlainTextEdit(); self.container_text.setPlaceholderText("Paste CryptoVault JSON or import a .cvault file…"); self.text_creds = DecryptionCredentials(); self.plaintext = QPlainTextEdit(); self.plaintext.setReadOnly(True)
        buttons = QHBoxLayout(); load = QPushButton("Import .cvault…"); load.clicked.connect(self.import_text); run = QPushButton("Decrypt text"); run.setObjectName("Primary"); run.clicked.connect(self.decrypt_text); buttons.addWidget(load); buttons.addWidget(run); buttons.addStretch()
        layout.addWidget(self.container_text); layout.addWidget(self.text_creds); layout.addLayout(buttons); layout.addWidget(QLabel("Verified plaintext")); layout.addWidget(self.plaintext); return page

    def _file_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); self.source = PathPicker("Encrypted .cvault", lambda edit: _open_file(edit, "CryptoVault (*.cvault);;All files (*)")); self.destination = PathPicker("Restored file or folder", lambda edit: _save_file(edit)); self.creds = DecryptionCredentials(); self.progress = QProgressBar(); run = QPushButton("Decrypt and authenticate"); run.setObjectName("Primary"); run.clicked.connect(self.decrypt_file)
        layout.addWidget(self.source); layout.addWidget(self.destination); layout.addWidget(self.creds); layout.addWidget(self.progress); layout.addWidget(run, 0, Qt.AlignLeft); layout.addStretch(); return page

    def import_text(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import message", "", "CryptoVault (*.cvault);;All files (*)")
        if path:
            try: self.container_text.setPlainText(Path(path).read_text(encoding="utf-8"))
            except Exception as exc: self.window.error(str(exc))

    def decrypt_text(self):
        try:
            container = loads_container(self.container_text.toPlainText().encode("utf-8")); result = decrypt_container(container, **self.text_creds.kwargs())
            self.plaintext.setPlainText(result.data.decode("utf-8")); self.window.record("Decrypt text", "message.cvault", container["algorithm"])
        except UnicodeDecodeError: self.window.error("The decrypted content is not UTF-8 text")
        except Exception as exc: self.window.error(str(exc))

    def decrypt_file(self):
        try:
            source, destination = self.source.text(), self.destination.text()
            if not source or not destination: raise ValueError("Select container and destination")
            container = loads_container(Path(source).read_bytes()); content_type = container.get("content", {}).get("type"); kwargs = self.creds.kwargs(); algorithm = container.get("algorithm", "Unknown")
            if content_type == "folder":
                def task(progress=None):
                    progress(10); result = decrypt_container(container, **kwargs); progress(70); unpack_folder(result.data, destination); progress(100); return result.metadata
                self.window.run_worker(task, (), {}, self.progress, lambda _: self.window.record("Decrypt folder", source, algorithm))
            else:
                self.window.run_worker(decrypt_file, (source, destination), kwargs, self.progress, lambda _: self.window.record("Decrypt file", source, algorithm))
        except Exception as exc: self.window.error(str(exc))


class KeyManagerPage(QWidget):
    def __init__(self, window):
        super().__init__(); self.window = window; layout = QVBoxLayout(self); layout.addLayout(page_header("Key manager", "Generate standard PEM keys. Private keys are always encrypted before export."))
        form_frame, form_layout = card("Generate a key pair"); form = QFormLayout(); self.kind = QComboBox(); self.kind.addItems(["RSA-4096", "X25519", "Ed25519"]); self.private_path = PathPicker("Encrypted private key .pem", lambda edit: _save_file(edit, "PEM (*.pem)")); self.public_path = PathPicker("Public key .pem", lambda edit: _save_file(edit, "PEM (*.pem)")); self.password = QLineEdit(); self.password.setEchoMode(QLineEdit.Password); form.addRow("Key type", self.kind); form.addRow("Private key", self.private_path); form.addRow("Public key", self.public_path); form.addRow("Export password", self.password); form_layout.addLayout(form)
        generate = QPushButton("Generate and export"); generate.setObjectName("Primary"); generate.clicked.connect(self.generate); form_layout.addWidget(generate, 0, Qt.AlignLeft); layout.addWidget(form_frame)
        inspect_frame, inspect_layout = card("Inspect an imported public key"); self.inspect_path = PathPicker("Public key .pem", lambda edit: _open_file(edit, "PEM (*.pem)")); inspect = QPushButton("Inspect key"); inspect.clicked.connect(self.inspect); self.details = QPlainTextEdit(); self.details.setReadOnly(True); inspect_layout.addWidget(self.inspect_path); inspect_layout.addWidget(inspect, 0, Qt.AlignLeft); inspect_layout.addWidget(self.details); layout.addWidget(inspect_frame, 1)

    def generate(self):
        try:
            if not self.private_path.text() or not self.public_path.text(): raise ValueError("Choose both export paths")
            key = generate_private_key(self.kind.currentText()); save_private_key(key, self.private_path.text(), self.password.text()); save_public_key(key, self.public_path.text()); info = key_description(key); self.details.setPlainText(json.dumps(info, indent=2)); self.window.record("Generate key", self.public_path.text(), info["type"])
            self.window.info("Key generated", "Keep the private key and its password backed up separately.")
        except Exception as exc: self.window.error(str(exc))

    def inspect(self):
        try: self.details.setPlainText(json.dumps(key_description(load_public_key(self.inspect_path.text())), indent=2))
        except Exception as exc: self.window.error(str(exc))


class VaultManagerPage(QWidget):
    def __init__(self, window):
        super().__init__(); self.window = window
        layout = QVBoxLayout(self); layout.addLayout(page_header("Vault manager", "A vault is a portable encrypted folder package. Restore it to a chosen directory, edit locally, then create a new encrypted revision."))
        warning = QLabel("CryptoVault vaults are authenticated archives, not mounted virtual drives. Restored files exist as normal plaintext files until you remove them using your operating system's storage controls."); warning.setObjectName("Warning"); warning.setWordWrap(True); layout.addWidget(warning)
        flow, body = card("Safe vault workflow")
        steps = QLabel("1  Create a vault from the Encrypt → Folder page\n2  Store or share the resulting .cvault package\n3  Restore it through the Decrypt → File / folder page\n4  After editing, create a new encrypted revision and verify it opens\n5  Retain backups before removing older revisions")
        steps.setStyleSheet("line-height: 1.5;"); body.addWidget(steps); layout.addWidget(flow)
        details, details_body = card("Container inspection")
        self.path = PathPicker("Vault .cvault", lambda edit: _open_file(edit, "CryptoVault (*.cvault)")); inspect = QPushButton("Inspect protected metadata"); inspect.clicked.connect(self.inspect); self.output = QPlainTextEdit(); self.output.setReadOnly(True); details_body.addWidget(self.path); details_body.addWidget(inspect, 0, Qt.AlignLeft); details_body.addWidget(self.output); layout.addWidget(details, 1)

    def inspect(self):
        try:
            container = loads_container(Path(self.path.text()).read_bytes())
            safe = {key: container.get(key) for key in ("format", "version", "created_utc", "algorithm", "content", "hash")}
            safe["key_protection"] = container.get("key_protection", {}).get("type")
            self.output.setPlainText(json.dumps(safe, indent=2, ensure_ascii=False))
        except Exception as exc: self.window.error(str(exc))


class IntegrityPage(QWidget):
    def __init__(self, window):
        super().__init__(); self.window = window; layout = QVBoxLayout(self); layout.addLayout(page_header("Integrity checker", "Generate or compare file digests without modifying the source file.")); self.path = PathPicker("File to hash", lambda edit: _open_file(edit)); self.algorithm = QComboBox(); self.algorithm.addItems(["SHA-256", "SHA-512", "SHA3-512", "BLAKE3"]); self.expected = QLineEdit(); self.expected.setPlaceholderText("Optional expected digest"); self.output = QPlainTextEdit(); self.output.setReadOnly(True); self.progress = QProgressBar(); run = QPushButton("Calculate hash"); run.setObjectName("Primary"); run.clicked.connect(self.calculate)
        form = QFormLayout(); form.addRow("File", self.path); form.addRow("Algorithm", self.algorithm); form.addRow("Expected digest", self.expected); layout.addLayout(form); layout.addWidget(self.progress); layout.addWidget(run, 0, Qt.AlignLeft); layout.addWidget(self.output); layout.addStretch()

    def calculate(self):
        try:
            if not self.path.text(): raise ValueError("Select a file")
            algo = self.algorithm.currentText()
            def done(digest):
                status = "MATCH ✓" if self.expected.text() and compare_digest(digest, self.expected.text()) else ("MISMATCH ✕" if self.expected.text() else "Generated")
                self.output.setPlainText(f"{algo}\n{digest}\n\nResult: {status}"); self.window.record("Hash file", self.path.text(), algo, status)
            self.window.run_worker(hash_file, (self.path.text(), algo), {}, self.progress, done)
        except Exception as exc: self.window.error(str(exc))


class SignaturePage(QWidget):
    def __init__(self, window):
        super().__init__(); self.window = window; layout = QVBoxLayout(self); layout.addLayout(page_header("Digital signatures", "Ed25519 detached signatures prove authenticity and detect file modification.")); tabs = QTabWidget(); tabs.addTab(self._sign(), "Sign"); tabs.addTab(self._verify(), "Verify"); layout.addWidget(tabs)

    def _sign(self):
        page = QWidget(); form = QFormLayout(page); self.sign_file = PathPicker("File", lambda edit: _open_file(edit)); self.sign_key = PathPicker("Ed25519 private key", lambda edit: _open_file(edit, "PEM (*.pem)")); self.sign_password = QLineEdit(); self.sign_password.setEchoMode(QLineEdit.Password); self.sign_output = PathPicker("Signature .cvsig", lambda edit: _save_file(edit, "CryptoVault signature (*.cvsig)")); button = QPushButton("Create signature"); button.setObjectName("Primary"); button.clicked.connect(self.sign); form.addRow("File", self.sign_file); form.addRow("Private key", self.sign_key); form.addRow("Key password", self.sign_password); form.addRow("Output", self.sign_output); form.addRow(button); return page

    def _verify(self):
        page = QWidget(); form = QFormLayout(page); self.verify_file = PathPicker("File", lambda edit: _open_file(edit)); self.verify_signature = PathPicker("Signature .cvsig", lambda edit: _open_file(edit, "CryptoVault signature (*.cvsig)")); self.verify_key = PathPicker("Ed25519 public key", lambda edit: _open_file(edit, "PEM (*.pem)")); self.verify_result = QLabel("Not verified"); button = QPushButton("Verify signature"); button.setObjectName("Primary"); button.clicked.connect(self.verify); form.addRow("File", self.verify_file); form.addRow("Signature", self.verify_signature); form.addRow("Public key", self.verify_key); form.addRow(button); form.addRow("Result", self.verify_result); return page

    def sign(self):
        try:
            key = load_private_key(self.sign_key.text(), self.sign_password.text() or None); create_detached_signature(self.sign_file.text(), key, self.sign_output.text()); self.window.record("Sign file", self.sign_file.text(), "Ed25519"); self.window.info("Signature created", "The detached .cvsig file can be shared with the original file.")
        except Exception as exc: self.window.error(str(exc))

    def verify(self):
        try:
            valid = verify_detached_signature(self.verify_file.text(), self.verify_signature.text(), load_public_key(self.verify_key.text())); self.verify_result.setText("VALID — signature and file digest match" if valid else "INVALID — do not trust this file"); self.verify_result.setStyleSheet("color: #65e3bd; font-weight: 700;" if valid else "color: #ef6b73; font-weight: 700;"); self.window.record("Verify signature", self.verify_file.text(), "Ed25519", "Valid" if valid else "Invalid")
        except Exception as exc: self.window.error(str(exc))


class LearningPage(QWidget):
    def __init__(self, window):
        super().__init__(); self.window = window; layout = QVBoxLayout(self); layout.addLayout(page_header("Learning center", "Explore historical transformations. These ciphers are insecure and must never protect real data.")); warning = QLabel("⚠ EDUCATIONAL ONLY — Caesar, Vigenère, repeating-key XOR, and substitution ciphers provide no modern security."); warning.setObjectName("Warning"); warning.setWordWrap(True); layout.addWidget(warning)
        form = QFormLayout(); self.kind = QComboBox(); self.kind.addItems(["Caesar", "Vigenère", "XOR", "Substitution"]); self.key = QLineEdit("3"); self.original = QPlainTextEdit(); self.original.setPlaceholderText("Original text"); self.final = QPlainTextEdit(); self.final.setReadOnly(True); self.steps = QPlainTextEdit(); self.steps.setReadOnly(True); run = QPushButton("Show transformation"); run.setObjectName("Primary"); run.clicked.connect(self.transform); form.addRow("Classical cipher", self.kind); form.addRow("Key / alphabet", self.key); layout.addLayout(form); layout.addWidget(QLabel("Original text")); layout.addWidget(self.original); layout.addWidget(run, 0, Qt.AlignLeft); layout.addWidget(QLabel("Final output")); layout.addWidget(self.final); layout.addWidget(QLabel("Transformation steps (first 100 bytes/characters)")); layout.addWidget(self.steps); self.kind.currentTextChanged.connect(self.defaults)

    def defaults(self, kind):
        defaults = {"Caesar": "3", "Vigenère": "LEMON", "XOR": "demo", "Substitution": random_substitution_alphabet()}; self.key.setText(defaults[kind])

    def transform(self):
        try:
            text, key, kind = self.original.toPlainText(), self.key.text(), self.kind.currentText()
            if kind == "Caesar": result, steps = caesar(text, int(key))
            elif kind == "Vigenère": result, steps = vigenere(text, key)
            elif kind == "XOR": result, steps = xor_cipher(text, key)
            else: result, steps = substitution(text, key)
            self.final.setPlainText(result); self.steps.setPlainText("\n".join(steps[:100]))
        except Exception as exc: self.window.error(str(exc))


class SettingsPage(QWidget):
    def __init__(self, window):
        super().__init__(); self.window = window; layout = QVBoxLayout(self); layout.addLayout(page_header("Settings & security", "Configure a local app lock and review operational security guidance.")); frame, body = card("Application lock"); form = QFormLayout(); self.master = QLineEdit(); self.master.setEchoMode(QLineEdit.Password); self.confirm = QLineEdit(); self.confirm.setEchoMode(QLineEdit.Password); self.timeout = QSpinBox(); self.timeout.setRange(1, 240); self.timeout.setValue(int(window.settings.value("session_timeout", 15))); form.addRow("New master password", self.master); form.addRow("Confirm password", self.confirm); form.addRow("Session timeout (minutes)", self.timeout); body.addLayout(form); save = QPushButton("Save security settings"); save.setObjectName("Primary"); save.clicked.connect(self.save); body.addWidget(save, 0, Qt.AlignLeft); layout.addWidget(frame)
        notes = QLabel("• The app lock protects casual local access; it is not full-disk encryption.\n• Private key export uses encrypted PKCS#8 PEM.\n• CryptoVault never stores encryption passwords.\n• Back up private keys separately. Lost keys and passwords cannot be recovered.\n• Secure deletion is not promised because SSD wear-leveling and filesystem snapshots can retain blocks."); notes.setWordWrap(True); notes.setObjectName("Muted"); layout.addWidget(notes); layout.addStretch()

    def save(self):
        try:
            if self.master.text():
                if self.master.text() != self.confirm.text(): raise ValueError("Master passwords do not match")
                encoded = self.window.guard.set_password(self.master.text()); self.window.settings.setValue("master_hash", encoded)
            self.window.settings.setValue("session_timeout", self.timeout.value()); self.window.guard.timeout_seconds = self.timeout.value() * 60; self.window.info("Settings saved", "Security settings were updated.")
        except Exception as exc: self.window.error(str(exc))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle(f"CryptoVault Pro {__version__}"); self.resize(1220, 780); self.setMinimumSize(980, 650); self.setStyleSheet(APP_STYLE); self.thread_pool = QThreadPool.globalInstance(); self.settings = QSettings("CryptoVault", "CryptoVault Pro")
        data_dir = Path(QStandardPaths.writableLocation(QStandardPaths.AppDataLocation)); self.history = HistoryStore(data_dir / "operations.json"); self.guard = SessionGuard(str(self.settings.value("master_hash", "")), int(self.settings.value("session_timeout", 15)))
        root = QWidget(); self.setCentralWidget(root); main = QHBoxLayout(root); main.setContentsMargins(0, 0, 0, 0); sidebar = QFrame(); sidebar.setObjectName("Sidebar"); sidebar.setFixedWidth(230); nav = QVBoxLayout(sidebar); brand = QLabel("◈ CryptoVault"); brand.setObjectName("Brand"); nav.addWidget(brand); subtitle = QLabel("PRO • LOCAL SECURITY"); subtitle.setObjectName("Muted"); nav.addWidget(subtitle); nav.addSpacing(18)
        self.stack = QStackedWidget(); self.dashboard = DashboardPage(self.history)
        pages = [("⌂  Dashboard", self.dashboard), ("⇧  Encrypt", EncryptPage(self)), ("⇩  Decrypt", DecryptPage(self)), ("▣  Vault Manager", VaultManagerPage(self)), ("⌘  Key Manager", KeyManagerPage(self)), ("#  Integrity", IntegrityPage(self)), ("✓  Signatures", SignaturePage(self)), ("◎  Learning Center", LearningPage(self)), ("⚙  Settings", SettingsPage(self))]
        self.nav_buttons = []
        for index, (label, page) in enumerate(pages):
            button = QPushButton(label); button.setObjectName("Nav"); button.setCheckable(True); button.clicked.connect(lambda checked=False, i=index: self.navigate(i)); nav.addWidget(button); self.nav_buttons.append(button); self.stack.addWidget(page)
        nav.addStretch(); version = QLabel(f"v{__version__}\nAuthenticated • Offline"); version.setObjectName("Muted"); nav.addWidget(version); main.addWidget(sidebar); content = QFrame(); content_layout = QVBoxLayout(content); content_layout.setContentsMargins(26, 22, 26, 22); content_layout.addWidget(self.stack); main.addWidget(content, 1); self.navigate(0)
        self.timeout_timer = QTimer(self); self.timeout_timer.timeout.connect(self.check_timeout); self.timeout_timer.start(30_000)

    def navigate(self, index):
        self.stack.setCurrentIndex(index)
        for i, button in enumerate(self.nav_buttons): button.setChecked(i == index)
        self.guard.touch()
        if index == 0: self.dashboard.refresh()

    def run_worker(self, function, args, kwargs, progress_bar, on_done):
        progress_bar.setValue(0); worker = Worker(function, *args, **kwargs); worker.signals.progress.connect(progress_bar.setValue); worker.signals.error.connect(self.error)
        def finished(result): progress_bar.setValue(100); on_done(result); self.info("Operation complete", "The operation completed and authenticated successfully.")
        worker.signals.finished.connect(finished); self.thread_pool.start(worker)

    def record(self, action, item, algorithm, status="Success"):
        self.history.add(action, item, algorithm, status); self.dashboard.refresh()

    def error(self, message): QMessageBox.critical(self, "CryptoVault", message)
    def info(self, title, message): QMessageBox.information(self, title, message)

    def check_timeout(self):
        if self.guard.configured() and self.guard.expired() and self.isVisible(): self.lock_application()

    def lock_application(self):
        dialog = QDialog(self); dialog.setWindowTitle("CryptoVault locked"); dialog.setModal(True); dialog.setWindowFlag(Qt.WindowCloseButtonHint, False); layout = QVBoxLayout(dialog); layout.addWidget(QLabel("Session locked. Enter the master password to continue.")); password = QLineEdit(); password.setEchoMode(QLineEdit.Password); layout.addWidget(password); unlock = QPushButton("Unlock"); unlock.setObjectName("Primary"); layout.addWidget(unlock); status = QLabel(); status.setStyleSheet("color: #ef6b73"); layout.addWidget(status)
        def verify():
            try:
                if self.guard.verify(password.text()): dialog.accept()
                else: status.setText("Incorrect password")
            except ValueError as exc: status.setText(str(exc))
        unlock.clicked.connect(verify); password.returnPressed.connect(verify); dialog.exec()

    def showEvent(self, event):
        super().showEvent(event)
        if self.guard.configured() and not getattr(self, "_initial_unlock", False): self._initial_unlock = True; QTimer.singleShot(0, self.lock_application)
