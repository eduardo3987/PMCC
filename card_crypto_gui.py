#!/usr/bin/env python3
"""GUI front end for the card_crypto utility.

The window lets the user choose whether to operate on a card image file or a
live card via PC/SC.  Readers can be scanned and a connection established; once
connected the card can be used for extracting keys, signing, encrypting, etc.

Most of the heavy lifting is done by the functions in ``card_crypto.py``; the
GUI simply builds the appropriate ``argparse.Namespace`` and calls the
corresponding ``cmd_*`` helper.  Error messages and progress are written to the
log box at the bottom of the window.

Requires PySide6 (already a dependency of the project).
"""

import sys
import os
import argparse
from pathlib import Path

from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QFileDialog,
    QTextEdit,
    QComboBox,
    QRadioButton,
    QButtonGroup,
    QHBoxLayout,
    QVBoxLayout,
    QStackedWidget,
    QCheckBox,
    QMessageBox,
)
from PySide6.QtCore import Qt

from core.pcsc_manager import PCSCManager
import card_crypto


class QTextEditStream:
    """File-like wrapper that writes into a QTextEdit."""

    def __init__(self, text_edit: QTextEdit):
        self._te = text_edit

    def write(self, text: str) -> None:
        if text:
            # strip trailing newline; QTextEdit.append will add its own
            self._te.append(text.rstrip("\n"))

    def flush(self) -> None:
        pass


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Card Crypto GUI")
        self.pcsc = PCSCManager(logger=self.log)

        self._build_ui()
        # perform initial scan and attempt connection
        self.scan_readers(auto_connect=True)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        main_layout = QVBoxLayout()

        # reader controls --------------------------------------------------
        rlay = QHBoxLayout()
        self.reader_combo = QComboBox()
        self.scan_btn = QPushButton("Scan readers")
        self.connect_btn = QPushButton("Connect")
        self.disconnect_btn = QPushButton("Disconnect")
        self.status_label = QLabel("not connected")
        rlay.addWidget(self.reader_combo)
        rlay.addWidget(self.scan_btn)
        rlay.addWidget(self.connect_btn)
        rlay.addWidget(self.disconnect_btn)
        rlay.addWidget(self.status_label)
        main_layout.addLayout(rlay)

        self.scan_btn.clicked.connect(self.scan_readers)
        self.connect_btn.clicked.connect(self.connect_reader)
        self.disconnect_btn.clicked.connect(self.disconnect_reader)

        # reader-only mode; no card image support
        # (user must connect a reader before performing any operation)

        # operation selector & pages --------------------------------------
        self.op_combo = QComboBox()
        self.operations = [
            ("Extract public key", "extract_public"),
            ("Sign file", "sign"),
            ("Verify signature", "verify"),
            ("Encrypt file", "encrypt"),
            ("Decrypt file", "decrypt"),
        ]
        for label, cmd in self.operations:
            self.op_combo.addItem(label, cmd)
        self.op_combo.currentIndexChanged.connect(self._on_op_changed)
        main_layout.addWidget(self.op_combo)

        self.pages = QStackedWidget()
        self._build_pages()
        main_layout.addWidget(self.pages)

        run_btn = QPushButton("Run")
        run_btn.clicked.connect(self.on_run)
        main_layout.addWidget(run_btn)

        # log area ---------------------------------------------------------
        main_layout.addWidget(QLabel("Log"))
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        main_layout.addWidget(self.log_area)

        self.setLayout(main_layout)
        self.resize(600, 700)

    def _build_pages(self):
        # each page builds its own widgets and stores handles on self
        self.pages.addWidget(self._build_extract_page())
        self.pages.addWidget(self._build_sign_page())
        self.pages.addWidget(self._build_verify_page())
        self.pages.addWidget(self._build_encrypt_page())
        self.pages.addWidget(self._build_decrypt_page())

    def _build_extract_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Public key will be saved automatically to ~/.pmcc based on card metadata."))
        page.setLayout(layout)
        return page

    # private-dump page removed - feature disabled

    def _build_sign_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout()

        self.sign_input = QLineEdit()
        btn = QPushButton("Browse...")
        btn.clicked.connect(lambda: self.choose_file(self.sign_input, "Input file"))
        # update output when input changes manually
        self.sign_input.textChanged.connect(self._update_signature_output)
        hl = QHBoxLayout()
        hl.addWidget(self.sign_input)
        hl.addWidget(btn)
        layout.addWidget(QLabel("Input to sign"))
        layout.addLayout(hl)

        # output is auto‑determined from input, display read-only
        self.sign_out = QLineEdit()
        self.sign_out.setReadOnly(True)
        layout.addWidget(QLabel("Signature output (auto)"))
        layout.addWidget(self.sign_out)

        self.sign_password = QLineEdit()
        self.sign_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("Password (if any)"))
        layout.addWidget(self.sign_password)

        page.setLayout(layout)
        return page

    def _build_verify_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout()

        # dropdown of public keys stored in ~/.pmcc
        self.verify_pub_combo = QComboBox()
        self.verify_pub_combo.setEditable(False)
        btn_refresh = QPushButton("Refresh list")
        btn_refresh.clicked.connect(self._populate_pubkey_list)
        hl = QHBoxLayout()
        hl.addWidget(self.verify_pub_combo)
        hl.addWidget(btn_refresh)
        layout.addWidget(QLabel("Public key file"))
        layout.addLayout(hl)
        # populate initially
        self._populate_pubkey_list()

        self.verify_input = QLineEdit()
        btn = QPushButton("Browse...")
        btn.clicked.connect(lambda: self.choose_file(self.verify_input, "Input file"))
        hl2 = QHBoxLayout()
        hl2.addWidget(self.verify_input)
        hl2.addWidget(btn)
        layout.addWidget(QLabel("Data file"))
        layout.addLayout(hl2)

        self.verify_sig = QLineEdit()
        btn3 = QPushButton("Browse...")
        btn3.clicked.connect(lambda: self.choose_file(self.verify_sig, "Signature file"))
        hl3 = QHBoxLayout()
        hl3.addWidget(self.verify_sig)
        hl3.addWidget(btn3)
        layout.addWidget(QLabel("Signature file"))
        layout.addLayout(hl3)

        page.setLayout(layout)
        return page

    def _populate_pubkey_list(self):
        """Read ~/.pmcc and populate the public-key dropdown."""
        self.verify_pub_combo.clear()
        home = Path.home() / ".pmcc"
        if home.exists():
            for p in sorted(home.iterdir()):
                if p.is_file() and p.suffix.lower() in (".pem", ".raw"):
                    self.verify_pub_combo.addItem(str(p))
        # always allow manual entry in case user wants a different file
        self.verify_pub_combo.setEditable(True)

    def _update_signature_output(self):
        path = self.sign_input.text().strip()
        if path:
            out = os.path.join(os.path.dirname(path), os.path.basename(path) + ".sig")
            self.sign_out.setText(out)

    def _build_encrypt_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout()

        self.encrypt_pub = QLineEdit()
        btn = QPushButton("Browse...")
        btn.clicked.connect(lambda: self.choose_file(self.encrypt_pub, "Public key (optional)"))
        hl = QHBoxLayout()
        hl.addWidget(self.encrypt_pub)
        hl.addWidget(btn)
        layout.addWidget(QLabel("Recipient public key (leave blank to use card)"))
        layout.addLayout(hl)

        self.encrypt_input = QLineEdit()
        btn2 = QPushButton("Browse...")
        btn2.clicked.connect(lambda: self.choose_file(self.encrypt_input, "Input file"))
        hl2 = QHBoxLayout()
        hl2.addWidget(self.encrypt_input)
        hl2.addWidget(btn2)
        layout.addWidget(QLabel("File to encrypt"))
        layout.addLayout(hl2)

        hl3 = QHBoxLayout()
        self.encrypt_out = QLineEdit()
        btn3 = QPushButton("Browse...")
        btn3.clicked.connect(lambda: self.choose_save(self.encrypt_out, "Encrypted output"))
        hl3.addWidget(self.encrypt_out)
        hl3.addWidget(btn3)
        layout.addWidget(QLabel("Output filename"))
        layout.addLayout(hl3)

        page.setLayout(layout)
        return page

    def _build_decrypt_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout()

        self.decrypt_input = QLineEdit()
        btn = QPushButton("Browse...")
        btn.clicked.connect(lambda: self.choose_file(self.decrypt_input, "Encrypted file"))
        hl = QHBoxLayout()
        hl.addWidget(self.decrypt_input)
        hl.addWidget(btn)
        layout.addWidget(QLabel("Encrypted file"))
        layout.addLayout(hl)

        hl2 = QHBoxLayout()
        self.decrypt_out = QLineEdit()
        btn2 = QPushButton("Browse...")
        btn2.clicked.connect(lambda: self.choose_save(self.decrypt_out, "Decrypted output"))
        hl2.addWidget(self.decrypt_out)
        hl2.addWidget(btn2)
        layout.addWidget(QLabel("Output filename"))
        layout.addLayout(hl2)

        self.decrypt_password = QLineEdit()
        self.decrypt_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel("Password (if any)"))
        layout.addWidget(self.decrypt_password)

        page.setLayout(layout)
        return page

    # ------------------------------------------------------------------
    # helper slots
    # ------------------------------------------------------------------

    def scan_readers(self, auto_connect: bool = False):
        """Populate the reader list.  If *auto_connect* is True attempt to connect
        to the first reader found immediately."""
        self.reader_combo.clear()
        for r in self.pcsc.list_readers():
            self.reader_combo.addItem(str(r), r)
        count = self.reader_combo.count()
        self.log(f"found {count} readers")
        if auto_connect and count > 0:
            # select the first reader and try to connect quietly
            self.reader_combo.setCurrentIndex(0)
            try:
                self.connect_reader()
            except Exception as e:
                # connect_reader already logs the error; nothing further
                pass

    def connect_reader(self):
        rdr = self.reader_combo.currentData()
        if rdr is None:
            QMessageBox.warning(self, "Connect", "No reader selected")
            return
        try:
            self.pcsc.connect(reader=rdr)
            self.status_label.setText(f"connected to {rdr}")
            self.log(f"connected to {rdr}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            self.log(f"connection error: {e}")

    def disconnect_reader(self):
        self.pcsc.disconnect()
        self.status_label.setText("not connected")
        self.log("reader disconnected")

    # card image support removed; reader-only GUI

    def choose_file(self, edit: QLineEdit, title: str):
        path, _ = QFileDialog.getOpenFileName(self, title)
        if path:
            edit.setText(path)
            # if selecting file to sign, update output field too
            if edit is self.sign_input:
                out = os.path.join(os.path.dirname(path), os.path.basename(path) + ".sig")
                self.sign_out.setText(out)

    def choose_save(self, edit: QLineEdit, title: str):
        path, _ = QFileDialog.getSaveFileName(self, title)
        if path:
            edit.setText(path)

    # card image option removed; always use connected reader
    # def _update_card_choice(self):
    #     use_img = self.radio_image.isChecked()
    #     self.img_edit.setEnabled(use_img)

    def _on_op_changed(self, idx: int):
        self.pages.setCurrentIndex(idx)

    def log(self, msg: str) -> None:
        self.log_area.append(msg)

    # ------------------------------------------------------------------
    # run actions
    # ------------------------------------------------------------------

    def on_run(self):
        cmd = self.op_combo.currentData()
        args = argparse.Namespace()
        # card source: always use connected reader
        rd = self.pcsc.reader
        args.reader = str(rd) if rd is not None else None
        args.manager = self.pcsc
        # populate operation-specific parameters
        if cmd == "extract_public":
            # output is determined automatically by the card_crypto helper
            args.pem = True
        elif cmd == "sign":
            args.input = self.sign_input.text()
            args.output = self.sign_out.text() or None
            args.password = self.sign_password.text() or None
        elif cmd == "verify":
            # either from combo box or allow manual override when editable
            pubtext = self.verify_pub_combo.currentText()
            args.pubkey = pubtext if pubtext else None
            args.input = self.verify_input.text()
            args.sig = self.verify_sig.text()
        elif cmd == "encrypt":
            args.pubkey = self.encrypt_pub.text() or None
            args.input = self.encrypt_input.text()
            args.output = self.encrypt_out.text() or None
        elif cmd == "decrypt":
            args.input = self.decrypt_input.text()
            args.output = self.decrypt_out.text() or None
            args.password = self.decrypt_password.text() or None
        # call underlying function with stdout/stderr redirected to the log
        stream = QTextEditStream(self.log_area)
        import contextlib
        with contextlib.redirect_stderr(stream), contextlib.redirect_stdout(stream):
            try:
                func = getattr(card_crypto, f"cmd_{cmd}")
                func(args)
            except SystemExit:
                # CLI helpers exit on error; we've already logged stderr.
                pass
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))
                self.log(f"Error: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
