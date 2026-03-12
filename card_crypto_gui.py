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
    QInputDialog,
    QSizePolicy,
    QSplitter,
)
from PySide6.QtCore import Qt

from core.pcsc_manager import PCSCManager
import card_crypto

# additional crypto helpers used by editor
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


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
        # put editor first so it's the top item in the dropdown
        self.operations = [
            ("Editor", "editor"),  # WYSIWYG text editor page
            ("Extract public key", "extract_public"),
            ("Sign file", "sign"),
            ("Verify signature", "verify"),
            ("Encrypt file", "encrypt"),
            ("Decrypt file", "decrypt"),
        ]
        for label, cmd in self.operations:
            self.op_combo.addItem(label, cmd)
        # make editor the default selection if present
        idx = next((i for i, (_, c) in enumerate(self.operations) if c == "editor"), None)
        if idx is not None:
            self.op_combo.setCurrentIndex(idx)
        self.op_combo.currentIndexChanged.connect(self._on_op_changed)
        main_layout.addWidget(self.op_combo)

        self.pages = QStackedWidget()
        self._build_pages()

        # log area ---------------------------------------------------------
        log_container = QWidget()
        log_layout = QVBoxLayout()
        log_layout.addWidget(QLabel("Log"))
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        log_layout.addWidget(self.log_area)
        log_container.setLayout(log_layout)

        # splitter to allow resizing between pages and log
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.pages)
        splitter.addWidget(log_container)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        main_layout.addWidget(splitter)

        # keep a reference to the run button so we can disable it in editor mode
        self.run_btn = QPushButton("Run")
        self.run_btn.clicked.connect(self.on_run)
        main_layout.addWidget(self.run_btn)

        # ensure page/run button state matches initial selection (run_btn now exists)
        self._on_op_changed(self.op_combo.currentIndex())

        self.setLayout(main_layout)
        self.resize(600, 700)

    def _build_pages(self):
        """Add pages in the same order as ``self.operations`` and remember
        their indices so we can look them up by command later.
        """
        self.page_indices = {}
        builder_map = {
            "extract_public": self._build_extract_page,
            "sign": self._build_sign_page,
            "verify": self._build_verify_page,
            "encrypt": self._build_encrypt_page,
            "decrypt": self._build_decrypt_page,
            "editor": self._build_editor_page,
        }
        for idx, (_, cmd) in enumerate(self.operations):
            builder = builder_map.get(cmd)
            if builder is None:
                continue
            page = builder()
            self.pages.addWidget(page)
            self.page_indices[cmd] = idx

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

    def _build_editor_page(self) -> QWidget:
        """Construct the WYSIWYG editor page with controls."""
        page = QWidget()
        layout = QVBoxLayout()

        hl = QHBoxLayout()
        # toolbar buttons
        self.open_btn = QPushButton("Open")
        self.save_btn = QPushButton("Save")
        self.encrypt_btn = QPushButton("Encrypt")
        self.decrypt_btn = QPushButton("Decrypt")
        self.sign_btn = QPushButton("Sign (attach)")
        self.verify_btn = QPushButton("Verify")
        self.insert_pub_btn = QPushButton("Insert pubkey")
        self.extract_pub_btn = QPushButton("Extract pubkey")
        for btn in (
            self.open_btn,
            self.save_btn,
            self.encrypt_btn,
            self.decrypt_btn,
            self.sign_btn,
            self.verify_btn,
            self.insert_pub_btn,
            self.extract_pub_btn,
        ):
            hl.addWidget(btn)
        layout.addLayout(hl)

        self.editor_text = QTextEdit()
        layout.addWidget(self.editor_text)

        page.setLayout(layout)

        # signal connections
        self.open_btn.clicked.connect(self._open_file_editor)
        self.save_btn.clicked.connect(self._save_file_editor)
        self.encrypt_btn.clicked.connect(self._encrypt_editor)
        self.decrypt_btn.clicked.connect(self._decrypt_editor)
        self.sign_btn.clicked.connect(self._sign_editor)
        self.verify_btn.clicked.connect(self._verify_editor)
        self.insert_pub_btn.clicked.connect(self._insert_pubkey)
        self.extract_pub_btn.clicked.connect(self._extract_pubkey)
        return page

    # ------------------------------------------------------------------
    # editor helpers
    # ------------------------------------------------------------------

    def _open_file_editor(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open file")
        if path:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    self.editor_text.setPlainText(f.read())
            except Exception as e:
                QMessageBox.critical(self, "Error", f"cannot open file: {e}")

    def _save_file_editor(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save file")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.editor_text.toPlainText())
            except Exception as e:
                QMessageBox.critical(self, "Error", f"cannot save file: {e}")

    def _encrypt_editor(self):
        # choose a recipient public key from ~/.pmcc dropdown; card used if blank
        args = argparse.Namespace()
        key = self._choose_pubkey_file(allow_blank=True)
        args.pubkey = key if key else None

        # write editor contents to temporary file for encryption
        import tempfile, base64
        with tempfile.NamedTemporaryFile(delete=False) as inf:
            inf.write(self.editor_text.toPlainText().encode("utf-8"))
            inf.flush()
            inp = inf.name
        # prepare temporary output file
        with tempfile.NamedTemporaryFile(delete=False) as outf:
            outp = outf.name
        args.input = inp
        args.output = outp

        rd = self.pcsc.reader
        args.reader = str(rd) if rd is not None else None
        args.manager = self.pcsc

        stream = QTextEditStream(self.log_area)
        import contextlib
        with contextlib.redirect_stderr(stream), contextlib.redirect_stdout(stream):
            try:
                card_crypto.cmd_encrypt(args)
            except Exception as e:
                self.log(f"Error: {e}")
                return
        # read encrypted bytes and show base64 wrapped in markers in editor
        try:
            data = open(outp, "rb").read()
            b64 = base64.b64encode(data).decode("ascii")
            wrapped = "-----BEGIN PMCC ENCRYPTED-----\n" + b64 + "\n-----END PMCC ENCRYPTED-----"
            self.editor_text.setPlainText(wrapped)
        except Exception as e:
            self.log(f"unable to load encrypted output: {e}")
        finally:
            try:
                os.unlink(inp)
                os.unlink(outp)
            except Exception:
                pass

    def _decrypt_editor(self):
        # decrypt the current contents of the editor (expects base64 input)
        import base64, tempfile
        txt = self.editor_text.toPlainText().strip()
        if not txt:
            return
        # strip optional wrapper lines
        import re
        m = re.search(r"-----BEGIN PMCC ENCRYPTED-----(.*?)-----END PMCC ENCRYPTED-----", txt, re.S)
        if m:
            txt = m.group(1).strip()
        try:
            enc = base64.b64decode(txt)
        except Exception as e:
            QMessageBox.warning(self, "Decrypt", f"failed to decode base64: {e}")
            return
        # write encrypted bytes to temp file
        with tempfile.NamedTemporaryFile(delete=False) as inf:
            inf.write(enc)
            inf.flush()
            inp = inf.name
        with tempfile.NamedTemporaryFile(delete=False) as outf:
            outp = outf.name
        args = argparse.Namespace()
        args.input = inp
        rd = self.pcsc.reader
        args.reader = str(rd) if rd is not None else None
        args.manager = self.pcsc
        args.output = outp
        pwd, ok = QInputDialog.getText(self, "Password", "Password (if any)", QLineEdit.Password)
        if not ok:
            # user cancelled; clean up and return
            try:
                os.unlink(inp)
                os.unlink(outp)
            except Exception:
                pass
            return
        args.password = pwd or None
        stream = QTextEditStream(self.log_area)
        import contextlib
        with contextlib.redirect_stderr(stream), contextlib.redirect_stdout(stream):
            try:
                card_crypto.cmd_decrypt(args)
                try:
                    with open(outp, "r", encoding="utf-8", errors="ignore") as f:
                        self.editor_text.setPlainText(f.read())
                except Exception as e:
                    self.log(f"unable to load decrypted output: {e}")
            except Exception as e:
                self.log(f"Error: {e}")
        for p in (inp, outp):
            try:
                os.unlink(p)
            except Exception:
                pass

    def _sign_editor(self):
        # normalize editor text to always end with newline before signing
        content = self.editor_text.toPlainText()
        if content and not content.endswith("\n"):
            content = content + "\n"
            self.editor_text.setPlainText(content)
        data = content.encode("utf-8")
        try:
            rdr = self.pcsc.reader
            img = card_crypto.read_image_from_card(reader=str(rdr), manager=self.pcsc)
            der = card_crypto.extract_private_der(img)
            if not der:
                QMessageBox.warning(self, "Sign", "No private key data found")
                return
            pwd, ok = QInputDialog.getText(self, "Password", "Password (if any)", QLineEdit.Password)
            if not ok:
                return
            password = pwd.encode() if pwd else None
            priv = card_crypto.load_private(der, password)
            sig = priv.sign(data)
            self.log(f"signed {len(data)} bytes of data")
            import base64
            arm = []
            arm.append("-----BEGIN PMCC SIGNATURE-----")
            arm.append(base64.b64encode(sig).decode())
            arm.append("-----END PMCC SIGNATURE-----")
            arm_text = "\n".join(arm) + "\n"
            # append to the end of the document explicitly
            current = self.editor_text.toPlainText()
            if current and not current.endswith("\n"):
                current = current + "\n"
            self.editor_text.setPlainText(current + arm_text)
            self.log("attached signature")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            self.log(f"sign error: {e}")

    def _verify_editor(self):
        txt = self.editor_text.toPlainText()
        import re, base64
        # find all signature blocks, pick the last one to avoid accidental matches
        matches = list(re.finditer(r"-----BEGIN (?:ED25519|PMCC) SIGNATURE-----.*?-----END (?:ED25519|PMCC) SIGNATURE-----", txt, re.S))
        if not matches:
            QMessageBox.warning(self, "Verify", "No signature block found")
            return
        sig_match = matches[-1]
        sig_block = sig_match.group(0)
        message = txt[: sig_match.start()]
        # do not modify message; it should exactly match the bytes signed earlier
        original_len = len(message.encode("utf-8"))
        b64 = re.sub(r"-----.*?-----", "", sig_block, flags=re.S).strip()
        sig = base64.b64decode(b64.encode())
        # log message length and signature size for debugging
        self.log(f"verifying against message length {original_len}")
        self.log(f"signature length {len(sig)} bytes")
        # choose a public key only if we can't read one from the card
        pub_bytes = None
        if self.pcsc.reader is not None:
            try:
                img = card_crypto.read_image_from_card(reader=str(self.pcsc.reader), manager=self.pcsc)
                pub_bytes = card_crypto.extract_public(img)
            except Exception:
                pub_bytes = None
        if pub_bytes is None:
            # ask user to select from ~/.pmcc via dropdown
            key = self._choose_pubkey_file()
            if key:
                pub_bytes = open(key, "rb").read()
            else:
                QMessageBox.warning(self, "Verify", "no public key available")
                return
        from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_der_public_key
        pk = None
        if len(pub_bytes) == 32:
            pk = Ed25519PublicKey.from_public_bytes(pub_bytes)
        else:
            try:
                pk = load_pem_public_key(pub_bytes)
            except Exception:
                try:
                    pk = load_der_public_key(pub_bytes)
                except Exception:
                    pk = None
        if pk is None:
            QMessageBox.warning(self, "Verify", "unable to parse public key")
            return
        try:
            pk.verify(sig, message.encode("utf-8"))
            QMessageBox.information(self, "Verify", "Signature OK")
            self.log("signature OK")
        except Exception as e:
            # produce diagnostics similar to CLI helper
            msg = str(e)
            if msg:
                dialog_msg = f"verification failed: {msg}"
            else:
                dialog_msg = "verification failed: signature did not verify"
            QMessageBox.warning(self, "Verify", dialog_msg)
            # also log lengths for debugging
            try:
                self.log(f"verification failed: {msg}")
                self.log(f"pub len={len(pub_bytes)} data len={len(message.encode('utf-8'))} sig len={len(sig)}")
            except Exception:
                pass

    def _insert_pubkey(self):
        # try selecting from ~/.pmcc first
        key = self._choose_pubkey_file(allow_blank=True)
        if key:
            try:
                content = open(key, "r", encoding="utf-8", errors="ignore").read()
                self.editor_text.insertPlainText(content + "\n")
                return
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))
                return
        # if user cancelled or no selection, fall back to card
        try:
            rdr = self.pcsc.reader
            img = card_crypto.read_image_from_card(reader=str(rdr), manager=self.pcsc)
            pub = card_crypto.extract_public(img)
            keyobj = Ed25519PublicKey.from_public_bytes(pub)
            pem = keyobj.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            self.editor_text.insertPlainText(pem.decode() + "\n")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _extract_pubkey(self):
        """Pull a public key from the editor text and save to ~/.pmcc."""
        txt = self.editor_text.toPlainText()
        import re
        pem_match = re.search(r"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----", txt, re.S)
        if pem_match:
            pem = pem_match.group(0).encode("utf-8")
        else:
            # try treating entire text as a raw or base64 key
            pem = txt.encode("utf-8")
        # prompt for filename
        name, ok = QInputDialog.getText(self, "Save public key", "Filename (will be created in ~/.pmcc):")
        if not ok or not name.strip():
            return
        dest = Path.home() / ".pmcc" / name.strip()
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "wb") as f:
                f.write(pem)
            os.chmod(dest, 0o600)
            QMessageBox.information(self, "Save pubkey", f"wrote {dest}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"failed to save public key: {e}")


    def _choose_pubkey_file(self, allow_blank: bool = False) -> str | None:
        """Return path of a public-key file from ~/.pmcc via dropdown.

        If *allow_blank* is True the user may cancel/leave empty (returns None).
        Otherwise the dialog will warn if no selection is made.
        """
        home = Path.home() / ".pmcc"
        options = []
        if home.exists():
            for p in sorted(home.iterdir()):
                if p.is_file() and p.suffix.lower() in (".pem", ".raw"):
                    options.append(str(p))
        if not options and not allow_blank:
            QMessageBox.warning(self, "Public key", "no keys found in ~/.pmcc")
            return None
        item, ok = QInputDialog.getItem(self, "Public key file", "Select public key:", options, 0, False)
        if ok and item:
            return item
        return None

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
        # hide the run button on the editor page since its actions are self-contained
        cmd = self.op_combo.currentData()
        if cmd == "editor":
            self.run_btn.setEnabled(False)
        else:
            self.run_btn.setEnabled(True)
        # lookup page index rather than relying on combo index
        page_idx = self.page_indices.get(cmd, idx)
        self.pages.setCurrentIndex(page_idx)

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
        elif cmd == "editor":
            # run button should be disabled in editor mode; nothing to do here
            return
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
