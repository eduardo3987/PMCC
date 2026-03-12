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
    QTextBrowser,
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
from PySide6.QtGui import QTextCursor, QFont, QIcon, QPixmap, QPainter

# utility composite widget used by the editor page
class MarkdownEditor(QWidget):
    """Simple markdown editor with raw/preview toggle.

    Internally it keeps a ``QTextEdit`` for the raw markdown source and a
    second ``QTextEdit`` for the rendered (and editable) HTML.  Only one
    widget is visible at a time; toggling into preview mode converts the
    markdown to HTML and back again when leaving preview.  This gives a
    basic WYSIWYG experience while allowing full markdown editing when raw
    mode is active.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.editor = QTextEdit()
        self.preview = QTextEdit()
        self.preview.setReadOnly(False)
        self.preview.setAcceptRichText(True)
        self._is_preview = False
        # whether the user has edited in preview; used to avoid stomping the
        # original markdown when simply toggling back and forth.
        self._preview_modified = False
        # internal guard to ignore textChanged signals caused by our own
        # programmatic updates (refresh_preview etc.)
        self._suppress_preview_modified = False

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.editor)
        layout.addWidget(self.preview)
        self.setLayout(layout)

        # start with preview hidden
        self.preview.hide()

        # keep preview updated when typing in raw mode if it's visible
        self.editor.textChanged.connect(self._on_text_changed)

    def _on_text_changed(self):
        if self._is_preview:
            self.refresh_preview()

    def toggle_preview(self):
        # switch between raw markdown and rendered HTML
        if self._is_preview:
            # going back to raw: if the user edited in the rich view we need to
            # convert, otherwise just restore the original markdown so we don't
            # lose any data (CRLFs, unusual spacing, etc.) when the round-trip
            # converter is imperfect.
            if self._preview_modified:
                md = self._to_markdown(self.preview.toHtml())
                self.editor.setPlainText(md)
            self.preview.hide()
            self.editor.show()
            self._is_preview = False
        else:
            # going to preview: render current markdown
            self.refresh_preview()
            self.editor.hide()
            self.preview.show()
            self._is_preview = True
            # we just entered preview; no edits yet
            self._preview_modified = False

    def refresh_preview(self):
        """Re-render the preview from the current editor contents.

        The result is written into the preview QTextEdit (which will preserve
        any existing cursor/selection).
        """
        html = self._to_html(self.editor.toPlainText())
        # updating the preview programmatically shouldn't count as a user edit
        # otherwise simply toggling preview on/off would mark it dirty.
        self._suppress_preview_modified = True
        try:
            self.preview.setHtml(html)
        finally:
            self._suppress_preview_modified = False

    # conversion helpers ---------------------------------------------------

    def _to_html(self, md: str) -> str:
        # protect PMCC/ED25519 signature blocks by wrapping them in a fenced
        # code block.  Without this the markdown renderer will treat the
        # delimiters as ordinary text which ends up being converted to
        # paragraphs; when converting the rich text back to markdown the
        # newline preceding the END marker can be lost, resulting in a
        # malformed signature.  The code block keeps the entire blob intact
        # during round trips and displays nicely in preview as preformatted
        # text.
        import re
        def _protect_sig(match):
            return "```\n" + match.group(0) + "\n```"
        md = re.sub(
            r"(-----BEGIN (?:ED25519|PMCC) SIGNATURE-----.*?-----END (?:ED25519|PMCC) SIGNATURE-----)",
            _protect_sig,
            md,
            flags=re.S,
        )
        try:
            import markdown as _md
            return _md.markdown(md, extensions=["fenced_code", "tables"])
        except ImportError:
            return md

    def _to_markdown(self, html: str) -> str:
        # strip off the Qt-generated <html> / <head> / <body> wrapper if present
        import re
        m = re.search(r"<body[^>]*>(.*)</body>", html, re.S)
        content = m.group(1) if m else html
        try:
            import html2text
            md = html2text.html2text(content)
            # html2text may collapse newlines around signature boundaries; make
            # sure the END marker starts on its own line so verification will
            # continue to work after toggling back and forth.
            md = re.sub(
                r"(?<!\n)(-----END (?:ED25519|PMCC) SIGNATURE-----)",
                r"\n\1",
                md,
            )
            return md.rstrip("\n")
        except ImportError:
            # simple fallback that handles common tags so WYSIWYG edits are
            # somewhat preserved
            # headings
            for i in range(6, 0, -1):
                content = re.sub(
                    rf"<h{i}[^>]*>(.*?)</h{i}>",
                    lambda m: "#" * i + " " + m.group(1) + "\n",
                    content,
                    flags=re.S,
                )
            # bold/strong and spans with font-weight
            content = re.sub(r"<(?:strong|b)>(.*?)</(?:strong|b)>", r"**\1**", content, flags=re.S)
            content = re.sub(r"<span[^>]*font-weight:\s*700[^>]*>(.*?)</span>", r"**\1**", content, flags=re.S)
            # italic/em and spans with font-style
            content = re.sub(r"<(?:em|i)>(.*?)</(?:em|i)>", r"*\1*", content, flags=re.S)
            content = re.sub(r"<span[^>]*font-style:\s*italic[^>]*>(.*?)</span>", r"*\1*", content, flags=re.S)
            # lists
            content = re.sub(r"<ul[^>]*>\s*(<li>.*?</li>)\s*</ul>", lambda m: re.sub(r"<li>(.*?)</li>", r"- \1\n", m.group(1), flags=re.S), content, flags=re.S)
            content = re.sub(r"<ol[^>]*>\s*(<li>.*?</li>)\s*</ol>", lambda m: ''.join(f"{i+1}. {item}\n" for i,item in enumerate(re.findall(r'<li>(.*?)</li>', m.group(1), flags=re.S))), content, flags=re.S)
            # line breaks & paragraphs
            content = re.sub(r"<br\s*/?>", "\n", content)
            content = re.sub(r"</p\s*>", "\n\n", content)
            # strip everything else
            content = re.sub(r"<[^>]+>", "", content)
            # ensure signature END markers remain on their own line
            content = re.sub(
                r"(?<!\n)(-----END (?:ED25519|PMCC) SIGNATURE-----)",
                r"\n\1",
                content,
            )
            return content

    # proxy methods so callers can treat this like a QTextEdit
    def toPlainText(self):
        # always return markdown representation (so callers can ignore mode)
        if self._is_preview:
            return self._to_markdown(self.preview.toHtml())
        return self.editor.toPlainText()

    def setPlainText(self, text):
        # write into the markdown editor; update preview if currently visible
        self.editor.setPlainText(text)
        if self._is_preview:
            self.refresh_preview()

    def insertPlainText(self, text):
        self.editor.insertPlainText(text)
        if self._is_preview:
            self.refresh_preview()

    def textCursor(self):
        # always operate on the underlying plain editor when formatting
        return self.editor.textCursor()

    def setTextCursor(self, cursor):
        return self.editor.setTextCursor(cursor)

    def append(self, text):
        self.editor.append(text)
        if self._is_preview:
            self.refresh_preview()

    def selectAll(self):
        self.editor.selectAll()

    def clear(self):
        self.editor.clear()
        if self._is_preview:
            self.preview.clear()
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
        # list commands in logical order; the editor is placed after the
        # crypto operations so it appears at the bottom of the dropdown.
        self.operations = [
            ("Extract public key", "extract_public"),
            ("Sign file", "sign"),
            ("Verify signature", "verify"),
            ("Encrypt file", "encrypt"),
            ("Decrypt file", "decrypt"),
            ("Editor", "editor"),  # WYSIWYG text editor page
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
        """Construct the WYSIWYG editor page with markdown controls."""
        page = QWidget()
        layout = QVBoxLayout()

        # toolbar: first row has file/crypto operations, second row holds
        # markdown formatting and the preview toggle.
        # row one
        hl1 = QHBoxLayout()
        # file operations
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
            hl1.addWidget(btn)
        layout.addLayout(hl1)

        # row two – formatting tools
        hl2 = QHBoxLayout()
        # create buttons and try to give them standard icons
        def themed(name, fallback_text):
            icon = QIcon.fromTheme(name)
            # some themes lack a heading glyph; synthesize a simple one
            if icon.isNull() and name == "format-text-heading":
                pix = QPixmap(16, 16)
                pix.fill(Qt.transparent)
                painter = QPainter(pix)
                painter.setPen(Qt.black)
                font = painter.font()
                font.setBold(True)
                font.setPointSize(10)
                painter.setFont(font)
                painter.drawText(pix.rect(), Qt.AlignCenter, "H")
                painter.end()
                icon = QIcon(pix)
            btn = QPushButton()
            if not icon.isNull():
                btn.setIcon(icon)
                btn.setText("")
            else:
                btn.setText(fallback_text)
            btn.setToolTip(fallback_text)
            return btn

        self.bold_btn = themed("format-text-bold", "Bold")
        self.bold_btn.setCheckable(True)
        self.italic_btn = themed("format-text-italic", "Italic")
        self.italic_btn.setCheckable(True)
        self.heading_btn = themed("format-text-heading", "Heading")
        self.heading_btn.setCheckable(True)
        self.bullet_btn = themed("format-list-unordered", "Bullet list")
        self.bullet_btn.setCheckable(False)
        self.numbered_btn = themed("format-list-ordered", "Numbered list")
        self.numbered_btn.setCheckable(False)
        self.quote_btn = themed("format-quote", "Quote")
        self.quote_btn.setCheckable(False)
        self.code_inline_btn = themed("insert-text", "Inline code")
        self.code_inline_btn.setCheckable(False)
        self.code_block_btn = themed("code-context", "Code block")
        self.code_block_btn.setCheckable(False)
        self.link_btn = themed("insert-link", "Link")
        self.link_btn.setCheckable(False)
        self.image_btn = themed("insert-image", "Image")
        self.image_btn.setCheckable(False)
        self.hr_btn = themed("insert-horizontal-rule", "Horizontal rule")
        self.hr_btn.setCheckable(False)
        # clear contents button (appears before preview toggle)
        self.clear_btn = themed("edit-clear", "Clear")
        self.clear_btn.setCheckable(False)
        # preview toggle
        self.preview_btn = themed("view-preview", "Preview")
        self.preview_btn.setCheckable(True)
        # prevent toolbar buttons from grabbing focus when clicked
        for btn in (
            self.bold_btn,
            self.italic_btn,
            self.heading_btn,
            self.bullet_btn,
            self.numbered_btn,
            self.quote_btn,
            self.code_inline_btn,
            self.code_block_btn,
            self.link_btn,
            self.image_btn,
            self.hr_btn,
            self.clear_btn,
            self.preview_btn,
        ):
            btn.setFocusPolicy(Qt.NoFocus)
        for btn in (
            self.bold_btn,
            self.italic_btn,
            self.heading_btn,
            self.bullet_btn,
            self.numbered_btn,
            self.quote_btn,
            self.code_inline_btn,
            self.code_block_btn,
            self.link_btn,
            self.image_btn,
            self.hr_btn,
            self.clear_btn,
            self.preview_btn,
        ):
            hl2.addWidget(btn)

        layout.addLayout(hl2)

        # markdown editor widget
        self.markdown_editor = MarkdownEditor()
        layout.addWidget(self.markdown_editor)
        # compatibility alias used elsewhere
        self.editor_text = self.markdown_editor

        page.setLayout(layout)

        # signal connections for file ops
        self.open_btn.clicked.connect(self._open_file_editor)
        self.save_btn.clicked.connect(self._save_file_editor)
        self.encrypt_btn.clicked.connect(self._encrypt_editor)
        self.decrypt_btn.clicked.connect(self._decrypt_editor)
        self.sign_btn.clicked.connect(self._sign_editor)
        self.verify_btn.clicked.connect(self._verify_editor)
        self.insert_pub_btn.clicked.connect(self._insert_pubkey)
        self.extract_pub_btn.clicked.connect(self._extract_pubkey)

        # default the editor to preview mode; this gives users the richer
        # WYSIWYG experience immediately.  The preview button text/state will
        # be updated by _toggle_preview().
        self._toggle_preview()
        # markdown formatting signals
        self.bold_btn.clicked.connect(self._format_bold)
        self.italic_btn.clicked.connect(self._format_italic)
        self.heading_btn.clicked.connect(self._format_heading)
        self.bullet_btn.clicked.connect(self._format_bullet)
        self.numbered_btn.clicked.connect(self._format_numbered)
        self.quote_btn.clicked.connect(self._format_quote)
        self.code_inline_btn.clicked.connect(self._format_code_inline)
        self.code_block_btn.clicked.connect(self._format_code_block)
        self.link_btn.clicked.connect(self._insert_link)
        self.image_btn.clicked.connect(self._insert_image)
        self.hr_btn.clicked.connect(self._insert_hr)
        self.clear_btn.clicked.connect(self._clear_editor)
        self.preview_btn.clicked.connect(self._toggle_preview)

        # maintain raw-mode heading flag used when typing
        self._raw_heading_mode = False
        # maintain preview-mode heading flag so new paragraphs inherit style
        self._preview_heading_mode = False
        # keep bold/italic/heading state in sync with cursor
        def connect_cursor_signals(widget):
            widget.cursorPositionChanged.connect(self._update_format_buttons)
        self.editor_text.editor.cursorPositionChanged.connect(self._update_format_buttons)
        self.editor_text.preview.cursorPositionChanged.connect(self._update_format_buttons)
        # raw editor newline insertion handler
        self.editor_text.editor.textChanged.connect(self._on_raw_text_changed)
        # preview text change handler to enforce heading mode on text changes
        self.editor_text.preview.textChanged.connect(self._on_preview_text_changed)
        # install filter to intercept Enter and create heading blocks when needed
        from PySide6.QtCore import QObject, QEvent, QTimer
        class _PreviewFilter(QObject):
            def __init__(self, parent):
                super().__init__(parent)
                self.win = parent
            def eventFilter(self, obj, ev):
                if ev.type() == QEvent.KeyPress and ev.key() == Qt.Key_Return:
                    if getattr(self.win, '_preview_heading_mode', False):
                        cursor = obj.textCursor()
                        # insert new block and apply heading format immediately
                        cursor.insertBlock()
                        block_fmt = cursor.blockFormat()
                        block_fmt.setHeadingLevel(1)
                        cursor.mergeBlockFormat(block_fmt)
                        fmt = cursor.charFormat()
                        fmt.setFontPointSize(24)
                        cursor.mergeCharFormat(fmt)
                        obj.setTextCursor(cursor)
                        return True
                return False
        self.editor_text.preview.installEventFilter(_PreviewFilter(self))
        return page

    # ------------------------------------------------------------------
    # editor helpers
    # ------------------------------------------------------------------

    def _open_file_editor(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open file")
        if path:
            # ensure raw mode so loading a file doesn't attempt to render in
            # preview (may be large and slow)
            self._ensure_raw_mode()
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    self.editor_text.setPlainText(f.read())
            except Exception as e:
                QMessageBox.critical(self, "Error", f"cannot open file: {e}")

    def _save_file_editor(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save file")
        if path:
            # when saving it's fine to grab the raw text; if we are currently in
            # preview mode we don't want to force a conversion here since the
            # editor already keeps the raw markdown up to date, but the helper
            # below normalises it anyway.
            self._ensure_raw_mode()
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.editor_text.toPlainText())
            except Exception as e:
                QMessageBox.critical(self, "Error", f"cannot save file: {e}")

    def _ensure_raw_mode(self):
        """If the markdown editor is showing a preview, switch back to raw mode.

        This is important for crypto operations because the preview renderer can
        mangle binary-looking blocks (base64, signature delimiters) and the
        conversions are expensive; leaving the editor in preview state while
        inserting or reading large text may appear to lock the UI.  By forcing
        raw mode we operate directly on the underlying QTextEdit contents and
        avoid unnecessary markdown/html round trips.
        """
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            self.log("disabling preview mode for crypto operation")
            # _toggle_preview handles the conversion and button state updates
            self._toggle_preview()

    def _encrypt_editor(self):
        # make sure we are not in preview mode before grabbing the text; this
        # also synchronises any edits the user may have made in the WYSIWYG
        # view back into the raw markdown buffer.
        self._ensure_raw_mode()

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
        # make sure we're not in preview mode, otherwise reading the contents
        # may trigger a costly html->markdown conversion and writing the output
        # could attempt to render an arbitrarily large result.
        self._ensure_raw_mode()
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
        # ensure raw markdown so we don't accidentally mangle the signature
        # boundaries when preview mode is active (those lines look like
        # horizontal rules to the markdown parser).
        self._ensure_raw_mode()

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
        # signature search and verification must operate on the original
        # markdown text; convert preview to raw if necessary so we don't end up
        # looking at HTML-ified content.
        self._ensure_raw_mode()
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

    # ------------------------------------------------------------------
    # markdown formatting helpers
    # ------------------------------------------------------------------

    def _refresh_if_needed(self):
        """If the editor is currently showing a preview, regenerate it."""
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            self.editor_text.refresh_preview()

    def _prepare_for_formatting(self):
        """When preview is active convert its HTML back to markdown.

        After calling this the plain-text editor holds the up‑to‑date markdown
        content which formatting helpers can operate on; the preview will be
        regenerated later by ``_refresh_if_needed``.
        """
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            md = self.editor_text._to_markdown(self.editor_text.preview.toHtml())
            self.editor_text.editor.setPlainText(md)

    def _wrap_selection(self, before: str, after: str | None = None) -> None:
        if after is None:
            after = before
        # ensure we're working with markdown if preview mode was active
        self._prepare_for_formatting()
        te = self.editor_text.editor if isinstance(self.editor_text, MarkdownEditor) else self.editor_text
        cursor = te.textCursor()
        if cursor.hasSelection():
            selected = cursor.selectedText()
            cursor.insertText(f"{before}{selected}{after}")
        else:
            cursor.insertText(f"{before}{after}")
            # position cursor between markers
            pos = cursor.position()
            cursor.setPosition(pos - len(after))
            te.setTextCursor(cursor)
        self._refresh_if_needed()

    def _prefix_lines(self, prefix_func):
        self._prepare_for_formatting()
        te = self.editor_text.editor if isinstance(self.editor_text, MarkdownEditor) else self.editor_text
        cursor = te.textCursor()
        if not cursor.hasSelection():
            cursor.select(QTextCursor.LineUnderCursor)
        text = cursor.selectedText()
        lines = text.splitlines()
        new_lines = []
        for i, line in enumerate(lines):
            new_lines.append(prefix_func(line, i))
        cursor.insertText("\n".join(new_lines))
        self._refresh_if_needed()

    def _format_bold(self):
        # in preview mode, toggle bold formatting
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            te = self.editor_text.preview
            cursor = te.textCursor()
            if cursor.hasSelection():
                fmt = cursor.charFormat()
                if fmt.fontWeight() == QFont.Bold:
                    fmt.setFontWeight(QFont.Normal)
                    self.bold_btn.setChecked(False)
                else:
                    fmt.setFontWeight(QFont.Bold)
                    self.bold_btn.setChecked(True)
                cursor.mergeCharFormat(fmt)
            else:
                # change default weight for new text
                current = te.fontWeight()
                newweight = QFont.Normal if current == QFont.Bold else QFont.Bold
                te.setFontWeight(newweight)
                self.bold_btn.setChecked(newweight == QFont.Bold)
            te.setFocus()
            return
        self._wrap_selection("**")
        # after raw-formatting bring focus back to editor
        self.editor_text.editor.setFocus()

    def _format_italic(self):
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            te = self.editor_text.preview
            cursor = te.textCursor()
            if cursor.hasSelection():
                fmt = cursor.charFormat()
                italic = not fmt.fontItalic()
                fmt.setFontItalic(italic)
                cursor.mergeCharFormat(fmt)
                self.italic_btn.setChecked(italic)
            else:
                newval = not te.fontItalic()
                te.setFontItalic(newval)
                self.italic_btn.setChecked(newval)
            te.setFocus()
            return
        self._wrap_selection("*")
        self.editor_text.editor.setFocus()

    def _format_heading(self):
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            te = self.editor_text.preview
            cursor = te.textCursor()
            block_fmt = cursor.blockFormat()
            current = block_fmt.headingLevel()
            if current == 1:
                # turning off heading
                block_fmt.setHeadingLevel(0)
                self.heading_btn.setChecked(False)
                self._preview_heading_mode = False
                cursor.mergeBlockFormat(block_fmt)
                # reset char size for entire block
                fmt = cursor.charFormat()
                fmt.setFontPointSize(0)
                cursor.select(QTextCursor.BlockUnderCursor)
                cursor.mergeCharFormat(fmt)
            else:
                # enabling heading
                block_fmt.setHeadingLevel(1)
                self.heading_btn.setChecked(True)
                self._preview_heading_mode = True
                cursor.mergeBlockFormat(block_fmt)
                # enlarge text in block
                fmt = cursor.charFormat()
                fmt.setFontPointSize(24)
                cursor.select(QTextCursor.BlockUnderCursor)
                cursor.mergeCharFormat(fmt)
            te.setTextCursor(cursor)
            from PySide6.QtCore import QTimer
            QTimer.singleShot(0, lambda: te.setFocus())
            return
        # raw markdown mode: toggle heading prefix mode
        te = self.editor_text.editor
        self._raw_heading_mode = not getattr(self, '_raw_heading_mode', False)
        self.heading_btn.setChecked(self._raw_heading_mode)
        cursor = te.textCursor()
        cursor.select(QTextCursor.LineUnderCursor)
        text = cursor.selectedText()
        if self._raw_heading_mode:
            if not text.startswith("#"):
                cursor.insertText("# " + text)
        else:
            # remove leading hashes/spaces
            newtext = text.lstrip("# ")
            cursor.insertText(newtext)
        te.setTextCursor(cursor)
        te.setFocus()

    def _format_bullet(self):
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            from PySide6.QtGui import QTextListFormat
            te = self.editor_text.preview
            cursor = te.textCursor()
            fmt = QTextListFormat()
            fmt.setStyle(QTextListFormat.ListDisc)
            cursor.createList(fmt)
            from PySide6.QtCore import QTimer
            QTimer.singleShot(0, lambda: te.setFocus())
            return
        def bullet(line, idx):
            return "- " + line.lstrip("- ")
        self._prefix_lines(bullet)

    def _format_numbered(self):
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            from PySide6.QtGui import QTextListFormat
            te = self.editor_text.preview
            cursor = te.textCursor()
            fmt = QTextListFormat()
            fmt.setStyle(QTextListFormat.ListDecimal)
            cursor.createList(fmt)
            from PySide6.QtCore import QTimer
            QTimer.singleShot(0, lambda: te.setFocus())
            return
        def num(line, idx):
            return f"{idx+1}. " + line.lstrip("0123456789. ")
        self._prefix_lines(num)


    def _format_quote(self):
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            te = self.editor_text.preview
            cursor = te.textCursor()
            cursor.insertHtml("<blockquote></blockquote>")
            return
        def quote(line, idx):
            return "> " + line
        self._prefix_lines(quote)

    def _format_code_inline(self):
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            te = self.editor_text.preview
            cursor = te.textCursor()
            if cursor.hasSelection():
                sel = cursor.selectedText()
                cursor.insertHtml(f"<code>{sel}</code>")
            else:
                cursor.insertHtml("<code></code>")
                pos = cursor.position()
                cursor.setPosition(pos - 7)
                te.setTextCursor(cursor)
            return
        self._wrap_selection("`")

    def _format_code_block(self):
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            te = self.editor_text.preview
            cursor = te.textCursor()
            cursor.insertHtml("<pre><code></code></pre>")
            return
        te = self.editor_text.editor if isinstance(self.editor_text, MarkdownEditor) else self.editor_text
        cursor = te.textCursor()
        lang, ok = QInputDialog.getText(self, "Code block", "Language (optional):")
        if not ok:
            return
        lang = lang.strip()
        if cursor.hasSelection():
            sel = cursor.selectedText()
            block = f"```{lang}\n{sel}\n```"
            cursor.insertText(block)
        else:
            block = f"```{lang}\n\n```"
            cursor.insertText(block)
            # put cursor between the newlines
            pos = cursor.position()
            cursor.setPosition(pos - 4)  # before the closing ```
            te.setTextCursor(cursor)
        self._refresh_if_needed()

    def _insert_link(self):
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            te = self.editor_text.preview
            cursor = te.textCursor()
            default = cursor.selectedText() or ""
            text, ok1 = QInputDialog.getText(self, "Link text", "Text:", text=default)
            if not ok1:
                te.setFocus()
                return
            url, ok2 = QInputDialog.getText(self, "Link URL", "URL:")
            if not ok2 or not url:
                te.setFocus()
                return
            cursor.insertHtml(f"<a href=\"{url}\">{text or url}</a>")
            te.setFocus()
            return
        te = self.editor_text.editor if isinstance(self.editor_text, MarkdownEditor) else self.editor_text
        cursor = te.textCursor()
        selected = cursor.selectedText()
        default = selected or ""
        text, ok1 = QInputDialog.getText(self, "Link text", "Text:", text=default)
        if not ok1:
            te.setFocus()
            return
        url, ok = QInputDialog.getText(self, "Link URL", "URL:")
        if not ok or not url:
            te.setFocus()
            return
        cursor.insertText(f"[{text or url}]({url})")
        self._refresh_if_needed()
        te.setFocus()
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            te = self.editor_text.preview
            cursor = te.textCursor()
            text = cursor.selectedText() or "text"
            url, ok = QInputDialog.getText(self, "Link", "URL:")
            if not ok or not url:
                return
            cursor.insertHtml(f"<a href=\"{url}\">{text}</a>")
            return
        te = self.editor_text.editor if isinstance(self.editor_text, MarkdownEditor) else self.editor_text
        cursor = te.textCursor()
        selected = cursor.selectedText()
        text = selected or "text"
        url, ok = QInputDialog.getText(self, "Link", "URL:")
        if not ok or not url:
            return
        cursor.insertText(f"[{text}]({url})")
        self._refresh_if_needed()

    def _insert_image(self):
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            te = self.editor_text.preview
            cursor = te.textCursor()
            alt, ok1 = QInputDialog.getText(self, "Image", "Alt text:")
            if not ok1:
                te.setFocus()
                return
            url, ok2 = QInputDialog.getText(self, "Image", "URL:")
            if not ok2 or not url:
                te.setFocus()
                return
            cursor.insertHtml(f"<img src=\"{url}\" alt=\"{alt}\" />")
            te.setFocus()
            return
        te = self.editor_text.editor if isinstance(self.editor_text, MarkdownEditor) else self.editor_text
        cursor = te.textCursor()
        alt, ok1 = QInputDialog.getText(self, "Image", "Alt text:")
        if not ok1:
            te.setFocus()
            return
        url, ok2 = QInputDialog.getText(self, "Image", "URL:")
        if not ok2 or not url:
            te.setFocus()
            return
        cursor.insertText(f"![{alt}]({url})")
        self._refresh_if_needed()
        te.setFocus()
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            te = self.editor_text.preview
            cursor = te.textCursor()
            alt, ok1 = QInputDialog.getText(self, "Image", "Alt text:")
            if not ok1:
                return
            url, ok2 = QInputDialog.getText(self, "Image", "URL:")
            if not ok2 or not url:
                return
            cursor.insertHtml(f"<img src=\"{url}\" alt=\"{alt}\" />")
            return
        te = self.editor_text.editor if isinstance(self.editor_text, MarkdownEditor) else self.editor_text
        cursor = te.textCursor()
        alt, ok1 = QInputDialog.getText(self, "Image", "Alt text:")
        if not ok1:
            return
        url, ok2 = QInputDialog.getText(self, "Image", "URL:")
        if not ok2 or not url:
            return
        cursor.insertText(f"![{alt}]({url})")
        self._refresh_if_needed()

    def _insert_hr(self):
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            te = self.editor_text.preview
            cursor = te.textCursor()
            cursor.insertHtml("<hr/>")
            te.setFocus()
            return
        te = self.editor_text.editor if isinstance(self.editor_text, MarkdownEditor) else self.editor_text
        cursor = te.textCursor()
        cursor.insertText("\n---\n")
        self._refresh_if_needed()
        te.setFocus()

    def _update_format_buttons(self):
        """Synchronize bold/italic/heading button states with current cursor."""
        te = self.editor_text.preview if (
            isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview
        ) else self.editor_text.editor if isinstance(self.editor_text, MarkdownEditor) else self.editor_text
        cursor = te.textCursor()
        fmt = cursor.charFormat()
        self.bold_btn.setChecked(fmt.fontWeight() == QFont.Bold)
        self.italic_btn.setChecked(fmt.fontItalic())
        # heading detection via block format when in preview
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            block_fmt = cursor.blockFormat()
            self.heading_btn.setChecked(block_fmt.headingLevel() == 1)
        else:
            # in raw mode reflect toggled state
            self.heading_btn.setChecked(self._raw_heading_mode)

    def _on_raw_text_changed(self):
        """Auto-prefix new lines with ``# `` if raw heading mode is active."""
        if not getattr(self, "_raw_heading_mode", False):
            return
        te = self.editor_text.editor
        # quick check: last char of document
        txt = te.toPlainText()
        if not txt or not txt.endswith("\n"):
            return
        # insert prefix at cursor position
        cursor = te.textCursor()
        cursor.insertText("# ")
        te.setTextCursor(cursor)

    def _on_preview_text_changed(self):
        """Ensure new paragraphs inherit heading style when preview heading mode is on."""
        # ignore programmatic updates
        if getattr(self, '_suppress_preview_modified', False):
            return
        # mark as edited by the user
        self._preview_modified = True
        if hasattr(self, '_suppress_preview_change') and self._suppress_preview_change:
            return
        if not getattr(self, "_preview_heading_mode", False):
            return
        te = self.editor_text.preview
        txt = te.toPlainText()
        if not txt or not txt.endswith("\n"):
            return
        # apply heading block and char format to current (new) block without reentering
        self._suppress_preview_change = True
        try:
            cursor = te.textCursor()
            block_fmt = cursor.blockFormat()
            block_fmt.setHeadingLevel(1)
            cursor.mergeBlockFormat(block_fmt)
            # adjust char size as well
            fmt = cursor.charFormat()
            fmt.setFontPointSize(24)
            cursor.mergeCharFormat(fmt)
            te.setTextCursor(cursor)
        finally:
            self._suppress_preview_change = False

    def _toggle_preview(self):
        if isinstance(self.editor_text, MarkdownEditor):
            self.editor_text.toggle_preview()
            # update button label/checked state
            if self.editor_text._is_preview:
                self.preview_btn.setText("Raw")
                self.preview_btn.setChecked(True)
                # defer focus until after toggle completed
                from PySide6.QtCore import QTimer
                QTimer.singleShot(0, lambda: self.editor_text.preview.setFocus())
            else:
                self.preview_btn.setText("Preview")
                self.preview_btn.setChecked(False)
                from PySide6.QtCore import QTimer
                QTimer.singleShot(0, lambda: self.editor_text.editor.setFocus())


    def _clear_editor(self):
        """Remove all text from the editor and reset modified state."""
        self.editor_text.clear()
        # if preview was active, also clear that view
        if isinstance(self.editor_text, MarkdownEditor) and self.editor_text._is_preview:
            self.editor_text.preview.clear()
        # nothing in preview now
        if isinstance(self.editor_text, MarkdownEditor):
            self.editor_text._preview_modified = False
        self.log("editor cleared")

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
