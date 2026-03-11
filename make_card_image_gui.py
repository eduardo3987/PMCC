#!/usr/bin/env python3
"""Simple GUI front end for ``make_card_image.py``.

Uses PySide6 (Qt) which is already a dependency of the project.  The GUI
lets the user select the various pieces required to construct a card image and
invokes the helper functions from ``make_card_image`` so that the command line
and GUI remain consistent.

The interface is intentionally minimal: select blank/private/public files or
"generate" a new key pair, edit metadata text, choose an output path, and hit
"Create image".  A log area displays progress and errors.
"""

import sys
import os
import json
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
    QCheckBox,
    QMessageBox,
    QHBoxLayout,
    QVBoxLayout,
    QInputDialog,
)

import make_card_image as mci


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Card Image Creator")
        self.priv_bytes = None
        self.pub_bytes = None

        main_layout = QVBoxLayout()

        # card type
        main_layout.addWidget(QLabel("Card type"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["sle4442", "sle4428"])
        main_layout.addWidget(self.type_combo)

        # blank file
        self.blank_edit = QLineEdit()
        btn_blank = QPushButton("Select blank dump...")
        btn_blank.clicked.connect(self.choose_blank)
        hl = QHBoxLayout()
        hl.addWidget(self.blank_edit)
        hl.addWidget(btn_blank)
        main_layout.addWidget(QLabel("Blank card dump"))
        main_layout.addLayout(hl)

        # private/public keys
        self.priv_edit = QLineEdit()
        self.pub_edit = QLineEdit()
        btn_priv = QPushButton("...")
        btn_priv.clicked.connect(self.choose_priv)
        btn_pub = QPushButton("...")
        btn_pub.clicked.connect(self.choose_pub)
        gen_btn = QPushButton("Generate key pair")
        gen_btn.clicked.connect(self.generate_keys)
        save_priv_btn = QPushButton("Save private key...")
        save_priv_btn.clicked.connect(self.save_priv)
        save_pub_btn = QPushButton("Save public key...")
        save_pub_btn.clicked.connect(self.save_pub)

        hl_priv = QHBoxLayout()
        hl_priv.addWidget(self.priv_edit)
        hl_priv.addWidget(btn_priv)
        hl_priv.addWidget(save_priv_btn)
        hl_pub = QHBoxLayout()
        hl_pub.addWidget(self.pub_edit)
        hl_pub.addWidget(btn_pub)
        hl_pub.addWidget(save_pub_btn)

        main_layout.addWidget(QLabel("Private key file"))
        main_layout.addLayout(hl_priv)
        main_layout.addWidget(QLabel("Public key file"))
        main_layout.addLayout(hl_pub)
        main_layout.addWidget(gen_btn)

        # metadata fields (loaded from schema)
        self.metadata_edits: dict[str, QLineEdit] = {}
        fields = mci._load_metadata_fields(None)
        if fields:
            main_layout.addWidget(QLabel("Metadata"))
            for field in fields:
                hl = QHBoxLayout()
                hl.addWidget(QLabel(field))
                edit = QLineEdit()
                self.metadata_edits[field] = edit
                hl.addWidget(edit)
                main_layout.addLayout(hl)

            # when any metadata field changes we may need to update default output
            for edit in self.metadata_edits.values():
                edit.editingFinished.connect(self.update_output_default)

        # output file
        self.output_edit = QLineEdit()
        btn_out = QPushButton("Choose output...")
        btn_out.clicked.connect(self.choose_output)
        hl_out = QHBoxLayout()
        hl_out.addWidget(self.output_edit)
        hl_out.addWidget(btn_out)
        main_layout.addWidget(QLabel("Output image file"))
        main_layout.addLayout(hl_out)
        # initialise with a sensible default including date
        self.update_output_default()

        # protect checkbox
        self.protect_checkbox = QCheckBox("Create protection map locking header")
        main_layout.addWidget(self.protect_checkbox)

        # generate button
        gen_img = QPushButton("Create image")
        gen_img.clicked.connect(self.on_generate)
        main_layout.addWidget(gen_img)

        # log area
        main_layout.addWidget(QLabel("Log"))
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        main_layout.addWidget(self.log_area)

        self.setLayout(main_layout)

    def log(self, msg: str) -> None:
        self.log_area.append(msg)

    def choose_blank(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select blank dump")
        if path:
            self.blank_edit.setText(path)

    def choose_priv(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select private key")
        if path:
            self.priv_edit.setText(path)
            self.priv_bytes = None

    def choose_pub(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select public key")
        if path:
            self.pub_edit.setText(path)
            self.pub_bytes = None

    def choose_output(self):
        path, _ = QFileDialog.getSaveFileName(self, "Output image file", filter="Binary files (*.bin);;All files (*)")
        if path:
            self.output_edit.setText(path)

    def generate_keys(self):
        # generate new ed25519 pair and optionally encrypt private key
        from cryptography.hazmat.primitives.asymmetric import ed25519

        pwd, ok = QInputDialog.getText(
            self,
            "Encrypt private key",
            "Password (leave empty for none):",
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            return
        if pwd == "":
            pwd = None

        privkey = ed25519.Ed25519PrivateKey.generate()
        seed = privkey.private_bytes(
            encoding=mci.serialization.Encoding.Raw,
            format=mci.serialization.PrivateFormat.Raw,
            encryption_algorithm=mci.serialization.NoEncryption(),
        )
        if pwd:
            priv_store = mci._encrypt_seed(seed, pwd)
        else:
            priv_store = seed
        pub_bytes = privkey.public_key().public_bytes(
            encoding=mci.serialization.Encoding.Raw,
            format=mci.serialization.PublicFormat.Raw,
        )
        self.priv_bytes = priv_store
        self.pub_bytes = pub_bytes
        self.priv_edit.setText("<generated>")
        self.pub_edit.setText("<generated>")
        self.log("Generated new key pair")

    def save_priv(self):
        if not self.priv_bytes:
            QMessageBox.information(self, "Save private key", "No generated private key available")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save private key", filter="DER files (*.der);;All files (*)")
        if path:
            with open(path, "wb") as f:
                f.write(self.priv_bytes)
                os.fchmod(f.fileno(), 0o600)
            self.log(f"Saved private key to {path}")

    def save_pub(self):
        if not self.pub_bytes:
            QMessageBox.information(self, "Save public key", "No generated public key available")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save public key", filter="Raw key (*.raw);;All files (*)")
        if path:
            with open(path, "wb") as f:
                f.write(self.pub_bytes)
                os.fchmod(f.fileno(), 0o644)
            self.log(f"Saved public key to {path}")

    def update_output_default(self):
        # compute default based on current metadata; only set if user hasn't
        # typed something custom.
        current = self.output_edit.text().strip()
        if current:
            return
        md = {fld: edt.text().strip() for fld, edt in self.metadata_edits.items() if edt.text().strip()}
        self.output_edit.setText(mci.default_output_name(md))

    def on_generate(self):
        try:
            blank = self.blank_edit.text().strip()
            if not blank:
                raise ValueError("blank dump path is required")
            header = mci.read_header(blank)

            # private key
            if self.priv_bytes is not None:
                priv = self.priv_bytes
            else:
                priv = mci.load_file(self.priv_edit.text().strip())
            # public key
            if self.pub_bytes is not None:
                pub = self.pub_bytes
            else:
                pub = mci.load_file(self.pub_edit.text().strip(), expected=32)

                # metadata: read each field edit
            md = {}
            md_pairs = []
            for field, edit in self.metadata_edits.items():
                val = edit.text().strip()
                if val:
                    md[field] = val
                    md_pairs.append(f"{field}={val}")
            args = argparse.Namespace(metadata=md_pairs, metadata_file=None, metadata_schema=None)
            metadata_bytes = mci.build_metadata(args)

            output = self.output_edit.text().strip()
            if not output:
                output = mci.default_output_name(md)
            protect = self.protect_checkbox.isChecked()

            card_type = self.type_combo.currentText()

            mci.make_image(header, priv, pub, metadata_bytes, card_type, output, protect)
            self.log(f"Created image {output}")
            if protect:
                pm = os.path.splitext(output)[0] + "_pm.bin"
                self.log(f"Created protection map {pm}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            self.log(f"Error: {e}")


if __name__ == "__main__":
    import argparse

    app = QApplication(sys.argv)
    win = MainWindow()
    win.resize(600, 700)
    win.show()
    sys.exit(app.exec())
