# Poor Man’s Crypto Card (PMCC)

Utilities for creating and using **SLE-series smart-card images** such as:

* SLE4442 (256-byte)
* SLE4428 (1024-byte)

The project provides command-line tools and optional GUI interfaces for:

* Creating card images
* Signing and verifying files
* Encrypting and decrypting messages
* Extracting public keys from cards

---

# Security Warning

**PMCC is not secure key storage.**

Card images contain **raw key material**. Anyone who obtains:

* the card image file, or
* a dump of the card

can copy the encrypted seed and attempt to **brute-force the password**.

This project provides **tools for working with keys**, but **does not protect them against theft or extraction**.

Treat card dumps and images as **sensitive data** and store them securely.

---

# Project Structure

| Component                | Purpose                                                                 |
| ------------------------ | ----------------------------------------------------------------------- |
| `card_crypto.py`         | Perform cryptographic operations using a key stored on a physical card  |
| `make_card_image.py`     | Build a card image containing a keypair and metadata                    |
| `make_card_image_gui.py` | GUI tool for creating card images                                       |
| `card_crypto_gui.py`     | GUI interface for signing, encrypting, verifying, and editing messages  |
| `core/`                  | Shared utilities (PC/SC communication, configuration, language support) |
| `drivers/`               | Low-level SLE card drivers                                              |
| `model/`                 | Data container classes used by tools and GUI                            |
| `i18n/`                  | Translation files                                                       |

The GUI defaults to **English (`en`)**.
You can change the language by editing the `language` setting in the configuration file.

---

# Requirements

Install Python dependencies:

```bash
python3 -m pip install -r requirements.txt
```

You will also need:

* **PC/SC middleware** (`pcsclite`)
* A **compatible smart-card reader**

Without PC/SC installed, the `pyscard` module will fail to load.

Scripts require **Python 3.8+** and were primarily tested on **Linux**, but should work on other platforms with PC/SC support.

---

# Card Image Format

The utilities assume the following memory layout:

```
0x000-0x01F   header (unused)
0x020-0x05F   encrypted Ed25519 private key (64 bytes)
0x060-0x07F   Ed25519 public key (32 bytes)
0x080-0x0FF   metadata (128 bytes)
```

---

# Command-Line Usage

Scripts can be run directly:

```
./card_crypto.py
./make_card_image.py
```

Passwords are **always requested interactively** and are never stored.

Public keys extracted from cards are automatically saved to:

```
~/.pmcc/
```

Generated files use restrictive permissions (`600` / `700`) when possible.

---

# Creating a Card Image

`make_card_image.py` builds a card image for an SLE card.

Default output is **256 bytes (SLE4442)**.
Use `--type sle4428` for **1024-byte images**.

### Example

```bash
python make_card_image.py \
    --blank blank_dump.bin \
    --priv private_enc.der \
    --pub public.raw \
    --metadata First=Alice Last=Smith expire=2026-12-31 \
    -o card.bin
```

For a **1024-byte card image**:

```bash
python make_card_image.py --type sle4428 \
    --blank blank_dump.bin \
    --priv private_enc.der \
    --pub public.raw \
    --metadata First=Alice Last=Smith expire=2026-12-31 \
    -o card_4428.bin
```

---

## Interactive Mode

If arguments are omitted you can run the tool interactively:

```bash
python make_card_image.py --interactive
```

The tool can also generate a **new keypair automatically**.

---

# Metadata

Metadata fields can be provided:

* directly on the command line
* through a JSON file (`--metadata-file`)

Allowed metadata fields are defined in:

```
metadata_fields.json
```

You can supply your own schema using:

```
--metadata-schema
```

If the schema cannot be found, the default fields are used:

```
First
Last
expire
clearance
Issue_Date
```

---

# Cryptographic Operations

`card_crypto.py` interacts with a **live smart card** via PC/SC.

Card image files are **not supported**.

Supported commands:

| Command          | Description                     |
| ---------------- | ------------------------------- |
| `extract-public` | Save the card’s public key      |
| `sign`           | Sign a file                     |
| `verify`         | Verify a signature              |
| `encrypt`        | Encrypt data using the card key |
| `decrypt`        | Decrypt data                    |

---

## Extract Public Key

```bash
python card_crypto.py extract-public
```

The public key is automatically saved to:

```
~/.pmcc/
```

The filename is generated from card metadata.

---

## Sign a File

```bash
python card_crypto.py sign --input message.txt
```

Creates a signature file:

```
message.txt.sig
```

---

## Verify a Signature

```bash
python card_crypto.py verify \
    --pubkey public.pem \
    --input message.txt \
    --sig message.txt.sig
```

If verification fails, the tool prints diagnostic information to help identify incorrect inputs.

---

# GUI Applications

Two optional Qt interfaces are included.

Both require **PySide6**.

---

# Card Image Creator (GUI)

Launch with:

```bash
python make_card_image_gui.py
```

Features:

* Select blank card dump
* Load or generate key pairs
* Enter metadata through structured fields
* Automatic filename generation
* Optional protection map generation
* Status and log output

Default output filename:

```
card_image_<YYYYMMDD>.bin
```

---

# Crypto GUI

Launch with:

```bash
python card_crypto_gui.py
```

Features:

* Automatically detects PC/SC card readers
* Supports signing, encryption, verification, and key extraction
* Includes a built-in message editor

The interface allows you to:

* scan for readers
* connect to a card
* perform cryptographic operations
* view log output

---

# Built-in Editor

The GUI includes a **Markdown-aware editor** for composing and processing messages.

Capabilities include:

* Markdown formatting
* WYSIWYG preview
* file open/save
* encryption and decryption
* signing and verification
* inserting and extracting public keys

The editor starts in **preview mode**, rendering Markdown as formatted text.

A **Preview toggle** allows switching between:

* raw Markdown
* rendered rich text

---

## Important Editor Notes

When performing crypto operations:

* the editor automatically switches to **raw Markdown mode**
* this prevents preview rendering from corrupting encrypted blocks or signatures

Signature blocks are also protected during preview rendering to prevent formatting issues.

---

# Development Notes

* Written in **plain Python**
* No build step required
* Shared logic is located in:

```
core/
drivers/
model/
```

---

# Acknowledgements

Some low-level code was adapted from the [**sle-suite-pro**](https://github.com/wikilift/sle-suite-pro) project developed by **Wikilift**. Their work enabled communication with blank SLE cards and image dumps.

The card images produced by this software are designed to be imported into [**sle-suite-pro**](https://github.com/wikilift/sle-suite-pro) and writen directly to a card.

---

# License

(Add license information here.)

