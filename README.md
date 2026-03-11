# Card utilities

Utilities for building and working with SLE‑series smart‑card images (SLE4442,
SLE4428, SLE5528 and similar).  This repository is a collection of standalone
command‑line helpers together with supporting Python modules for card
communication and data formatting.  The command‑line tools support both
256‑byte (SLE4442) and 1024‑byte (SLE4428) images where applicable.

> **Note:** current scripts were written for Python 3.8+ and tested on Linux;
> behaviour should be identical on other platforms supporting PC/SC
> readers.

## Contents

- `card_crypto.py` – sign/verify and encrypt/decrypt data using keys stored in a
  card image or read from a physical card.
- `make_card_image.py` – build a 256‑byte card image containing an encrypted
  Ed25519 private key, its public counterpart, and optional metadata.
- `core/` – shared helpers for PC/SC communication, ATR detection, language
  resources and settings management used by the utilities.
- `drivers/` – low‑level drivers for SLE‑family cards (4428, 4442, 5528).
- `model/` – simple data container classes used by the command‑line tools and
  GUI.
- `i18n/` – translation files used by the GUI and utilities.


## Prerequisites

Install the Python dependencies listed in `requirements.txt`:

```sh
python3 -m pip install -r requirements.txt
```

Depending on your system you may need the PC/SC middleware (`pcsclite`) and a
compatible reader installed.  The `pyscard` package will fail to import without
it.

## Usage

Most helpers are invoked directly from the command line.  For convenience the
scripts are made executable and contain a shebang so they can be run as
`./card_crypto.py` etc.

### make_card_image.py

Create a card image for either an SLE4442 or SLE4428 device.  By default the
script builds a 256‑byte image (SLE4442); pass `--type sle4428` to generate a
1024‑byte dump suitable for SLE4428 cards.

```sh
# build using existing key files and a blank dump (SLE4442 default)
python make_card_image.py \ 
    --blank blank_dump.bin \ 
    --priv private_enc.der \ 
    --pub public.raw \ 
    --metadata First=Alice Last=Smith expire=2026-12-31 \ 
    -o card.bin

# for a 1024-byte SLE4428 image include the type flag
python make_card_image.py --type sle4428 \
    --blank blank_dump.bin \
    --priv private_enc.der \
    --pub public.raw \
    --metadata First=Alice Last=Smith expire=2026-12-31 \
    -o card_4428.bin
```

You can also run interactively and generate a new key pair when arguments are
omitted:

```sh
python make_card_image.py --interactive
```

Metadata may be supplied directly on the command line or via a JSON file
(`--metadata-file`).  The script will optionally produce a `_pm.bin` protection
map locking the header bytes.

### card_crypto.py

Interact with key material stored inside a card image or on a live card.  The
memory layout assumed by this utility is:

```
0x000-0x01F   header (unused)
0x020-0x05F   encrypted Ed25519 private key (64 bytes)
0x060-0x07F   Ed25519 public key (32 bytes)
0x080-0x0FF   metadata area (128 bytes)
```

Supported commands:

- `extract-public` – dump public key from image/card to PEM file.
- `dump-private` – decrypt & export private key (DER/PEM/raw seed).
- `sign` / `verify` – Ed25519 signing and verification.
- `encrypt` / `decrypt` – sealed‑box encryption using the card’s key.

Examples:

```sh
# get public key from a local image
python card_crypto.py extract-public --card-image card.bin

# sign a file using key on attached card
python card_crypto.py sign --input message.txt

# verify a signature
python card_crypto.py verify --pubkey public.pem \
    --input message.txt --sig signature.sig
```

The helpers will default output filenames to `$HOME/.pmcc/*` when not
specified.

## Development

- Source files are plain Python; there is no build step.
- `core/`, `drivers/` and `model/` packages contain the shared logic used by
  the command‑line tools.
- Tests are not included; adapt or replicate functionality as needed.

## License

(If the project has a license add appropriate text here; otherwise state that
it's unspecified.)

