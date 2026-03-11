#!/usr/bin/env python3
"""Build a card image following the layout described by the user.

Supports SLE4442 (256‑byte) and SLE4428 (1024‑byte) chips; the desired type
is selected with ``--type`` (defaults to ``sle4442``).

Memory map used by this helper (offsets are identical for both sizes):

    0x000-0x01F   manufacturer header (copied "as is" from a blank dump)
    0x020-0x05F   encrypted Ed25519 private key (64 bytes)
    0x060-0x07F   Ed25519 public key (32 bytes)
    0x080-0x0FF   metadata area (128 bytes)

Values shorter than the allotted space are padded with 0x00; the image length
is determined by the selected card type.  A companion protection map file can
also be created, protecting the header region (0x00-0x1F) by default.

The metadata area is a simple UTF-8 encoded sequence of ``key=value`` lines
terminated by a blank line.  The set of valid keys is not baked into the
script; a companion JSON schema (``metadata_fields.json``) controls which
fields are considered and in what order.  The default schema lists the
following fields, which may be supplied on the command line or via a
JSON/YAML file:
    First, Last, expire, clearance, Issue_Date

Example invocation::

    python make_card_image.py \
        --type sle4428 \
        --blank blank_dump.bin \
        --priv private_enc.der \
        --pub public.raw \
        --metadata First=Alice Last=Smith expire=2026-12-31 \
        -o card.bin

You can also supply ``--metadata-file`` pointing to a JSON file with the
above keys.
"""

import argparse
import json
import os
import sys
import getpass
from pathlib import Path
import tempfile
import re


def _sanitize_filename_component(s: str) -> str:
    # restrict automatically generated names to a safe subset
    return re.sub(r"[^A-Za-z0-9_-]", "_", s)


def parse_args():
    parser = argparse.ArgumentParser(description="Build a card image from pieces")
    parser.add_argument("--type",
                        choices=["sle4442", "sle4428"],
                        default="sle4442",
                        help="card type/size (" 
                             "sle4442=256‑byte, sle4428=1024‑byte)")
    parser.add_argument("--blank", help="path to blank card dump used for header")
    parser.add_argument("--priv", help="DER file containing encrypted private key")
    parser.add_argument("--pub", help="raw 32‑byte public key file")
    parser.add_argument(
        "--metadata",
        nargs="*",
        help="metadata key=value pairs (see docs above)",
        default=[],
    )
    parser.add_argument(
        "--metadata-file",
        help="JSON file containing metadata keys",
        default=None,
    )
    parser.add_argument(
        "--metadata-schema",
        help="JSON file defining metadata field names",
        default=None,
    )
    parser.add_argument("-o", "--output", help="output image filename")
    parser.add_argument("--protect", action="store_true", help="also write a protection map locking the header")
    parser.add_argument("--interactive", action="store_true", help="prompt for missing information and optionally generate keys")
    parser.add_argument("--gui", action="store_true", help="launch graphical interface")
    return parser.parse_args()


def read_header(blank_path: str, size: int = 0x20) -> bytes:
    try:
        with open(blank_path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise FileNotFoundError(f"cannot open blank dump '{blank_path}': {e}")
    if len(data) < size:
        raise ValueError(f"blank dump is only {len(data)} bytes long")
    return data[:size]


from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def load_file(path: str, expected: int = None) -> bytes:
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise FileNotFoundError(f"cannot open file '{path}': {e}")
    if expected is None:
        return data
    if len(data) == expected:
        return data
    # if the length does not match, but we're expecting a public key, try
    # to parse it as DER and extract raw bytes (handles openssl output).
    if expected == 32:
        try:
            key = serialization.load_der_public_key(data)
            raw = key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            if len(raw) == 32:
                return raw
        except Exception:
            pass
    raise ValueError(f"{path} is {len(data)} bytes, expected {expected}")


def _load_metadata_fields(schema_path: str | None = None) -> list[str]:
    """Return the ordered list of metadata field names.

    The schema is stored in a small JSON file (default ``metadata_fields.json``
    next to this script).  It may be overridden on the command line using
    ``--metadata-schema``.  The file can either be a simple list of strings or
    an object with a ``fields`` key pointing to such a list.  If the file is
    missing we fall back to the hard‑coded defaults for backwards
    compatibility.
    """
    default = ["First", "Last", "expire", "clearance", "Issue_Date"]
    if schema_path is None:
        schema_path = Path(__file__).parent / "metadata_fields.json"
    try:
        with open(schema_path, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        return default
    if isinstance(data, dict) and "fields" in data and isinstance(data["fields"], list):
        return data["fields"]
    if isinstance(data, list):
        return data
    raise ValueError(f"invalid metadata schema in {schema_path}")


def build_metadata(args) -> bytes:
    # gather pairs from command line and file
    md = {}
    for kv in args.metadata:
        if "=" not in kv:
            raise ValueError(f"bad metadata pair '{kv}'")
        k, v = kv.split("=", 1)
        md[k] = v
    if args.metadata_file:
        with open(args.metadata_file, "r") as f:
            j = json.load(f)
        md.update(j)

    fields = _load_metadata_fields(args.metadata_schema)
    lines = []
    for k in fields:
        if k in md:
            lines.append(f"{k}={md[k]}")
    if lines:
        lines.append("")
    txt = "\n".join(lines)
    b = txt.encode("utf-8")
    if len(b) > 128:
        raise ValueError("metadata too long")
    return b


# helper for GUI/other callers ------------------------------------------------

from datetime import date


def default_output_name(md: dict, base: str = "card_image") -> str:
    """Return a reasonable default filename based on metadata and current date.

    The filename will always include the local date (YYYYMMDD).  If the metadata
    contains ``First`` or ``Last`` they are sanitized and prefixed (with
    "_card" suffix) before the date component.  This ensures sensible names
    while keeping them unique per day.
    """
    # build a base using names if available
    first = _sanitize_filename_component(md.get("First", "").strip())
    last = _sanitize_filename_component(md.get("Last", "").strip())
    if first or last:
        base = f"{first}_{last}_card"
    today = date.today().isoformat().replace("-", "")
    return f"{base}_{today}.bin"


def make_image(header: bytes,
               priv: bytes,
               pub: bytes,
               metadata: bytes,
               card_type: str,
               output: str,
               protect: bool = False) -> None:
    """Build card image and write it to ``output``.

    This encapsulates the core logic previously residing in ``main`` so that
    both the command‑line interface and a GUI front end can reuse it.
    """
    total_size = 256 if card_type == "sle4442" else 1024

    # use temporary directory to build file then move
    with tempfile.TemporaryDirectory() as td:
        temp_path = Path(td) / output
        img = bytearray(b"\x00" * total_size)
        img[0x000 : 0x000 + len(header)] = header
        # private key region (pad with zeroes)
        if len(priv) > 0x40:
            raise ValueError("private key file too large (max 64 bytes)")
        img[0x020 : 0x020 + len(priv)] = priv
        img[0x020 + len(priv) : 0x060] = b"\x00" * (0x60 - 0x20 - len(priv))
        img[0x060 : 0x060 + len(pub)] = pub
        img[0x060 + len(pub) : 0x080] = b"\x00" * (0x80 - 0x60 - len(pub))
        img[0x080 : 0x080 + len(metadata)] = metadata
        # rest already zero

        with open(temp_path, "wb") as f:
            f.write(img)
            os.fchmod(f.fileno(), 0o600)
        print(f"wrote image ({len(img)} bytes) to temporary {temp_path}")
        # move into place
        import shutil
        shutil.move(str(temp_path), output)
        os.chmod(output, 0o600)
        print(f"moved image to {output}")
    # end temporary directory

    if protect:
        # generate simple protection map locking header 0-0x1F
        pm = bytearray([0xFF] * ((total_size + 7) // 8))
        # clear bits 0..0x1f
        for a in range(0x20):
            pm[a // 8] &= ~(1 << (a % 8))
        pm_path = os.path.splitext(output)[0] + "_pm.bin"
        with open(pm_path, "wb") as f:
            f.write(pm)
            os.fchmod(f.fileno(), 0o600)
        print(f"wrote protection map ({len(pm)} bytes) to {pm_path}")


# constants matching card_crypto.py
SALT_LEN = 4            # bytes of salt stored alongside blob
NONCE_LEN = 12          # AESGCM nonce
PBKDF2_ITERS = 100_000


def _derive_key(password: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(password.encode())


def _encrypt_seed(seed: bytes, password: str) -> bytes:
    # format: salt||nonce||ciphertext(tag appended)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = os.urandom(SALT_LEN)
    key = _derive_key(password, salt)
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, seed, None)
    out = salt + nonce + ct
    if len(out) > 0x40:
        raise ValueError("encrypted seed too large to fit in 64 bytes")
    return out


def _normalize_private(data: bytes, password: str | None = None) -> bytes:
    """Return bytes suitable for storage in card region (<=64).

    If input is DER it will be converted to raw seed.  If a password is
    supplied the seed will be encrypted with the AEAD/PBKDF2 scheme above.
    """
    # try parse as DER
    try:
        key = serialization.load_der_private_key(data, password=None)
        seed = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    except Exception:
        # not DER, assume data already raw
        seed = data
    if password:
        encrypted = _encrypt_seed(seed, password)
        return encrypted
    else:
        if len(seed) > 0x40:
            raise ValueError("seed too large to fit in 64 bytes")
        return seed


def main() -> None:
    args = parse_args()

    # if GUI requested, try to import and run the front end
    if args.gui:
        try:
            import make_card_image_gui  # noqa: F401 - side effect of launching
        except ImportError as e:
            print("GUI dependencies not installed:", e, file=sys.stderr)
            sys.exit(1)
        return

    # interactive prompting if requested or if required args are missing
    if args.interactive or len(sys.argv) == 1:
        # blank dump
        while not args.blank:
            args.blank = input("blank card dump path: ").strip() or None
        # keys: either prompt for existing files or generate new
        if not args.priv or not args.pub:
            print("No key files specified; generating new Ed25519 key pair.")
            from cryptography.hazmat.primitives.asymmetric import ed25519
            privkey = ed25519.Ed25519PrivateKey.generate()
            pwd = getpass.getpass("password to encrypt private key (empty for none): ")
            if pwd == "":
                pwd = None
            seed = privkey.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            if pwd:
                priv_store = _encrypt_seed(seed, pwd)
            else:
                priv_store = seed
            pub_bytes = privkey.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            args.priv_bytes = priv_store
            args.pub_bytes = pub_bytes
            save = input("save generated keys to files? [y/N]: ")
            if save.lower().startswith("y"):
                ppath = input("private key filename [private.der]: ").strip() or "private.der"
                with open(ppath, "wb") as f:
                    f.write(priv_store)
                    os.fchmod(f.fileno(), 0o600)
                qpath = input("public key filename [public.raw]: ").strip() or "public.raw"
                with open(qpath, "wb") as f:
                    f.write(pub_bytes)
                    os.fchmod(f.fileno(), 0o644)
                print(f"keys written to {ppath} and {qpath}")
        else:
            raw = load_file(args.priv)
            # if user provided external private, may be raw or DER; let normalize
            pwd = None
            # not prompting; use none
            args.priv_bytes = _normalize_private(raw, pwd)
            args.pub_bytes = load_file(args.pub, expected=32)
        # metadata prompts
        if not args.metadata and not args.metadata_file:
            print("Enter metadata values (leave blank to skip):")
            fields = _load_metadata_fields(args.metadata_schema)
            for field in fields:
                val = input(f" {field}: ").strip()
                if val:
                    args.metadata.append(f"{field}={val}")
    else:
        # non-interactive path: read provided files
        if not args.blank or not args.priv or not args.pub:
            parser = argparse.ArgumentParser()
            parser.error("--blank, --priv and --pub are required unless --interactive is used")
        args.priv_bytes = load_file(args.priv)
        args.pub_bytes = load_file(args.pub, expected=32)
    # determine card parameters based on type
    total_size = 256 if args.type == "sle4442" else 1024

    # read header and other pieces
    header = read_header(args.blank)
    priv = args.priv_bytes
    pub = args.pub_bytes
    metadata = build_metadata(args)

    # reconstruct metadata dict for naming
    md = {}
    for kv in args.metadata:
        if "=" in kv:
            k, v = kv.split("=", 1)
            md[k] = v
    if args.metadata_file:
        with open(args.metadata_file, "r") as f:
            md.update(json.load(f))

    # decide output filename if not supplied
    if not args.output:
        args.output = default_output_name(md)

    # build the file and optionally protection map
    make_image(header, priv, pub, metadata, args.type, args.output, args.protect)


if __name__ == "__main__":
    main()
