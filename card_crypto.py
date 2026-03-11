#!/usr/bin/env python3
"""Utility for working with key material stored in the card image or directly on a physical
card via PC/SC.  For most subcommands you can either supply ``--card-image`` (a
256‑byte dump) or omit it to connect to the first available card reader.

Commands:
    extract-public   write the public key (PEM) from the image/card to a file
    dump-private     decrypt and dump the private key (PKCS8 DER or raw) to a file
    sign             sign an input file with the private key inside the image/card
    verify           verify a signature using a public key file
    encrypt          encrypt a file using an Ed25519 public key (sealed box)
    decrypt          decrypt a sealed box using the private key in the image/card

This tool uses ``cryptography`` to load and handle Ed25519 keys and
``PyNaCl``/``libsodium`` to perform sealed-box (public-key) encryption.  

The private key region is assumed to occupy bytes 0x20..0x5F of the image; the
public key is at 0x60..0x7F.  The private key bytes are interpreted as a DER
structure and may therefore be password-encrypted.  If you built the image
with ``make_card_image.py`` the encrypted DER produced by OpenSSL is simply
copied to that region.
"""

import argparse
import getpass
import os
import sys
from pathlib import Path
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# pcsc management for reading directly from a card
from core.pcsc_manager import PCSCManager
from core.atr_detector import ATRDetector, CardType
from drivers.sle4442 import SLE4442
from drivers.sle4428 import SLE4428
from drivers.sle5528 import SLE5528

# optional imports for encryption/decryption with sealed boxes

# home directory for the utility
PMCC_HOME = Path.home() / ".pmcc"
# create home directory with restrictive permissions
PMCC_HOME.mkdir(mode=0o700, exist_ok=True)

try:
    from nacl.public import SealedBox, PublicKey, PrivateKey
    from nacl.bindings import (
        crypto_sign_ed25519_pk_to_curve25519,
        crypto_sign_ed25519_sk_to_curve25519,
    )
except ImportError:
    SealedBox = None


PAGE_PRIV_START = 0x20
PAGE_PRIV_LEN = 0x40
PAGE_PUB_START = 0x60
PAGE_PUB_LEN = 0x20


def read_image(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise FileNotFoundError(f"cannot open image file '{path}': {e}")


def read_image_from_card(reader=None, manager: PCSCManager | None = None) -> bytes:
    """Read the 256/1024‑byte card image from a connected card.

    *reader* may be either a reader object (as returned by
    ``smartcard.System.readers()``) or a string matching ``str(r)``; it is
    passed through to ``PCSCManager.connect``.  If *manager* is provided it
    will be used and assumed to already have a connection open; otherwise a
    new ``PCSCManager`` is created internally.  The return value is the raw
    bytes read from the card.
    """
    mgr = manager if manager is not None else PCSCManager()
    # if we weren't given an already-open connection, connect now
    if mgr.conn is None:
        mgr.connect(reader=reader)
    atr = mgr.get_atr()
    ctype = ATRDetector.detect(atr, mgr.conn)
    driver_cls = {
        CardType.SLE4442: SLE4442,
        CardType.SLE5542: SLE4442,
        CardType.SLE4428: SLE4428,
        CardType.SLE5528: SLE5528,
    }.get(ctype)
    if not driver_cls:
        raise ValueError(f"unsupported card type {ctype}")
    card = driver_cls(conn=mgr.conn)
    data = card.read_all()
    if not data or len(data) not in (256, 1024):
        raise ValueError("card read returned unexpected length")
    img = bytes(data)
    # write a temporary copy for debugging; it will be cleaned up.  We can't
    # specify a mode to TemporaryDirectory (not supported by the stdlib), so
    # create it then fix perms if we care; the directory is ephemeral anyway.
    with tempfile.TemporaryDirectory() as td:
        os.chmod(td, 0o700)
        tmpf = Path(td) / "card_image.bin"
        tmpf.write_bytes(img)
        # leave directory immediately, file will be removed
    return img


def extract_public(img: bytes) -> bytes:
    return img[PAGE_PUB_START : PAGE_PUB_START + PAGE_PUB_LEN]


def extract_private_der(img: bytes) -> bytes:
    priv = img[PAGE_PRIV_START : PAGE_PRIV_START + PAGE_PRIV_LEN]
    # strip trailing zeros / 0xFF which may pad the DER
    return priv.rstrip(b"\x00").rstrip(b"\xFF")


# constants for the redesigned encrypted format
SALT_LEN = 4            # bytes of random salt stored with data
NONCE_LEN = 12          # AESGCM nonce
PBKDF2_ITERS = 100_000  # work factor: adjust based on your env


def _derive_key(password: bytes, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(password)


def _encrypt_seed(seed: bytes, password: bytes) -> bytes:
    # format: salt||nonce||ciphertext(tag appended)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = os.urandom(SALT_LEN)
    key = _derive_key(password, salt)
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, seed, None)
    out = salt + nonce + ct
    if len(out) > PAGE_PRIV_LEN:
        raise ValueError("encrypted seed too large to fit in card region")
    return out


def _decrypt_seed(data: bytes, password: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    # strip padding/ff that may have been added by image builder
    data = data.rstrip(b"\x00").rstrip(b"\xFF")
    if len(data) < SALT_LEN + NONCE_LEN + 1:
        raise ValueError("encrypted blob too short")
    salt = data[:SALT_LEN]
    nonce = data[SALT_LEN:SALT_LEN+NONCE_LEN]
    ct = data[SALT_LEN+NONCE_LEN:]
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def load_private(der_or_seed: bytes, password: bytes | None):
    """Return an Ed25519 private key object.

    The input may be:
    * a PKCS#8 DER blob (encrypted or not), or
    * a raw 32-byte seed, optionally encrypted with password using the
      AES-GCM/PBKDF2 scheme used by make_card_image.
    """
    # first try DER
    try:
        return serialization.load_der_private_key(der_or_seed, password=password)
    except (ValueError, TypeError):
        # not a DER private key
        pass
    # not DER; treat as raw or encrypted seed
    seed = der_or_seed
    if password:
        try:
            seed = _decrypt_seed(der_or_seed, password)
        except Exception as e:
            raise ValueError(f"failed to decrypt seed: {e}")
    # final length check
    if len(seed) != 32:
        raise ValueError("private seed has incorrect length")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(seed)


def _parse_metadata(img: bytes) -> dict:
    # metadata region is 0x080-0x0FF, simple key=value lines
    raw = img[0x080:0x080+128]
    try:
        txt = raw.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
    except Exception:
        return {}
    md = {}
    for line in txt.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            md[k] = v
    return md


def _parse_reader_arg(reader_str: str | None):
    """Return a reader object matching the given string.

    ``PCSCManager.list_readers`` is used to enumerate available readers; the
    first one whose ``str()`` matches *reader_str* is returned.  ``None`` is
    returned if *reader_str* is falsy.
    """
    if not reader_str:
        return None
    mgr = PCSCManager()
    for r in mgr.list_readers():
        if str(r) == reader_str or reader_str in str(r):
            return r
    raise ValueError(f"reader '{reader_str}' not found")



def cmd_extract_public(args):
    # always read from a connected card
    rdr = _parse_reader_arg(getattr(args, "reader", None))
    img = read_image_from_card(reader=rdr, manager=getattr(args, "manager", None))
    pub = extract_public(img)
    # compute output path based on metadata; ignore any provided value
    PMCC_HOME.mkdir(parents=True, exist_ok=True, mode=0o700)
    md = _parse_metadata(img)
    # construct name from first two non-empty metadata values (in order);
    # this works even if field names change via metadata_fields.json
    vals = [
        _sanitize_filename_component(v.strip())
        for v in md.values()
        if v and v.strip()
    ]
    if vals:
        name = "_".join(vals[:2]) + "_Pubkey.pem"
    else:
        name = "public.pem"
    args.output = str(PMCC_HOME / name)
    # dump as PEM
    keyobj = Ed25519PublicKey.from_public_bytes(pub)
    pem = keyobj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(args.output, "wb") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(pem)
    print(f"wrote public key PEM ({len(pem)} bytes) to {args.output}", file=sys.stderr)


def cmd_dump_private(args):
    # not accessible via CLI; kept for potential internal use
    rdr = _parse_reader_arg(getattr(args, "reader", None))
    img = read_image_from_card(reader=rdr, manager=getattr(args, "manager", None))
    der = extract_private_der(img)
    if not der:
        print("no private key data found", file=sys.stderr)
        sys.exit(1)
    pwd = args.password
    if pwd is None:
        pwd = getpass.getpass("password (if any): ")
        if pwd == "":
            pwd = None
        else:
            pwd = pwd.encode()
    else:
        pwd = pwd.encode()
    try:
        priv = load_private(der, pwd)
    except ValueError as e:
        print(f"failed to load private key: {e}", file=sys.stderr)
        sys.exit(1)
    # default output
    if not args.output:
        PMCC_HOME.mkdir(parents=True, exist_ok=True, mode=0o700)
        fname = "private.pem" if args.pem else ("private_raw.bin" if args.raw else "private.der")
        args.output = str(PMCC_HOME / fname)
    if args.raw:
        # dump raw seed
        seed = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        if args.output == "-":
            sys.stdout.buffer.write(seed)
        else:
            with open(args.output, "wb") as f:
                os.fchmod(f.fileno(), 0o600)
                f.write(seed)
        print(f"wrote raw private seed ({len(seed)} bytes) to {args.output}", file=sys.stderr)
    elif args.pem:
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        if args.output == "-":
            sys.stdout.buffer.write(pem)
        else:
            with open(args.output, "wb") as f:
                os.fchmod(f.fileno(), 0o600)
                f.write(pem)
        print(f"wrote PEM private key ({len(pem)} bytes) to {args.output}", file=sys.stderr)
    else:
        if args.output == "-":
            sys.stdout.buffer.write(der)
        else:
            with open(args.output, "wb") as f:
                os.fchmod(f.fileno(), 0o600)
                f.write(der)
        print(f"wrote DER private key ({len(der)} bytes) to {args.output}", file=sys.stderr)


def cmd_sign(args):
    rdr = _parse_reader_arg(getattr(args, "reader", None))
    img = read_image_from_card(reader=rdr, manager=getattr(args, "manager", None))
    der = extract_private_der(img)
    if not der:
        print("no private key data found", file=sys.stderr)
        sys.exit(1)
    pwd = args.password
    if pwd is None:
        pwd = getpass.getpass("password (if any): ")
        if pwd == "":
            pwd = None
        else:
            pwd = pwd.encode()
    else:
        pwd = pwd.encode()
    try:
        priv = load_private(der, pwd)
    except ValueError as e:
        print(f"failed to load private key: {e}", file=sys.stderr)
        sys.exit(1)
    data = open(args.input, "rb").read()
    sig = priv.sign(data)
    # PEM-armored signature
    import base64
    arm = []
    arm.append("-----BEGIN ED25519 SIGNATURE-----")
    arm.append(base64.b64encode(sig).decode())
    arm.append("-----END ED25519 SIGNATURE-----")
    arm_text = "\n".join(arm) + "\n"

    if not args.output:
        inp = Path(args.input)
        args.output = str(inp.parent / (inp.name + ".sig"))
    if args.output == "-":
        sys.stdout.write(arm_text)
    else:
        with open(args.output, "w") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(arm_text)
    print(f"signature ({len(sig)} bytes) written to {args.output}", file=sys.stderr)


def cmd_verify(args):
    pub = open(args.pubkey, "rb").read()
    from cryptography.hazmat.primitives.serialization import (
        load_pem_public_key,
        load_der_public_key,
    )
    pk = None
    if len(pub) == 32:
        pk = Ed25519PublicKey.from_public_bytes(pub)
    else:
        # try PEM/DER
        try:
            keyobj = load_pem_public_key(pub)
        except Exception:
            try:
                keyobj = load_der_public_key(pub)
            except Exception:
                keyobj = None
        if keyobj is not None:
            pk = keyobj
    if pk is None:
        print("unable to parse public key", file=sys.stderr)
        sys.exit(1)
    data = open(args.input, "rb").read()
    raw = open(args.sig, "rb").read()
    # detect PEM armor
    sig = raw
    if raw.startswith(b"-----BEGIN ED25519 SIGNATURE-----"):
        import base64, re
        # strip header/footer and whitespace
        b64 = re.sub(b"-----.*?-----", b"", raw, flags=re.S).strip()
        sig = base64.b64decode(b64)
    try:
        pk.verify(sig, data)
        print("signature OK")
    except Exception as e:
        # diagnostics to help determine why a supposedly-valid signature
        # failed (length mismatch, corrupted file, wrong key, etc.)
        msg = str(e)
        if msg:
            print(f"verification failed: {msg}")
        else:
            # cryptography sometimes raises InvalidSignature with no text
            print("verification failed: signature did not verify")
        # also show lengths so callers can spot common problems
        try:
            print(f"pub len={len(pub)} data len={len(data)} sig len={len(sig)}")
        except Exception:
            pass
        sys.exit(1)


def cmd_encrypt(args):
    if SealedBox is None:
        print("PyNaCl required for encryption/decryption", file=sys.stderr)
        sys.exit(1)
    pub = None
    img = None

    # if user gave explicit file use it (try local then ~/.pmcc)
    if args.pubkey:
        path = Path(args.pubkey)
        if not path.exists():
            alt = PMCC_HOME / args.pubkey
            if alt.exists():
                path = alt
        if not path.exists():
            raise FileNotFoundError(f"public key '{args.pubkey}' not found")
        pub = path.read_bytes()
    else:
        # try to find a saved public key in ~/.pmcc
        candidates = [PMCC_HOME / "public.pem"]
        candidates.extend(sorted(PMCC_HOME.glob("*_Pubkey.pem")))
        existing = [c for c in candidates if c.exists()]

        # if there are any saved keys, attempt to pick one
        if existing:
            # read metadata once if needed
            try:
                rdr = _parse_reader_arg(getattr(args, "reader", None))
                img = read_image_from_card(reader=rdr, manager=getattr(args, "manager", None))
                md = _parse_metadata(img)
                # adapt same generic naming used in extract-public
                vals = [
                    _sanitize_filename_component(v.strip())
                    for v in md.values()
                    if v and v.strip()
                ]
                if vals:
                    target = "_".join(vals[:2]) + "_Pubkey.pem"
                    # try to locate a matching saved key
                    for c in existing:
                        if c.name == target:
                            pub = c.read_bytes()
                            break
                    if pub is None:
                        # found saved keys but none matched metadata
                        print(
                            "warning: no saved public key matches card metadata; using card directly",
                            file=sys.stderr,
                        )
                else:
                    # no metadata, just pick first
                    pub = existing[0].read_bytes()
            except Exception:
                # could not read card, fallback to first candidate
                pub = existing[0].read_bytes()
        if pub is None:
            # no files available or mismatch forced using card
            if img is None:
                rdr = _parse_reader_arg(getattr(args, "reader", None))
                img = read_image_from_card(reader=rdr, manager=getattr(args, "manager", None))
            pub = extract_public(img)

    # ensure pub is raw 32 bytes; try to parse PEM/DER if not
    from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_der_public_key
    rawpub = pub
    if len(pub) not in (32,):
        try:
            keyobj = load_pem_public_key(pub)
        except Exception:
            try:
                keyobj = load_der_public_key(pub)
            except Exception:
                keyobj = None
        if keyobj is not None:
            try:
                rawpub = keyobj.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            except Exception:
                rawpub = pub
    if len(rawpub) != 32:
        raise ValueError("public key is not 32 bytes or valid Ed25519 key")
    try:
        curve_pub = crypto_sign_ed25519_pk_to_curve25519(rawpub)
    except Exception as e:
        raise ValueError(f"invalid Ed25519 public key: {e}")
    box = SealedBox(PublicKey(curve_pub))
    data = open(args.input, "rb").read()
    cipher = box.encrypt(data)
    # prepare ascii-armored output with filename header
    basename = os.path.basename(args.input)
    import base64
    arm = []
    arm.append("-----BEGIN PMCC ENCRYPTED-----")
    arm.append(f"Filename: {basename}")
    arm.append("")
    arm.append(base64.b64encode(cipher).decode())
    arm.append("-----END PMCC ENCRYPTED-----")
    arm_text = "\n".join(arm) + "\n"
    if not args.output:
        # encrypted payloads go in current directory by default
        args.output = "encrypted.txt"
    if args.output == "-":
        sys.stdout.write(arm_text)
    else:
        with open(args.output, "w") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(arm_text)
    print(f"encrypted {len(data)} bytes to {args.output} (ascii armored)", file=sys.stderr)


def cmd_decrypt(args):
    if SealedBox is None:
        print("PyNaCl required for encryption/decryption", file=sys.stderr)
        sys.exit(1)
    rdr = _parse_reader_arg(getattr(args, "reader", None))
    img = read_image_from_card(reader=rdr, manager=getattr(args, "manager", None))
    der = extract_private_der(img)
    if not der:
        print("no private key data found", file=sys.stderr)
        sys.exit(1)
    pwd = args.password
    if pwd is None:
        pwd = getpass.getpass("password (if any): ")
        if pwd == "":
            pwd = None
        else:
            pwd = pwd.encode()
    else:
        pwd = pwd.encode()
    try:
        priv = load_private(der, pwd)
    except ValueError as e:
        print(f"failed to load private key: {e}", file=sys.stderr)
        sys.exit(1)
    # convert to 64-byte secret for curve25519 conversion
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sk64 = seed + pub
    curve_priv = crypto_sign_ed25519_sk_to_curve25519(sk64)
    box = SealedBox(PrivateKey(curve_priv))
    import base64
    if args.input == "-":
        raw = sys.stdin.buffer.read()
    else:
        raw = open(args.input, "rb").read()
    # detect armor
    text = None
    try:
        text = raw.decode('utf-8')
    except Exception:
        text = None
    if text and text.startswith("-----BEGIN PMCC ENCRYPTED-----"):
        lines = text.strip().splitlines()
        fname = None
        b64chars = []
        for ln in lines:
            if ln.startswith("Filename:"):
                fname = ln.split(":",1)[1].strip()
            elif ln and not ln.startswith("-----"):
                # keep base64 characters only
                b64chars.append(ln.strip())
        b64s = "".join(b64chars)
        # pad to multiple of 4
        if len(b64s) % 4:
            b64s += "=" * (4 - (len(b64s) % 4))
        cipher = base64.b64decode(b64s)
        if fname and not args.output:
            # avoid directory traversal and illegal characters
            fname = os.path.basename(fname)
            fname = _sanitize_filename_component(fname)
            PMCC_HOME.mkdir(parents=True, exist_ok=True, mode=0o700)
            args.output = str(PMCC_HOME / fname)
    else:
        cipher = raw
    try:
        pt = box.decrypt(cipher)
    except Exception as e:
        print(f"decryption failed: {e}", file=sys.stderr)
        sys.exit(1)
    if not args.output:
        PMCC_HOME.mkdir(parents=True, exist_ok=True, mode=0o700)
        args.output = str(PMCC_HOME / "decrypted.bin")
    if args.output == "-":
        sys.stdout.buffer.write(pt)
    else:
        with open(args.output, "wb") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(pt)
    print(f"decrypted to {args.output} ({len(pt)} bytes)", file=sys.stderr)


def _sanitize_filename_component(s: str) -> str:
    # allow only a conservative set of characters in automatically generated
    # filenames to prevent path traversal and shell surprises.
    import re
    return re.sub(r"[^A-Za-z0-9_-]", "_", s)


def main():
    parser = argparse.ArgumentParser(description="Card crypto helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract-public")
    p.add_argument("--reader", help="PC/SC reader to use when communicating with a card")
    p.add_argument("--pem", action="store_true", help="return PEM (default)")
    p.set_defaults(func=cmd_extract_public)

    # the dump-private command has been removed by policy; private key
    # extraction is no longer supported via this tool.
    # p = sub.add_parser("dump-private")
    # ... (not registered)

    p = sub.add_parser("sign")
    p.add_argument("--reader", help="PC/SC reader to use when communicating with a card")
    p.add_argument("--input", required=True)
    p.add_argument("-o","--output", help="output filename (default: <input>.sig in same directory; '-'=stdout). signature will be PEM-armored")
    p.add_argument("--password", help="key password (prompt if omitted)")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify")
    p.add_argument("--pubkey", required=True)
    p.add_argument("--input", required=True)
    p.add_argument("--sig", required=True)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("encrypt")
    p.add_argument("--pubkey", help="public key file (PEM/DER). omit to read from card")
    p.add_argument("--reader", help="PC/SC reader to use when communicating with a card (when pubkey omitted)")
    p.add_argument("--input", required=True)
    p.add_argument("-o","--output", help="output filename (default: ./encrypted.txt; '-'=stdout)")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt")
    p.add_argument("--reader", help="PC/SC reader to use when communicating with a card")
    p.add_argument("--input", required=True)
    p.add_argument("-o","--output", help="output filename (default: ~/.pmcc/decrypted.bin; '-'=stdout)")
    p.add_argument("--password", help="key password (prompt if omitted)")
    p.set_defaults(func=cmd_decrypt)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
