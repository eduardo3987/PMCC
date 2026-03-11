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
PMCC_HOME.mkdir(exist_ok=True)

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
    return open(path, "rb").read()


def read_image_from_card() -> bytes:
    mgr = PCSCManager()
    mgr.connect()
    atr = mgr.get_atr()
    ctype = ATRDetector.detect(atr, mgr.conn)
    driver_cls = {
        CardType.SLE4442: SLE4442,
        CardType.SLE5542: SLE4442,
        CardType.SLE4428: SLE4428,
        CardType.SLE5528: SLE5528,
    }.get(ctype)
    if not driver_cls:
        raise Exception(f"unsupported card type {ctype}")
    card = driver_cls(conn=mgr.conn)
    data = card.read_all()
    img = bytes(data)
    # write a temporary copy for debugging; it will be cleaned up
    with tempfile.TemporaryDirectory() as td:
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


def _decrypt_seed(data: bytes, password: bytes) -> bytes:
    # same scheme as make_card_image: key=SHA256(password), iv=first16
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    iv = data[:16]
    ct = data[16:]
    key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    key.update(password)
    key_bytes = key.finalize()
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    seed = unpadder.update(padded) + unpadder.finalize()
    return seed


def load_private(der_or_seed: bytes, password: bytes | None):
    """Return an Ed25519 private key object.

    The input may be:
    * a PKCS#8 DER blob (encrypted or not), or
    * a raw 32-byte seed, optionally encrypted with password using the
      simple AES-CBC scheme used by make_card_image.
    """
    # first try DER
    try:
        return serialization.load_der_private_key(der_or_seed, password=password)
    except Exception:
        pass
    # not DER; treat as raw or encrypted seed
    if password:
        try:
            seed = _decrypt_seed(der_or_seed, password)
        except Exception as e:
            # if padding invalid, assume data was not encrypted and use raw
            msg = str(e).lower()
            if "padding" in msg:
                seed = der_or_seed
            else:
                raise ValueError(f"failed to decrypt seed: {e}")
    else:
        seed = der_or_seed
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


def cmd_extract_public(args):
    if args.card_image:
        img = read_image(args.card_image)
    else:
        img = read_image_from_card()
    pub = extract_public(img)
    # apply default output using metadata
    if not args.output:
        PMCC_HOME.mkdir(parents=True, exist_ok=True)
        md = _parse_metadata(img)
        first = md.get("First", "").strip().replace(" ", "_")
        last = md.get("Last", "").strip().replace(" ", "_")
        if first or last:
            name = f"{first}_{last}_Pubkey.pem"
        else:
            name = "public.pem"
        args.output = str(PMCC_HOME / name)
    # dump as PEM
    keyobj = Ed25519PublicKey.from_public_bytes(pub)
    pem = keyobj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    open(args.output, "wb").write(pem)
    print(f"wrote public key PEM ({len(pem)} bytes) to {args.output}", file=sys.stderr)


def cmd_dump_private(args):
    if args.card_image:
        img = read_image(args.card_image)
    else:
        img = read_image_from_card()
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
        PMCC_HOME.mkdir(parents=True, exist_ok=True)
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
            open(args.output, "wb").write(seed)
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
            open(args.output, "wb").write(pem)
        print(f"wrote PEM private key ({len(pem)} bytes) to {args.output}", file=sys.stderr)
    else:
        if args.output == "-":
            sys.stdout.buffer.write(der)
        else:
            open(args.output, "wb").write(der)
        print(f"wrote DER private key ({len(der)} bytes) to {args.output}", file=sys.stderr)


def cmd_sign(args):
    if args.card_image:
        img = read_image(args.card_image)
    else:
        img = read_image_from_card()
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
    if not args.output:
        PMCC_HOME.mkdir(parents=True, exist_ok=True)
        args.output = str(PMCC_HOME / "signature.sig")
    if args.output == "-":
        sys.stdout.buffer.write(sig)
    else:
        open(args.output, "wb").write(sig)
    print(f"signature ({len(sig)} bytes) written to {args.output}", file=sys.stderr)


def cmd_verify(args):
    pub = open(args.pubkey, "rb").read()
    pk = Ed25519PublicKey.from_public_bytes(pub)
    data = open(args.input, "rb").read()
    sig = open(args.sig, "rb").read()
    try:
        pk.verify(sig, data)
        print("signature OK")
    except Exception as e:
        print(f"verification failed: {e}")
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
                img = read_image_from_card()
                md = _parse_metadata(img)
                first = md.get("First", "").strip().replace(" ", "_")
                last = md.get("Last", "").strip().replace(" ", "_")
                if first or last:
                    target = f"{first}_{last}_Pubkey.pem"
                    for c in existing:
                        if c.name == target:
                            pub = c.read_bytes()
                            break
                    if pub is None:
                        # found saved keys but none matched metadata
                        print(
                            f"warning: no saved public key matches card metadata {first} {last}; using card directly",
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
                img = read_image_from_card()
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
            f.write(arm_text)
    print(f"encrypted {len(data)} bytes to {args.output} (ascii armored)", file=sys.stderr)


def cmd_decrypt(args):
    if SealedBox is None:
        print("PyNaCl required for encryption/decryption", file=sys.stderr)
        sys.exit(1)
    if args.card_image:
        img = read_image(args.card_image)
    else:
        img = read_image_from_card()
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
            PMCC_HOME.mkdir(parents=True, exist_ok=True)
            args.output = str(PMCC_HOME / fname)
    else:
        cipher = raw
    try:
        pt = box.decrypt(cipher)
    except Exception as e:
        print(f"decryption failed: {e}", file=sys.stderr)
        sys.exit(1)
    if not args.output:
        PMCC_HOME.mkdir(parents=True, exist_ok=True)
        args.output = str(PMCC_HOME / "decrypted.bin")
    if args.output == "-":
        sys.stdout.buffer.write(pt)
    else:
        open(args.output, "wb").write(pt)
    print(f"decrypted to {args.output} ({len(pt)} bytes)", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Card crypto helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract-public")
    p.add_argument("--card-image", help="path to card image file (omit to read from PC/SC)")
    p.add_argument("-o","--output", help="output filename (default: ~/.pmcc/public.pem; use '-' for stdout)")
    p.add_argument("--pem", action="store_true", help="return PEM (default)")
    p.set_defaults(func=cmd_extract_public)

    p = sub.add_parser("dump-private")
    p.add_argument("--card-image", help="path to card image file (omit to read from PC/SC)")
    p.add_argument("-o","--output", help="output filename (default: ~/.pmcc/private.pem or .der; '-'=stdout)")
    p.add_argument("--password", help="key password (prompt if omitted)")
    p.add_argument("--raw", action="store_true", help="output raw seed instead of DER")
    p.add_argument("--pem", action="store_true", help="output PEM-formatted PKCS8 key instead of DER")
    p.set_defaults(func=cmd_dump_private)

    p = sub.add_parser("sign")
    p.add_argument("--card-image", help="path to card image file (omit to read from PC/SC)")
    p.add_argument("--input", required=True)
    p.add_argument("-o","--output", help="output filename (default: ~/.pmcc/signature.sig; '-'=stdout)")
    p.add_argument("--password", help="key password (prompt if omitted)")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify")
    p.add_argument("--pubkey", required=True)
    p.add_argument("--input", required=True)
    p.add_argument("--sig", required=True)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("encrypt")
    p.add_argument("--pubkey", help="public key file (PEM/DER). omit to read from card")
    p.add_argument("--input", required=True)
    p.add_argument("-o","--output", help="output filename (default: ./encrypted.txt; '-'=stdout)")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt")
    p.add_argument("--card-image", help="path to card image file (omit to read from PC/SC)")
    p.add_argument("--input", required=True)
    p.add_argument("-o","--output", help="output filename (default: ~/.pmcc/decrypted.bin; '-'=stdout)")
    p.add_argument("--password", help="key password (prompt if omitted)")
    p.set_defaults(func=cmd_decrypt)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
