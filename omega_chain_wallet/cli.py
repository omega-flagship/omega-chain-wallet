"""Local operator interface. Successful key operations print only public keys."""
import argparse
import getpass
from pathlib import Path
import re
import sys
import warnings

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import Wallet, WalletError


def _prompt(label):
    # getpass normally warns and falls back to echoed stdin when it lacks a TTY.
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass(label)
    except (EOFError, getpass.GetPassWarning):
        raise WalletError("A terminal with hidden input is required.") from None


def _import_pem(wallet, path):
    with path.open("rb") as stream:
        pem = stream.read(16_385)
    if len(pem) > 16_384 or not pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"):
        raise WalletError("Expected a F1R3node encrypted PKCS#8 key file.")
    password = _prompt("Key file passphrase: ").encode("utf-8")
    try:
        key = serialization.load_pem_private_key(pem, password=password)
    except (TypeError, ValueError, UnsupportedAlgorithm):
        raise WalletError("Could not unlock the encrypted key file.") from None
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256K1):
        raise WalletError("F1R3node signing requires a secp256k1 key.")
    return wallet.import_secret(key.private_numbers().private_value.to_bytes(32, "big"))


def _import_hex(wallet, use_stdin):
    if use_stdin:
        if sys.stdin.isatty():
            raise WalletError("Redirect a key file to stdin or use the hidden prompt.")
        raw = sys.stdin.buffer.read(129)
        if len(raw) > 128:
            raise WalletError("Expected one 64-digit hexadecimal private key.")
        value = raw.strip().decode("ascii", errors="replace")
    else:
        value = _prompt("Hex signing key: ").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise WalletError("Expected one 64-digit hexadecimal private key.")
    return wallet.import_secret(bytes.fromhex(value))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="omega-chain-wallet", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="initialize host storage")
    commands.add_parser("generate", help="generate a signing key in the wallet")
    commands.add_parser("list", help="print public keys")
    commands.add_parser("import-pem", help="import an encrypted F1R3node key file").add_argument("path", type=Path)
    commands.add_parser("import-hex", help="import a 32-byte hex key").add_argument(
        "--stdin", action="store_true", help="read from redirected standard input")
    args = parser.parse_args(argv)
    try:
        wallet = Wallet.from_env()
        if args.command == "init":
            wallet.initialize()
        elif args.command == "generate":
            print(wallet.generate())
        elif args.command == "list":
            for public in wallet.public_keys():
                print(public)
        elif args.command == "import-pem":
            print(_import_pem(wallet, args.path))
        else:
            print(_import_hex(wallet, args.stdin))
    except WalletError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except OSError:
        print("Could not access a wallet file. Check the configured paths and permissions.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
