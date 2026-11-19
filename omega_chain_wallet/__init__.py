"""Operator-owned F1R3node signing keys. The Hive view reads public metadata."""
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
import unicodedata

from coincurve import PrivateKey, PublicKey
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class WalletError(ValueError):
    """A message safe to pass to the caller."""


class WalletChanged(WalletError):
    """The caller viewed an older wallet snapshot."""


def wallet_revision(entries):
    return hashlib.sha256(json.dumps(entries, separators=(",", ":")).encode("ascii")).hexdigest()


@dataclass(frozen=True)
class SignerPage:
    entries: list[tuple[str, str]]
    count: int
    number: int
    pages: int
    revision: str


def _name(value):
    if not isinstance(value, str) or len(value) > 80 or any(
        unicodedata.category(char) in {"Cc", "Cs", "Zl", "Zp"} for char in value
    ):
        raise WalletError("Use a single-line name of up to 80 characters without control characters.")
    if re.search(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])", value):
        raise WalletError("Choose a display name without private key material.")
    return value.strip()


DOMAIN = b"omega-chain-wallet/v1/"
KEY_NAME = re.compile(r"(04[0-9a-f]{128})\.owk")


def _check_access(info, expected_type):
    if (not expected_type(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        raise WalletError("Wallet storage must belong to the service account and allow owner access only.")


@contextmanager
def _directory(path, *, create=False):
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _check_access(os.fstat(fd), stat.S_ISDIR)
        yield fd
    finally:
        os.close(fd)


def _read(directory, name, size, *, exact=True):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        _check_access(os.fstat(fd), stat.S_ISREG)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(size + 1)
    finally:
        os.close(fd)
    if len(data) > size or (exact and len(data) != size):
        raise WalletError("Wallet file has an invalid size.")
    return data


def _publish(directory, name, data, *, replace=False):
    """Publish a complete file atomically. Only mutable metadata may be replaced."""
    tmp = "." + secrets.token_hex(16) + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(fd, 0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(tmp, name, src_dir_fd=directory, dst_dir_fd=directory)
            return True
        try:
            os.link(tmp, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        except FileExistsError:
            return False
        return True
    finally:
        try:
            os.unlink(tmp, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.fsync(directory)


def _read_name(vault, public):
    # A name is optional display metadata. Keep the same ownership and no-follow checks
    # as other wallet files, but let the operator replace an unreadable name via Rename.
    try:
        return _name(_read(vault, public + ".name", 320, exact=False).decode("utf-8"))
    except (OSError, UnicodeError, WalletError):
        return ""


def _exists(vault, filename):
    try:
        os.stat(filename, dir_fd=vault, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _lock(vault, mode, *, bounded):
    if not bounded:
        fcntl.flock(vault, mode)
        return
    deadline = time.monotonic() + 0.5
    while True:
        try:
            fcntl.flock(vault, mode | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise WalletError("The wallet is busy. Try again.") from None
            time.sleep(0.01)


def _public_bytes(value):
    if isinstance(value, str) and re.fullmatch(r"04[0-9a-fA-F]{128}", value):
        encoded = bytes.fromhex(value)
        try:
            PublicKey(encoded)
            return encoded
        except ValueError:
            pass
    raise WalletError("Expected an uncompressed secp256k1 public key.")


def _binding(master):
    return hmac.digest(master, DOMAIN + b"keyring", "sha256")


class Wallet:
    def __init__(self, vault, config):
        self.vault = Path(vault).expanduser().absolute()
        self.config = Path(config).expanduser().absolute()
        config_root = self.config.resolve()
        vault_root = self.vault.resolve()
        if config_root.is_relative_to(vault_root) or vault_root.is_relative_to(config_root):
            raise WalletError("Use separate directories for the encrypted records and the wrapping key.")

    @classmethod
    def from_env(cls):
        data = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
        config = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        return cls(os.environ.get("OMEGA_CHAIN_WALLET_DIR") or data / "omega-chain-wallet",
                   os.environ.get("OMEGA_CHAIN_WALLET_CONFIG_DIR") or config / "omega-chain-wallet")

    def initialize(self):
        with _directory(self.vault, create=True) as vault:
            fcntl.flock(vault, fcntl.LOCK_EX)
            existing = os.listdir(vault)
            with _directory(self.config, create=True) as config:
                try:
                    master = _read(config, "wrapping.key", 32)
                except FileNotFoundError:
                    if "wallet.id" in existing or any(k.endswith(".owk") for k in existing):
                        raise WalletError("Restore the original wrapping key for this wallet.") from None
                    _publish(config, "wrapping.key", secrets.token_bytes(32))
                    master = _read(config, "wrapping.key", 32)
            if "wallet.id" not in existing:
                if any(k.endswith(".owk") for k in existing):
                    raise WalletError("Restore the wallet identity file from backup.")
                _publish(vault, "wallet.id", _binding(master))
            self._check_binding(vault, master)

    @staticmethod
    def _check_binding(vault, master):
        if not hmac.compare_digest(_read(vault, "wallet.id", 32), _binding(master)):
            raise WalletError("The wrapping key does not match this wallet.")

    def _master(self, vault):
        try:
            with _directory(self.config) as config:
                master = _read(config, "wrapping.key", 32)
            self._check_binding(vault, master)
        except FileNotFoundError:
            raise WalletError("Wallet configuration is missing. Initialize a new wallet or restore its backup.") from None
        return master

    @staticmethod
    def _keys(vault):
        return sorted(_public_bytes(match[1]).hex() for name in os.listdir(vault)
                      if (match := KEY_NAME.fullmatch(name)))

    @staticmethod
    def _catalog(vault):
        # All wallet name writes replace the inode. ctime also detects in-place edits
        # and permission changes on restore. Only the visible page opens label files.
        keys = []
        names = {}
        with os.scandir(vault) as files:
            for entry in files:
                match = KEY_NAME.fullmatch(entry.name)
                if match:
                    keys.append(_public_bytes(match[1]).hex())
                elif entry.name.endswith(".name"):
                    try:
                        info = entry.stat(follow_symlinks=False)
                        stamp = (info.st_ino, info.st_ctime_ns, info.st_mtime_ns, info.st_size)
                    except OSError:
                        stamp = "unreadable"
                    names[entry.name[:-5]] = stamp
        keys.sort()
        stamps = [(key, names.get(key)) for key in keys]
        return keys, names, wallet_revision(stamps)

    def public_keys(self):
        try:
            with _directory(self.vault) as vault:
                return self._keys(vault)
        except FileNotFoundError:
            return []

    def signer_page(self, number=1, *, size=32, focus=None):
        try:
            with _directory(self.vault) as vault:
                _lock(vault, fcntl.LOCK_SH, bounded=True)
                keys, names, revision = self._catalog(vault)
                count = len(keys)
                size = max(1, count) if size is None else size
                if size < 1:
                    raise ValueError("Page size must be positive.")
                pages = max(1, (count + size - 1) // size)
                number = max(1, min(number, pages))
                if focus and focus in keys:
                    number = keys.index(focus) // size + 1
                entries = [(key, _read_name(vault, key) if key in names else "")
                           for key in keys[(number - 1) * size:number * size]]
                return SignerPage(entries, count, number, pages, revision)
        except FileNotFoundError:
            return SignerPage([], 0, 1, 1, wallet_revision([]))

    def entries(self):
        return self.signer_page(size=None).entries

    @contextmanager
    def _edit(self, revision):
        try:
            with _directory(self.vault) as vault:
                _lock(vault, fcntl.LOCK_EX, bounded=revision is not None)
                if revision is not None and self._catalog(vault)[2] != revision:
                    raise WalletChanged("The wallet changed. Refresh and try again.")
                yield vault
        except FileNotFoundError:
            raise WalletError("Initialize the wallet before editing signers.") from None

    def rename(self, public, name, *, revision=None):
        public = _public_bytes(public).hex()
        name = _name(name)
        with self._edit(revision) as vault:
            if not _exists(vault, public + ".owk"):
                raise WalletError("The selected signer is absent from the wallet.")
            _publish(vault, public + ".name", name.encode("utf-8"), replace=True)
        return public

    @staticmethod
    def _unlock(vault, master, public):
        try:
            record = _read(vault, public.hex() + ".owk", 12 + 32 + 16)
        except FileNotFoundError:
            raise WalletError("The selected public key is absent from the wallet.") from None
        try:
            secret = AESGCM(master).decrypt(record[:12], record[12:], DOMAIN + public)
            key = PrivateKey(secret)
        except (InvalidTag, ValueError):
            raise WalletError("Signing key record failed authentication.") from None
        if key.public_key.format(compressed=False) != public:
            raise WalletError("Signing key record does not match its public key.")
        return key

    def _store(self, key, name, revision):
        public = key.public_key.format(compressed=False)
        filename = public.hex() + ".owk"
        name = _name(name)
        with self._edit(revision) as vault:
            master = self._master(vault)
            outcome = "imported"
            if _exists(vault, filename):
                self._unlock(vault, master, public)
                outcome = "present"
                if name and name != _read_name(vault, public.hex()):
                    _publish(vault, public.hex() + ".name", name.encode("utf-8"), replace=True)
                    outcome = "renamed"
            else:
                nonce = secrets.token_bytes(12)
                record = nonce + AESGCM(master).encrypt(nonce, key.secret, DOMAIN + public)
                # Publish the name first. Readers only discover keys with a complete record.
                sidecar = public.hex() + ".name"
                if name or _exists(vault, sidecar):
                    _publish(vault, sidecar, name.encode("utf-8"), replace=True)
                if not _publish(vault, filename, record):
                    self._unlock(vault, master, public)
                    outcome = "renamed" if name else "present"
        return public.hex(), outcome

    def generate(self, name="", *, revision=None):
        return self._store(PrivateKey(), name, revision)[0]

    def import_secret(self, secret, name="", *, revision=None):
        return self.import_signer(secret, name, revision=revision)[0]

    def import_signer(self, secret, name="", *, revision=None):
        """Return the public key and whether the import added, found, or renamed it."""
        if not isinstance(secret, bytes) or len(secret) != 32:
            raise WalletError("Expected a 32-byte secp256k1 private key.")
        try:
            key = PrivateKey(secret)
        except ValueError:
            raise WalletError("Invalid secp256k1 private key.") from None
        return self._store(key, name, revision)

    def sign_digest(self, public_key, digest):
        """Host-only DER signature over an already hashed F1R3node deploy."""
        if not isinstance(digest, bytes) or len(digest) != 32:
            raise WalletError("Expected a 32-byte deploy digest.")
        public = _public_bytes(public_key)
        with _directory(self.vault) as vault:
            key = self._unlock(vault, self._master(vault), public)
        return key.sign(digest, hasher=None)
