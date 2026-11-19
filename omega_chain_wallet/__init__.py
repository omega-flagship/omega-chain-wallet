"""Operator-owned F1R3node signing keys. The Hive view uses only public_keys()."""
from contextlib import contextmanager
import fcntl
import hmac
import os
from pathlib import Path
import re
import secrets
import stat

from coincurve import PrivateKey, PublicKey
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class WalletError(ValueError):
    """A message safe to pass to the caller."""


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


def _read(directory, name, size):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        _check_access(os.fstat(fd), stat.S_ISREG)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(size + 1)
    finally:
        os.close(fd)
    if len(data) != size:
        raise WalletError("Wallet file has an invalid size.")
    return data


def _publish(directory, name, data):
    """Publish a complete immutable file. A concurrent initializer may win."""
    tmp = "." + secrets.token_hex(16) + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(fd, 0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(tmp, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        except FileExistsError:
            return False
        return True
    finally:
        os.unlink(tmp, dir_fd=directory)
        os.fsync(directory)


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

    def public_keys(self):
        # The Hive app only enumerates record names. Neither secret file is opened.
        try:
            with _directory(self.vault) as vault:
                names = os.listdir(vault)
        except FileNotFoundError:
            return []
        return sorted(_public_bytes(match[1]).hex() for name in names if (match := KEY_NAME.fullmatch(name)))

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

    def _store(self, key):
        public = key.public_key.format(compressed=False)
        try:
            with _directory(self.vault) as vault:
                master = self._master(vault)
                nonce = secrets.token_bytes(12)
                record = nonce + AESGCM(master).encrypt(nonce, key.secret, DOMAIN + public)
                if not _publish(vault, public.hex() + ".owk", record):
                    # A duplicate import is successful only if the existing key is usable.
                    self._unlock(vault, master, public)
        except FileNotFoundError:
            raise WalletError("Initialize the wallet before storing keys.") from None
        return public.hex()

    def generate(self):
        return self._store(PrivateKey())

    def import_secret(self, secret):
        if not isinstance(secret, bytes) or len(secret) != 32:
            raise WalletError("Expected a 32-byte secp256k1 private key.")
        try:
            key = PrivateKey(secret)
        except ValueError:
            raise WalletError("Invalid secp256k1 private key.") from None
        return self._store(key)

    def sign_digest(self, public_key, digest):
        """Host-only DER signature over an already hashed F1R3node deploy."""
        if not isinstance(digest, bytes) or len(digest) != 32:
            raise WalletError("Expected a 32-byte deploy digest.")
        public = _public_bytes(public_key)
        with _directory(self.vault) as vault:
            key = self._unlock(vault, self._master(vault), public)
        return key.sign(digest, hasher=None)
