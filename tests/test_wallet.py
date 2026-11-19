import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from coincurve import PrivateKey, PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from omega_chain_wallet import Wallet, WalletError
from omega_chain_wallet.cli import _import_pem


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("wallet_program", ROOT / "app/program.py")
program = importlib.util.module_from_spec(spec)
spec.loader.exec_module(program)


class WalletTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        env = patch.dict(os.environ, {"OMEGA_CHAIN_WALLET_DIR": str(root / "records"),
                                      "OMEGA_CHAIN_WALLET_CONFIG_DIR": str(root / "config")})
        env.start()
        self.addCleanup(env.stop)
        self.wallet = Wallet.from_env()
        self.wallet.initialize()
        self.master = self.wallet.config / "wrapping.key"

    def test_store_restart_sign_and_public_only_projection(self):
        private = PrivateKey()
        public = self.wallet.import_secret(private.secret)
        self.assertEqual(public, private.public_key.format(False).hex())
        record = self.wallet.vault / (public + ".owk")
        self.assertNotIn(private.secret, record.read_bytes())
        self.assertNotIn(private.secret.hex().encode(), record.read_bytes())
        for path in (record, self.master, self.wallet.vault / "wallet.id"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for path in (self.wallet.vault, self.wallet.config):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        digest = hashlib.blake2b(b"deploy", digest_size=32).digest()
        signature = Wallet.from_env().sign_digest(public.upper(), digest)
        self.assertTrue(PublicKey(bytes.fromhex(public)).verify(signature, digest, hasher=None))
        self.master.unlink()
        # Rendering the view must work even when the wrapping key is offline.
        graph = program.view(None, None, "unfold")
        self.assertEqual(graph["items"][1]["public_key"], public)
        self.assertNotIn(private.secret.hex(), json.dumps(graph))
        self.assertEqual(program.describe()["actions"], [])
        with self.assertRaises(ValueError):
            program.act(None, "sign", [], {})
        with self.assertRaises(WalletError):
            self.wallet.initialize()
        self.assertFalse(self.master.exists())
        with self.assertRaises(WalletError):
            self.wallet.sign_digest(public, digest)

    def test_authenticates_record_identity_and_refuses_wrong_master_or_corrupt_duplicate(self):
        secret = PrivateKey().secret
        a = self.wallet.import_secret(secret)
        b = self.wallet.generate()
        path_a = self.wallet.vault / (a + ".owk")
        path_b = self.wallet.vault / (b + ".owk")
        path_a.write_bytes(path_b.read_bytes())
        with self.assertRaises(WalletError):
            self.wallet.sign_digest(a, bytes(32))
        with self.assertRaises(WalletError):
            self.wallet.import_secret(secret)
        self.master.write_bytes(secrets.token_bytes(32))
        for operation in (self.wallet.initialize, self.wallet.generate):
            with self.assertRaises(WalletError):
                operation()
        self.assertEqual(self.wallet.public_keys(), sorted((a, b)))

    def test_rejects_bad_permissions_links_and_invalid_selectors(self):
        public = self.wallet.generate()
        record = self.wallet.vault / (public + ".owk")
        record.chmod(0o644)
        with self.assertRaises(WalletError):
            self.wallet.sign_digest(public, bytes(32))
        record.unlink()
        record.symlink_to(self.master)
        with self.assertRaises(OSError):
            self.wallet.sign_digest(public, bytes(32))
        with self.assertRaises(WalletError):
            self.wallet.sign_digest("../../wrapping.key", bytes(32))
        self.master.chmod(0o640)
        with self.assertRaises(WalletError):
            self.wallet.generate()
        self.wallet.vault.chmod(0o755)
        self.assertEqual(program.view(None, None, None)["revision"], "unavailable")

    def test_parallel_initialization_and_import(self):
        wallet = Wallet(self.wallet.vault.parent / "new-records", self.wallet.config.parent / "new-config")
        key = PrivateKey()
        def store(_):
            wallet.initialize()
            return wallet.import_secret(key.secret)
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            result = list(pool.map(store, range(16)))
        self.assertEqual(set(result), {key.public_key.format(False).hex()})
        self.assertEqual(wallet.public_keys(), result[:1])
        self.assertFalse(any(p.name.endswith(".tmp") for p in wallet.vault.iterdir()))

    def test_import_encrypted_node_format_and_refuse_other_curves(self):
        password = secrets.token_urlsafe()
        pem_path = self.wallet.vault.parent / "f1r3fly.key"
        for curve in (ec.SECP256K1(), ec.SECP256R1()):
            native = ec.generate_private_key(curve)
            pem_path.write_bytes(native.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password.encode())))
            with patch("omega_chain_wallet.cli._prompt", return_value="invalid"):
                with self.assertRaises(WalletError):
                    _import_pem(self.wallet, pem_path)
            with patch("omega_chain_wallet.cli._prompt", return_value=password):
                if isinstance(curve, ec.SECP256K1):
                    self.assertEqual(_import_pem(self.wallet, pem_path), native.public_key().public_bytes(
                        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex())
                else:
                    with self.assertRaises(WalletError):
                        _import_pem(self.wallet, pem_path)
        self.assertEqual(len(self.wallet.public_keys()), 1)

    def test_cli_only_prints_public_keys_and_keeps_invalid_input_out_of_errors(self):
        def run(*args, data=b""):
            return subprocess.run([sys.executable, "-m", "omega_chain_wallet.cli", *args],
                                  input=data, capture_output=True, cwd=ROOT)
        private = PrivateKey()
        output = run("import-hex", "--stdin", data=private.secret.hex().encode())
        self.assertEqual(output.returncode, 0)
        self.assertEqual(output.stdout.strip(), private.public_key.format(False).hex().encode())
        self.assertEqual(output.stderr, b"")
        self.assertEqual(run("list").stdout, output.stdout)
        for invalid in (b"01" * 33, b"00" * 32, b"ff" * 32, b"x" * 64):
            output = run("import-hex", "--stdin", data=invalid)
            self.assertNotEqual(output.returncode, 0)
            self.assertEqual(output.stdout, b"")
            self.assertNotIn(invalid, output.stderr)
            self.assertNotIn(b"Traceback", output.stderr)

    def test_view_paginates_and_preserves_full_keys(self):
        keys = sorted(self.wallet.generate() for _ in range(34))
        first = program.view(None, None, None)
        last = program.view(None, "page-2", None)
        self.assertEqual(first["items"][0]["pages"], 2)
        self.assertEqual([row["public_key"] for graph in (first, last) for row in graph["items"][1:]], keys)
