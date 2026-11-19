import asyncio
import base64
import concurrent.futures
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from coincurve import PrivateKey, PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

import omega_chain_wallet
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
        self.assertNotIn("import_recipient", graph["items"][0])
        self.assertNotIn("sign", {act["id"] for act in program.describe()["actions"]})
        self.assertEqual(program.act(None, "sign", [], {})["status"], "refused")
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

    def test_ui_operator_roundtrip_and_stale_retry(self):
        ctx = SimpleNamespace(actor={"kind": "person", "local_operator": True, "route": "operator"},
                              viewer={"kind": "operator", "local_operator": True, "route": "operator"})
        def snapshot():
            return program.view(ctx, None, "unfold")
        def act(action, items=(), **params):
            params.setdefault("base_revision", snapshot()["revision"])
            return program.act(ctx, action, list(items), params)

        first = snapshot()
        def generate(_):
            return act("generate", name="First signer", base_revision=first["revision"])
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(generate, range(2)))
        self.assertCountEqual([r["status"] for r in results], ["done", "stale"])
        self.assertEqual(snapshot()["items"][1]["name"], "First signer")

        private = PrivateKey()
        public = private.public_key.format(False).hex()
        recipient = serialization.load_der_public_key(base64.b64decode(first["items"][0]["import_recipient"]))
        encrypted = recipient.encrypt(private.secret, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        envelope = base64.b64encode(encrypted).decode()
        result = act("import", name="Imported signer", envelope=envelope)
        self.assertEqual(result, {"status": "done", "detail": {"public_key": public, "import_outcome": "imported"}})
        for name in ("Imported signer", ""):
            self.assertEqual(act("import", name=name, envelope=envelope)["detail"]["import_outcome"], "present")
        self.assertEqual(dict(self.wallet.entries())[public], "Imported signer")
        localized = "عائلة‏ 👨‍👩‍👧‍👦"
        self.assertEqual(act("import", name=localized, envelope=envelope)["detail"]["import_outcome"], "renamed")
        self.assertEqual(dict(self.wallet.entries())[public], localized)
        for bad in ("bad\nname", "a\u2028b", "a\ud800b", "x"*81, private.secret.hex()):
            result = act("rename", [public], name=bad)
            self.assertEqual(result["status"], "refused")
            self.assertNotIn(bad, json.dumps(result))
        before = snapshot()["revision"]
        self.assertEqual(act("rename", [public], name="Deploy QA")["status"], "done")
        self.assertNotEqual(snapshot()["revision"], before)
        self.assertEqual(act("rename", [public], name="Lost edit", base_revision=before)["status"], "stale")
        self.assertEqual(dict(Wallet.from_env().entries())[public], "Deploy QA")
        digest = secrets.token_bytes(32)
        self.assertTrue(private.public_key.verify(self.wallet.sign_digest(public, digest), digest, hasher=None))
        self.assertEqual(act("rename", [public], name="")["status"], "done")
        self.assertEqual(dict(self.wallet.entries())[public], "")
        for invalid in ("!"*344, private.secret.hex(), "A"*344):
            result = act("import", envelope=invalid)
            self.assertEqual(result["status"], "refused")
            self.assertNotIn(invalid, json.dumps(result))
        self.assertEqual(len(self.wallet.public_keys()), 2)

    def test_host_identity_required_for_wallet_edits(self):
        public = self.wallet.generate()
        for actor in (None, {"kind": "person", "role": "admin", "local_operator": False, "route": "operator"},
                      {"kind": "mind", "local_operator": True, "route": "agent"}):
            ctx = SimpleNamespace(actor=actor, viewer=actor)
            graph = program.view(ctx, None, None)
            self.assertNotIn("import_recipient", graph["items"][0])
            for action, items in [("generate", []), ("import", []), ("rename", [public])]:
                result = program.act(ctx, action, items, {"base_revision": graph["revision"], "local_operator": True})
                self.assertEqual(result["status"], "refused")
        self.assertEqual(self.wallet.entries(), [(public, "")])

    def test_damaged_names_are_isolated_and_repairable(self):
        a = self.wallet.generate("Intact")
        b = self.wallet.generate("Original")
        sidecar = self.wallet.vault / (b + ".name")
        for data, mode in [(b"x"*321, 0o600), (b"x"*81, 0o600), (b"\xff", 0o600),
                           (b"two\nlines", 0o600), (b"public", 0o644), (None, None)]:
            with self.subTest(data=data, mode=mode):
                if data is None:
                    sidecar.unlink()
                    sidecar.symlink_to(self.master)
                else:
                    sidecar.write_bytes(data)
                    sidecar.chmod(mode)
                graph = program.view(None, None, None)
                self.assertEqual({i["public_key"]: i["name"] for i in graph["items"][1:]}, {a: "Intact", b: ""})
                ctx = SimpleNamespace(actor={"kind": "person", "local_operator": True, "route": "operator"})
                result = program.act(ctx, "rename", [b], {"name": "Repaired", "base_revision": graph["revision"]})
                self.assertEqual(result["status"], "done")
                self.assertFalse(sidecar.is_symlink())
                self.assertEqual(sidecar.stat().st_mode & 0o777, 0o600)
                self.assertEqual(dict(self.wallet.entries())[b], "Repaired")

    def test_only_visible_names_are_opened_and_off_page_edits_invalidate_revision(self):
        keys = sorted(self.wallet.generate(f"Signer {i}") for i in range(35))
        with patch.object(omega_chain_wallet, "_read", wraps=omega_chain_wallet._read) as reads:
            page = self.wallet.signer_page(focus=keys[-1])
            self.assertEqual(page.number, 2)
            self.assertEqual([call.args[1] for call in reads.call_args_list], [key + ".name" for key in keys[32:]])
        with patch("os.scandir", wraps=os.scandir) as scans, patch.object(
                omega_chain_wallet, "_read", wraps=omega_chain_wallet._read) as reads:
            self.wallet.rename(keys[0], "Off-page rename", revision=page.revision)
            self.assertEqual(scans.call_count, 1)
            reads.assert_not_called()
        with self.assertRaises(omega_chain_wallet.WalletChanged):
            self.wallet.rename(keys[-1], "Stale", revision=page.revision)

    def test_host_work_stays_off_loop_and_lock_wait_is_bounded(self):
        ctx = SimpleNamespace(actor={"kind": "person", "local_operator": True, "route": "operator"},
                              viewer={"kind": "operator", "local_operator": True, "route": "operator"})
        main_thread = threading.get_ident()
        keygen = program.rsa.generate_private_key
        def checked_keygen(**kwargs):
            self.assertNotEqual(threading.get_ident(), main_thread)
            return keygen(**kwargs)

        async def check():
            with patch.object(program, "_recipient", None), patch.object(
                    program.rsa, "generate_private_key", side_effect=checked_keygen) as rsa_keygen:
                graph = await program.view(ctx, None, "unfold")
                rsa_keygen.assert_called_once()
            vault = os.open(self.wallet.vault, os.O_DIRECTORY)
            try:
                fcntl.flock(vault, fcntl.LOCK_EX)
                read, write = await asyncio.wait_for(asyncio.gather(
                    program.view(ctx, None, "unfold"),
                    program.act(ctx, "generate", [], {"base_revision": graph["revision"]})), timeout=3)
                self.assertEqual(read["revision"], "unavailable")
                self.assertIn("busy", write["message"])
            finally:
                os.close(vault)
            self.assertEqual(self.wallet.public_keys(), [])
            self.assertEqual((await program.act(ctx, "generate", [], {"base_revision": graph["revision"]}))["status"], "done")

        asyncio.run(check())
