"""OmegaHive signer management. Only public metadata leaves the host wallet."""
import asyncio
import base64
import binascii
import re
from functools import wraps
from threading import Lock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from omega_chain_wallet import Wallet, WalletChanged, WalletError


# Only the host process holds the import recipient's private key. Reloading the app rotates it.
_recipient = None
_recipient_lock = Lock()
_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def _import_recipient():
    global _recipient
    with _recipient_lock:
        if _recipient is None:
            _recipient = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return _recipient


def describe():
    name = {"type": "string", "title": "Signer name"}
    return {"contract": "0.1", "actions": [
                {"id": "generate", "label": "Generate key", "applies_to": [], "params": {"name": name}},
                {"id": "import", "label": "Import key", "applies_to": [],
                 "params": {"name": name, "envelope": "Encrypted signer from the Chain Wallet interface"}},
                {"id": "rename", "label": "Rename signer", "applies_to": ["public-key"], "params": {"name": name}}],
            "relations": [],
            "kinds": [{"id": "wallet", "label": "Wallet", "role": "other"},
                      {"id": "public-key", "label": "Public key", "role": "other"}]}


def _operator(identity, kind):
    return (isinstance(identity, dict) and identity.get("kind") == kind
            and identity.get("local_operator") is True and identity.get("route") == "operator")


def _off_loop(fn):
    """Hive awaits program results. Its standalone checker also calls view synchronously."""
    @wraps(fn)
    def run(*args, **kwargs):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return fn(*args, **kwargs)
        return asyncio.to_thread(fn, *args, **kwargs)
    return run


@_off_loop
def view(ctx, focus, stage):
    match = re.fullmatch(r"page-([1-9][0-9]{0,8})", focus or "")
    try:
        page = Wallet.from_env().signer_page(int(match[1]) if match else 1,
                                             focus=None if match else focus)
    except (WalletError, OSError, RuntimeError) as exc:
        summary = str(exc) if isinstance(exc, WalletError) else "The host could not read the public key list."
        return {"title": "Chain Wallet", "revision": "unavailable", "focus": "wallet",
                "items": [{"id": "wallet", "kind": "wallet", "label": "Wallet unavailable",
                           "summary": summary}], "links": []}

    root = {"id": "wallet", "kind": "wallet", "label": "Signers", "page": page.number,
            "pages": page.pages, "count": page.count}
    if _operator(getattr(ctx, "viewer", None), "operator"):
        der = _import_recipient().public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        root["import_recipient"] = base64.b64encode(der).decode("ascii")
    items = [root]
    for key, name in page.entries:
        items.append({"id": key, "kind": "public-key", "label": name or key, "name": name, "public_key": key})
    return {"title": "Chain Wallet", "revision": f"{page.revision}/{page.number}", "focus": "wallet",
            "items": items, "links": []}


def _open_envelope(envelope):
    if not isinstance(envelope, str) or len(envelope) != 344:
        raise WalletError("Use the Import key form to encrypt the signer.")
    try:
        ciphertext = base64.b64decode(envelope, validate=True)
        return _import_recipient().decrypt(ciphertext, _OAEP)
    except (binascii.Error, ValueError):
        raise WalletError("Could not open the import. Refresh the wallet and enter the key again.") from None


@_off_loop
def act(ctx, action, items, params):
    if not _operator(getattr(ctx, "actor", None), "person") or getattr(ctx, "read_only", False):
        return {"status": "refused", "message": "Only the Hive local operator can manage this wallet."}
    revision = params.get("base_revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}/[1-9][0-9]*", revision):
        return {"status": "stale", "message": "Refresh the wallet before editing signers."}
    revision = revision.split("/", 1)[0]
    name = params.get("name", "")
    detail = {}
    try:
        wallet = Wallet.from_env()
        if action == "generate" and not items:
            public = wallet.generate(name, revision=revision)
        elif action == "import" and not items:
            public, detail["import_outcome"] = wallet.import_signer(
                _open_envelope(params.get("envelope")), name, revision=revision)
        elif action == "rename" and len(items) == 1 and "name" in params:
            public = wallet.rename(items[0], name, revision=revision)
        else:
            raise WalletError("Choose a supported action and signer.")
    except WalletChanged as exc:
        return {"status": "stale", "message": str(exc)}
    except WalletError as exc:
        return {"status": "refused", "message": str(exc)}
    except OSError:
        return {"status": "error", "message": "Could not access wallet storage. Check the host wallet."}
    detail["public_key"] = public
    return {"status": "done", "detail": detail}
