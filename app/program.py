"""OmegaHive signer management. Only public metadata leaves the host wallet."""
import base64
import binascii
import re
from threading import Lock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from omega_chain_wallet import Wallet, WalletChanged, WalletError, wallet_revision


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


def view(ctx, focus, stage):
    try:
        entries = Wallet.from_env().entries()
    except (WalletError, OSError, RuntimeError):
        return {"title": "Chain Wallet", "revision": "unavailable", "focus": "wallet",
                "items": [{"id": "wallet", "kind": "wallet", "label": "Wallet unavailable",
                           "summary": "The host could not read the public key list."}], "links": []}

    page_size = 32
    pages = max(1, (len(entries) + page_size - 1) // page_size)
    match = re.fullmatch(r"page-([1-9][0-9]{0,8})", focus or "")
    page = min(int(match[1]), pages) if match else 1
    if focus and not match:
        page = next((i // page_size + 1 for i, (key, _) in enumerate(entries) if key == focus), 1)
    root = {"id": "wallet", "kind": "wallet", "label": "Signers", "page": page,
            "pages": pages, "count": len(entries)}
    if _operator(getattr(ctx, "viewer", None), "operator"):
        der = _import_recipient().public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        root["import_recipient"] = base64.b64encode(der).decode("ascii")
    items = [root]
    for key, name in entries[(page - 1) * page_size:page * page_size]:
        items.append({"id": key, "kind": "public-key", "label": name or key, "name": name, "public_key": key})
    return {"title": "Chain Wallet", "revision": f"{wallet_revision(entries)}/{page}", "focus": "wallet",
            "items": items, "links": []}


def _open_envelope(envelope):
    if not isinstance(envelope, str) or len(envelope) != 344:
        raise WalletError("Use the Import key form to encrypt the signer.")
    try:
        ciphertext = base64.b64decode(envelope, validate=True)
        return _import_recipient().decrypt(ciphertext, _OAEP)
    except (binascii.Error, ValueError):
        raise WalletError("Could not open the import. Refresh the wallet and enter the key again.") from None


def act(ctx, action, items, params):
    if not _operator(getattr(ctx, "actor", None), "person") or getattr(ctx, "read_only", False):
        return {"status": "refused", "message": "Only the Hive local operator can manage this wallet."}
    revision = params.get("base_revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}/[1-9][0-9]*", revision):
        return {"status": "stale", "message": "Refresh the wallet before editing signers."}
    revision = revision.split("/", 1)[0]
    name = params.get("name", "")
    try:
        wallet = Wallet.from_env()
        if action == "generate" and not items:
            public = wallet.generate(name, revision=revision)
        elif action == "import" and not items:
            public = wallet.import_secret(_open_envelope(params.get("envelope")), name, revision=revision)
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
    return {"status": "done", "detail": {"public_key": public}}
