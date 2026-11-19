"""OmegaHive's read-only projection of the host wallet."""
import hashlib
import re

from omega_chain_wallet import Wallet, WalletError


def describe():
    return {"contract": "0.1", "actions": [], "relations": [],
            "kinds": [{"id": "wallet", "label": "Wallet", "role": "other"},
                      {"id": "public-key", "label": "Public key", "role": "other"}]}


def view(ctx, focus, stage):
    try:
        keys = Wallet.from_env().public_keys()
    except (WalletError, OSError, RuntimeError):
        return {"title": "Chain Wallet", "revision": "unavailable", "focus": "wallet",
                "items": [{"id": "wallet", "kind": "wallet", "label": "Wallet unavailable",
                           "summary": "The host could not read the public key list."}], "links": []}

    page_size = 32
    pages = max(1, (len(keys) + page_size - 1) // page_size)
    match = re.fullmatch(r"page-([1-9][0-9]{0,8})", focus or "")
    page = min(int(match[1]), pages) if match else 1
    revision = hashlib.sha256("".join(keys).encode("ascii")).hexdigest()
    items = [{"id": "wallet", "kind": "wallet", "label": "Public keys", "page": page,
              "pages": pages, "count": len(keys), "summary": f"{len(keys)} registered public keys"}]
    for key in keys[(page - 1) * page_size:page * page_size]:
        items.append({"id": key, "kind": "public-key", "label": key, "public_key": key})
    return {"title": "Chain Wallet", "revision": f"{revision}/{page}", "focus": "wallet", "items": items, "links": []}


def act(ctx, action, items, params):
    raise ValueError("The wallet view is read-only.")
