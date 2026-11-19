# Omega Chain Wallet

Chain Wallet stores the Hive host’s F1R3node secp256k1 deploy signers. In OmegaHive, **Apps → Chain Wallet** shows the full uncompressed public keys. The app lists encrypted record filenames and has no actions. Key creation, import and signing take place on the host.

## Set up a wallet

Run these commands as the Unix service account that runs Hive. The examples assume sibling checkouts.

```sh
cd ~/work/takopi/omega-flagship/omega-chain-wallet
hive=../omegahive
uv pip install --python "$hive/.venv/bin/python" .
wallet="$hive/.venv/bin/omega-chain-wallet"
"$wallet" init
```

Choose the command that matches the signer you want. Import preserves its public key, chain identity and existing balances. A newly generated key starts unfunded.

| Command | Purpose |
| --- | --- |
| `"$wallet" import-pem /path/to/f1r3fly.key` | Import the encrypted PKCS#8 file from F1R3node’s `keygen`. Enter its passphrase at the hidden terminal prompt. |
| `"$wallet" import-hex` | Import a 64-digit hex private key at a hidden terminal prompt. |
| `"$wallet" import-hex --stdin < /path/to/signer.hex` | Migrate a hex key file already used by the deploy adapter. |
| `"$wallet" generate` | Generate a fresh key directly in the wallet. |
| `"$wallet" list` | Print one public key per line. |

Generation and import print the public key. Compare it to `f1r3fly.pub.hex` when migrating a node-generated signer. The wallet uses lowercase hex. Reimporting the same key verifies the existing record.

## Open the OmegaHive app

Run this from the wallet checkout when configuring the Hive host environment. It preserves existing plugin directories and release pins.

```sh
wallet_app="$PWD/app"
export HIVE_PLUGIN_DIRS="${HIVE_PLUGIN_DIRS:+$HIVE_PLUGIN_DIRS:}$wallet_app"
cd ../omegahive
HIVE_APP_PINS=$(.venv/bin/python - "$wallet_app" <<'PY'
import json, os, sys
from pathlib import Path
from hive.core.programs import Programs
app = Path(sys.argv[1]).resolve()
pins = json.loads(os.environ.get("HIVE_APP_PINS") or "{}")
pins["omega-chain-wallet"] = {"release": str(app), "digest": Programs.source_digest(app)}
print(json.dumps(pins))
PY
)
export HIVE_APP_PINS
```

Start Hive with that environment. Open Chain Wallet in a swarm and use **Refresh** after adding a key. The list belongs to the host and is visible to users with access to that app. After an update, reinstall the host package and refresh the app pin.

## Sign benchmark deploys

Install the sibling `chain-tools` deploy extra in the same Hive environment. Set `CHAIN_DEPLOY_PUBLIC_KEY` to the full public hex key printed by the wallet. Use this configuration for both the benchmark installer and the Hive service.

```sh
# From the OmegaHive checkout
uv pip install --python .venv/bin/python -e '../chain-tools[deploy]'
unset CHAIN_DEPLOY_KEY_FILE
export CHAIN_DEPLOY_PUBLIC_KEY='<full public key from omega-chain-wallet list>'
```

The adapter signs the canonical deploy digest locally and sends the public key and DER signature to F1R3node. For an existing benchmark, select its original funded signer. Changing the signer changes the on-chain deployer identity.

## Storage and recovery

| Location | Contents | Override |
| --- | --- | --- |
| `$XDG_DATA_HOME/omega-chain-wallet` (defaults under `~/.local/share`) | Authenticated encrypted signing records and `wallet.id` | `OMEGA_CHAIN_WALLET_DIR` |
| `$XDG_CONFIG_HOME/omega-chain-wallet` (defaults under `~/.config`) | 32-byte wrapping key in `wrapping.key` | `OMEGA_CHAIN_WALLET_CONFIG_DIR` |

Use separate directories on a local Linux filesystem under trusted parent directories. Apply path overrides consistently to the CLI and the Hive service. Directories are created with mode `0700`. Files are published atomically with mode `0600`. Each record uses AES-256-GCM with a random nonce and authenticates its format and public key. A wallet identity check catches a mismatched wrapping key before adding or signing with a key.

Back up the complete encrypted record directory and the wrapping key separately, with access restricted to the operator. Restore both to recover signing. Losing the wrapping key requires recovery from an independent backup of the original signer. Import leaves the source file under its existing protection.

The Unix service account is the custody boundary. Code running as that account or as root can use its keys. Run untrusted minds outside that account’s filesystem access. Hive’s app bridge exposes only the public list.

## Verification

```sh
# From the wallet checkout after installation
../omegahive/.venv/bin/python -m unittest discover -s tests -v
(cd ../omegahive && .venv/bin/python -m hive.programs_check ../omega-chain-wallet/app)
```
