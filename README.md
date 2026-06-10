# watt-wallet

Local key custody, signing, and wallet metadata for the Watt ecosystem.

`watt-wallet` manages local identities and payment accounts, then signs payloads,
capability tokens, and wallet-backed payment binding proofs. It deliberately does
not own networking, registry behavior, product UI, or public agent discovery.

## Scope

- Generate and import local Ed25519 identity keys
- Generate and import EVM-compatible payment account keys
- Derive Web3 settlement addresses
- Store wallet metadata and local key material for development workflows
- Track active identity and active payment account selection
- Sign raw bytes, structured JSON payloads, and capability tokens
- Create and verify agent DID to payment account binding proofs

`watt-wallet` depends on `watt-did` for DID parsing and proof verification:

```text
watt-wallet -> watt-did
```

## Quick Start

```rust
use watt_wallet::{InMemoryKeyStore, FileWalletMetadataStore, SignerPurpose, Wallet};

fn main() -> watt_wallet::Result<()> {
    let metadata_store = FileWalletMetadataStore::new("/tmp/watt-wallet-metadata.json");
    let keystore = InMemoryKeyStore::new();
    let mut wallet = Wallet::new(keystore, metadata_store);

    let mut profile = wallet.load_or_create_profile("default", 1)?;
    let identity = wallet.create_identity_ed25519(
        &mut profile,
        Some("alice".into()),
        vec![SignerPurpose::General],
        1,
    )?;

    let signature = wallet.sign_with_active_identity(&profile, b"hello")?;
    wallet.verify_with_identity(&profile, &identity.identity_id, b"hello", &signature)?;
    Ok(())
}
```

## CLI

The crate includes a small local CLI for development workflows:

```bash
cargo run --bin watt-wallet -- help
cargo run --bin watt-wallet -- create-identity alice
cargo run --bin watt-wallet -- list-identities
cargo run --bin watt-wallet -- create-payment-account settlement base-sepolia
cargo run --bin watt-wallet -- list-payment-accounts
cargo run --bin watt-wallet -- bind-payment-account <account-id>
cargo run --bin watt-wallet -- sign-test-payload "hello"
```

By default the CLI stores local data under `.watt-wallet/`:

- `.watt-wallet/metadata.json`
- `.watt-wallet/keystore.json`

Override the storage directory with `WATT_WALLET_DIR`:

```bash
WATT_WALLET_DIR=/custom/path cargo run --bin watt-wallet -- list-identities
```

## Payment Binding

Payment binding proofs link an agent DID to a local wallet identity and a payment
account key or address. Spending-capable accounts are signed by both the active
identity key and the payment account key. Watch-only accounts can be stored for
receiving or observing, but they cannot prove spend authority.

## Security

The file-backed keystore is for tests, local iteration, and CLI development. It
is not a replacement for OS keychain, secure enclave, or hardware-backed storage.

## Development

```bash
cargo fmt --all --check
cargo test
```
