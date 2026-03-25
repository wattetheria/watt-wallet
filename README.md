# watt-wallet

`watt-wallet` is the local key-custody and signing boundary for the Watt ecosystem.

It is responsible for:

- local key generation and import
- key-handle management
- local identity selection
- signing raw bytes and structured payloads
- capability/delegation token signing
- local wallet metadata

It is not responsible for:

- transport networking
- service registry semantics
- product UI logic
- public-agent discovery

## Relationship To `watt-did`

Boundary rule:

- `watt-did` parses and verifies DID documents and proofs
- `watt-wallet` creates and manages local signing identities and produces signatures

Typical dependency direction:

```text
watt-wallet -> watt-did
```

## Current Features

- Rust library crate
- `Ed25519` local key generation
- `Ed25519` seed import
- in-memory keystore
- file-backed local keystore for development
- file-backed wallet metadata store
- active identity selection
- multiple local identities
- key rotation model
- raw payload signing and verification
- structured JSON payload signing helpers
- capability token signing
- local CLI for developer workflows

## Main Types

- `KeyStore`
- `InMemoryKeyStore`
- `FileKeyStore`
- `WalletMetadataStore`
- `FileWalletMetadataStore`
- `Wallet`
- `WalletProfileMetadata`
- `LocalIdentity`
- `SignerCapabilityMetadata`
- `CapabilityToken`

## Quick Start

### Create a wallet and local identity

```rust
use watt_wallet::{InMemoryKeyStore, FileWalletMetadataStore, SignerPurpose, Wallet};

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
assert_eq!(identity.did.method(), "key");
# Ok::<(), watt_wallet::WalletError>(())
```

### Sign a payload with the active identity

```rust
use watt_wallet::{InMemoryKeyStore, FileWalletMetadataStore, SignerPurpose, Wallet};

let metadata_store = FileWalletMetadataStore::new("/tmp/watt-wallet-metadata-2.json");
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
# Ok::<(), watt_wallet::WalletError>(())
```

### Sign a capability token

```rust
use watt_did::UcanCapability;
use watt_wallet::{
    CapabilityTokenOptions, FileWalletMetadataStore, InMemoryKeyStore, SignerPurpose, Wallet,
};

let metadata_store = FileWalletMetadataStore::new("/tmp/watt-wallet-metadata-3.json");
let keystore = InMemoryKeyStore::new();
let mut wallet = Wallet::new(keystore, metadata_store);
let mut profile = wallet.load_or_create_profile("default", 1)?;
let identity = wallet.create_identity_ed25519(
    &mut profile,
    Some("alice".into()),
    vec![SignerPurpose::CapabilityDelegation],
    1,
)?;
let token = wallet.sign_capability_token(
    &profile,
    CapabilityTokenOptions {
        issuer_did: identity.did.clone(),
        subject: "agent-1".into(),
        audience: vec!["wattetheria".into()],
        issued_at_ms: 100,
        not_before_ms: Some(100),
        expires_at_ms: Some(200),
        capabilities: vec![UcanCapability {
            resource: "urn:watt:task".into(),
            ability: "invoke".into(),
            caveat: None,
        }],
        verification_method: Some("#key-1".into()),
    },
)?;
assert_eq!(token.token.split('.').count(), 3);
# Ok::<(), watt_wallet::WalletError>(())
```

## CLI

The project includes a small local CLI:

```bash
cargo run --bin watt-wallet -- help
cargo run --bin watt-wallet -- create-identity alice
cargo run --bin watt-wallet -- list-identities
cargo run --bin watt-wallet -- sign-test-payload "hello"
cargo run --bin watt-wallet -- sign-capability
```

By default it uses:

- metadata: `.watt-wallet/metadata.json`
- keystore: `.watt-wallet/keystore.json`

Override with:

```bash
WATT_WALLET_DIR=/custom/path cargo run --bin watt-wallet -- list-identities
```

## Security Note

The file-backed keystore is a local development implementation.

It is useful for:

- tests
- local iteration
- CLI workflows

It is not a replacement for future OS keychain, secure enclave, or hardware-backed adapters.

## Development

```bash
cargo fmt --all --check
cargo test
```
