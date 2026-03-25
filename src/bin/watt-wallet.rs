use base64::Engine;
use std::env;
use std::path::PathBuf;
use watt_did::UcanCapability;
use watt_wallet::{
    CapabilityTokenOptions, FileKeyStore, FileWalletMetadataStore, SignerPurpose, Wallet,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> watt_wallet::Result<()> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let base_dir = wallet_dir();
    let metadata_path = base_dir.join("metadata.json");
    let keystore_path = base_dir.join("keystore.json");

    let metadata_store = FileWalletMetadataStore::new(&metadata_path);
    let keystore = FileKeyStore::open(&keystore_path)?;
    let mut wallet = Wallet::new(keystore, metadata_store);
    let mut profile = wallet.load_or_create_profile("default", now_ms())?;

    match command.as_str() {
        "create-identity" => {
            let label = args.next();
            let identity = wallet.create_identity_ed25519(
                &mut profile,
                label,
                vec![SignerPurpose::General],
                now_ms(),
            )?;
            println!("identity_id={}", identity.identity_id);
            println!("did={}", identity.did);
            Ok(())
        }
        "list-identities" => {
            for identity in wallet.list_identities(&profile) {
                println!(
                    "{} {} {:?} {:?}",
                    identity.identity_id, identity.did, identity.algorithm, identity.status
                );
            }
            Ok(())
        }
        "sign-test-payload" => {
            let payload = args.next().unwrap_or_else(|| "hello".into());
            let signature = wallet.sign_with_active_identity(&profile, payload.as_bytes())?;
            println!("{}", base64::engine::general_purpose::STANDARD.encode(signature.0));
            Ok(())
        }
        "sign-capability" => {
            let active = wallet.active_identity(&profile)?;
            let token = wallet.sign_capability_token(
                &profile,
                CapabilityTokenOptions {
                    issuer_did: active.did.clone(),
                    subject: "local-agent".into(),
                    audience: vec!["wattetheria".into()],
                    issued_at_ms: now_ms(),
                    not_before_ms: Some(now_ms()),
                    expires_at_ms: Some(now_ms() + 60_000),
                    capabilities: vec![UcanCapability {
                        resource: "urn:watt:task".into(),
                        ability: "invoke".into(),
                        caveat: None,
                    }],
                    verification_method: Some("#key-1".into()),
                },
            )?;
            println!("{}", token.token);
            Ok(())
        }
        "help" | "" => {
            print_help();
            Ok(())
        }
        _ => Err(watt_wallet::WalletError::Metadata(
            "unknown command; use create-identity | list-identities | sign-test-payload | sign-capability".into(),
        )),
    }
}

fn wallet_dir() -> PathBuf {
    env::var_os("WATT_WALLET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".watt-wallet"))
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn print_help() {
    println!("watt-wallet");
    println!();
    println!("Commands:");
    println!("  create-identity [label]");
    println!("  list-identities");
    println!("  sign-test-payload [payload]");
    println!("  sign-capability");
}
