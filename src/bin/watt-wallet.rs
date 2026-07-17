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
        "create-payment-account" => {
            let label = args.next();
            let network = args.next();
            let account = wallet.create_payment_account_web3_evm(
                &mut profile,
                label,
                network,
                Some("x402".into()),
                now_ms(),
            )?;
            println!("account_id={}", account.account_id);
            println!("rail={}", account.rail);
            println!("layer={:?}", account.layer);
            if let Some(address) = account.address {
                println!("address={address}");
            }
            Ok(())
        }
        "import-payment-account" => {
            let private_key_hex = args.next().ok_or_else(|| {
                watt_wallet::WalletError::Metadata(
                    "usage: import-payment-account <private-key-hex> [label] [network]".into(),
                )
            })?;
            let label = args.next();
            let network = args.next();
            let secret = decode_hex_secret(&private_key_hex)?;
            let account = wallet.import_payment_account_web3_evm_secret(
                &mut profile,
                secret,
                label,
                network,
                Some("x402".into()),
                now_ms(),
            )?;
            println!("account_id={}", account.account_id);
            if let Some(address) = account.address {
                println!("address={address}");
            }
            Ok(())
        }
        "watch-payment-account" => {
            let address = args.next().ok_or_else(|| {
                watt_wallet::WalletError::Metadata(
                    "usage: watch-payment-account <address> [label] [network]".into(),
                )
            })?;
            let label = args.next();
            let network = args.next();
            let account = wallet.register_watch_payment_account_web3_evm(
                &mut profile,
                address,
                label,
                network,
                Some("x402".into()),
                now_ms(),
            )?;
            println!("account_id={}", account.account_id);
            Ok(())
        }
        "list-payment-accounts" => {
            for account in wallet.list_payment_accounts(&profile) {
                let network = account.network.clone().unwrap_or_else(|| "-".into());
                let address = account.address.clone().unwrap_or_else(|| "-".into());
                println!(
                    "{} {} {} {} {}",
                    account.account_id,
                    account.rail,
                    network,
                    address,
                    if account.is_key_controlled() {
                        "local_key"
                    } else {
                        "watch_only"
                    }
                );
            }
            Ok(())
        }
        "bind-payment-account" => {
            let account_id = args.next().ok_or_else(|| {
                watt_wallet::WalletError::Metadata(
                    "usage: bind-payment-account <account-id>".into(),
                )
            })?;
            wallet.set_active_payment_account(&mut profile, &account_id, now_ms())?;
            println!("active_payment_account_id={account_id}");
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
                    verification_method: None,
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
            "unknown command; use create-identity | list-identities | create-payment-account | import-payment-account | watch-payment-account | list-payment-accounts | bind-payment-account | sign-test-payload | sign-capability".into(),
        )),
    }
}

fn decode_hex_secret(input: &str) -> watt_wallet::Result<[u8; 32]> {
    let normalized = input.trim().trim_start_matches("0x");
    let bytes = hex::decode(normalized)
        .map_err(|error| watt_wallet::WalletError::InvalidSecretKey(error.to_string()))?;
    if bytes.len() != 32 {
        return Err(watt_wallet::WalletError::InvalidSecretKey(format!(
            "expected 32-byte secret, got {} bytes",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
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
    println!("  create-payment-account [label] [network]");
    println!("  import-payment-account <private-key-hex> [label] [network]");
    println!("  watch-payment-account <address> [label] [network]");
    println!("  list-payment-accounts");
    println!("  bind-payment-account <account-id>");
    println!("  sign-test-payload [payload]");
    println!("  sign-capability");
}
