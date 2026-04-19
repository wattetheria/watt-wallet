use crate::delegation::{CapabilityToken, CapabilityTokenOptions, sign_capability_token};
use crate::error::{Result, WalletError};
use crate::keystore::{KeyMaterialInfo, KeyStore, SignatureBytes};
use crate::metadata::WalletMetadataStore;
use crate::model::{
    IdentityStatus, LocalIdentity, PaymentAccount, PaymentAccountKind, PaymentAccountParams,
    PaymentAccountStatus, PaymentLayer, SignerCapabilityMetadata, SignerPurpose, SigningAlgorithm,
    WalletProfileMetadata,
};

pub struct Wallet<K, M> {
    keystore: K,
    metadata_store: M,
}

impl<K, M> Wallet<K, M> {
    pub fn new(keystore: K, metadata_store: M) -> Self {
        Self {
            keystore,
            metadata_store,
        }
    }
}

impl<K, M> Wallet<K, M>
where
    K: KeyStore,
    M: WalletMetadataStore,
{
    pub fn load_or_create_profile(
        &self,
        profile_id: impl Into<String>,
        now_ms: u64,
    ) -> Result<WalletProfileMetadata> {
        Ok(self
            .metadata_store
            .load()?
            .unwrap_or_else(|| WalletProfileMetadata::new(profile_id, now_ms)))
    }

    pub fn save_profile(&self, profile: &WalletProfileMetadata) -> Result<()> {
        self.metadata_store.save(profile)
    }

    pub fn create_identity_ed25519(
        &mut self,
        profile: &mut WalletProfileMetadata,
        label: Option<String>,
        purposes: Vec<SignerPurpose>,
        now_ms: u64,
    ) -> Result<LocalIdentity> {
        let key_info = self.keystore.generate_ed25519()?;
        let identity = build_identity_from_key_info(key_info, label, purposes, now_ms);
        profile.add_identity(identity.clone());
        profile.updated_at_ms = now_ms;
        self.metadata_store.save(profile)?;
        Ok(identity)
    }

    pub fn import_identity_ed25519_seed(
        &mut self,
        profile: &mut WalletProfileMetadata,
        seed: [u8; 32],
        label: Option<String>,
        purposes: Vec<SignerPurpose>,
        now_ms: u64,
    ) -> Result<LocalIdentity> {
        let key_info = self.keystore.import_ed25519_seed(seed)?;
        let identity = build_identity_from_key_info(key_info, label, purposes, now_ms);
        profile.add_identity(identity.clone());
        profile.updated_at_ms = now_ms;
        self.metadata_store.save(profile)?;
        Ok(identity)
    }

    pub fn list_identities(
        &self,
        profile: &WalletProfileMetadata,
    ) -> Vec<SignerCapabilityMetadata> {
        profile
            .identities
            .iter()
            .map(LocalIdentity::signer_metadata)
            .collect()
    }

    pub fn set_active_identity(
        &self,
        profile: &mut WalletProfileMetadata,
        identity_id: &str,
        now_ms: u64,
    ) -> Result<()> {
        if !profile.set_active_identity(identity_id, now_ms) {
            return Err(WalletError::UnknownIdentityId(identity_id.to_owned()));
        }
        self.metadata_store.save(profile)?;
        Ok(())
    }

    pub fn create_payment_account_web3_evm(
        &mut self,
        profile: &mut WalletProfileMetadata,
        label: Option<String>,
        network: Option<String>,
        rail: Option<String>,
        now_ms: u64,
    ) -> Result<PaymentAccount> {
        let key_info = self.keystore.generate_secp256k1()?;
        let account = build_web3_evm_payment_account(
            key_info,
            label,
            network,
            rail.unwrap_or_else(|| "x402".to_string()),
            now_ms,
        );
        profile.add_payment_account(account.clone());
        profile.updated_at_ms = now_ms;
        self.metadata_store.save(profile)?;
        Ok(account)
    }

    pub fn import_payment_account_web3_evm_secret(
        &mut self,
        profile: &mut WalletProfileMetadata,
        secret: [u8; 32],
        label: Option<String>,
        network: Option<String>,
        rail: Option<String>,
        now_ms: u64,
    ) -> Result<PaymentAccount> {
        let key_info = self.keystore.import_secp256k1_secret(secret)?;
        let account = build_web3_evm_payment_account(
            key_info,
            label,
            network,
            rail.unwrap_or_else(|| "x402".to_string()),
            now_ms,
        );
        profile.add_payment_account(account.clone());
        profile.updated_at_ms = now_ms;
        self.metadata_store.save(profile)?;
        Ok(account)
    }

    pub fn register_watch_payment_account_web3_evm(
        &self,
        profile: &mut WalletProfileMetadata,
        address: String,
        label: Option<String>,
        network: Option<String>,
        rail: Option<String>,
        now_ms: u64,
    ) -> Result<PaymentAccount> {
        let account = PaymentAccount::new(PaymentAccountParams {
            key_handle: None,
            kind: PaymentAccountKind::Web3Evm,
            layer: PaymentLayer::Web3,
            rail: rail.unwrap_or_else(|| "x402".to_string()),
            network,
            address: Some(address),
            provider_account_id: None,
            label,
            capabilities: vec!["receive".into()],
            created_at_ms: now_ms,
        });
        profile.add_payment_account(account.clone());
        profile.updated_at_ms = now_ms;
        self.metadata_store.save(profile)?;
        Ok(account)
    }

    pub fn list_payment_accounts(&self, profile: &WalletProfileMetadata) -> Vec<PaymentAccount> {
        profile.payment_accounts.clone()
    }

    pub fn set_active_payment_account(
        &self,
        profile: &mut WalletProfileMetadata,
        account_id: &str,
        now_ms: u64,
    ) -> Result<()> {
        if !profile.set_active_payment_account(account_id, now_ms) {
            return Err(WalletError::UnknownPaymentAccountId(account_id.to_owned()));
        }
        self.metadata_store.save(profile)?;
        Ok(())
    }

    pub fn active_payment_account<'a>(
        &self,
        profile: &'a WalletProfileMetadata,
    ) -> Result<&'a PaymentAccount> {
        let account = profile
            .active_payment_account()
            .ok_or(WalletError::NoActivePaymentAccount)?;
        if account.status != PaymentAccountStatus::Active {
            return Err(WalletError::PaymentAccountNotActive(
                account.account_id.clone(),
            ));
        }
        Ok(account)
    }

    pub fn payment_account<'a>(
        &self,
        profile: &'a WalletProfileMetadata,
        account_id: &str,
    ) -> Result<&'a PaymentAccount> {
        let account = profile
            .payment_account(account_id)
            .ok_or_else(|| WalletError::UnknownPaymentAccountId(account_id.to_owned()))?;
        if account.status != PaymentAccountStatus::Active {
            return Err(WalletError::PaymentAccountNotActive(
                account.account_id.clone(),
            ));
        }
        Ok(account)
    }

    pub fn export_active_payment_account_web3_evm_secret(
        &self,
        profile: &WalletProfileMetadata,
    ) -> Result<[u8; 32]> {
        let account = self.active_payment_account(profile)?;
        let key_handle = account
            .key_handle
            .as_ref()
            .ok_or_else(|| WalletError::Metadata("active payment account is watch-only".into()))?;
        self.keystore.export_secp256k1_secret(key_handle)
    }

    pub fn active_identity<'a>(
        &self,
        profile: &'a WalletProfileMetadata,
    ) -> Result<&'a LocalIdentity> {
        let identity = profile
            .active_identity()
            .ok_or(WalletError::NoActiveIdentity)?;
        if identity.status != IdentityStatus::Active {
            return Err(WalletError::IdentityNotActive(identity.identity_id.clone()));
        }
        Ok(identity)
    }

    pub fn sign_with_active_identity(
        &self,
        profile: &WalletProfileMetadata,
        payload: &[u8],
    ) -> Result<SignatureBytes> {
        let identity = self.active_identity(profile)?;
        self.keystore.sign_bytes(&identity.key_handle, payload)
    }

    pub fn verify_with_identity(
        &self,
        profile: &WalletProfileMetadata,
        identity_id: &str,
        payload: &[u8],
        signature: &SignatureBytes,
    ) -> Result<()> {
        let identity = profile
            .identity(identity_id)
            .ok_or_else(|| WalletError::UnknownIdentityId(identity_id.to_owned()))?;
        self.keystore
            .verify_bytes(&identity.key_handle, payload, signature)
    }

    pub fn active_identity_key_info(
        &self,
        profile: &WalletProfileMetadata,
    ) -> Result<KeyMaterialInfo> {
        let identity = self.active_identity(profile)?;
        self.keystore.public_key_info(&identity.key_handle)
    }

    pub fn export_active_identity_ed25519_seed(
        &self,
        profile: &WalletProfileMetadata,
    ) -> Result<[u8; 32]> {
        let identity = self.active_identity(profile)?;
        self.keystore.export_ed25519_seed(&identity.key_handle)
    }

    pub fn rotate_active_identity(
        &mut self,
        profile: &mut WalletProfileMetadata,
        label: Option<String>,
        purposes: Vec<SignerPurpose>,
        now_ms: u64,
    ) -> Result<LocalIdentity> {
        let previous = self.active_identity(profile)?.identity_id.clone();
        let key_info = self.keystore.generate_ed25519()?;
        let replacement = build_identity_from_key_info(key_info, label, purposes, now_ms);
        if !profile.rotate_identity(&previous, replacement.clone(), now_ms) {
            return Err(WalletError::UnknownIdentityId(previous));
        }
        self.metadata_store.save(profile)?;
        Ok(replacement)
    }

    pub fn sign_capability_token(
        &self,
        profile: &WalletProfileMetadata,
        options: CapabilityTokenOptions,
    ) -> Result<CapabilityToken> {
        let identity = self.active_identity(profile)?;
        sign_capability_token(&self.keystore, &identity.key_handle, options)
    }
}

fn build_identity_from_key_info(
    key_info: KeyMaterialInfo,
    label: Option<String>,
    purposes: Vec<SignerPurpose>,
    now_ms: u64,
) -> LocalIdentity {
    LocalIdentity::new(
        key_info.did,
        key_info.key_handle,
        SigningAlgorithm::Ed25519,
        if purposes.is_empty() {
            vec![SignerPurpose::General]
        } else {
            purposes
        },
        label,
        now_ms,
    )
}

fn build_web3_evm_payment_account(
    key_info: KeyMaterialInfo,
    label: Option<String>,
    network: Option<String>,
    rail: String,
    now_ms: u64,
) -> PaymentAccount {
    PaymentAccount::new(PaymentAccountParams {
        key_handle: Some(key_info.key_handle),
        kind: PaymentAccountKind::Web3Evm,
        layer: PaymentLayer::Web3,
        rail,
        network,
        address: key_info.derived_address,
        provider_account_id: None,
        label,
        capabilities: vec!["send".into(), "receive".into()],
        created_at_ms: now_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::InMemoryKeyStore;
    use crate::metadata::FileWalletMetadataStore;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn wallet_can_create_sign_and_rotate_identity() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let path = std::env::temp_dir().join(format!("watt-wallet-profile-{unique}.json"));
        let store = FileWalletMetadataStore::new(&path);
        let keystore = InMemoryKeyStore::new();
        let mut wallet = Wallet::new(keystore, store);
        let mut profile = wallet.load_or_create_profile("default", 1).unwrap();
        let identity = wallet
            .create_identity_ed25519(
                &mut profile,
                Some("alice".into()),
                vec![SignerPurpose::General],
                1,
            )
            .unwrap();
        let signature = wallet
            .sign_with_active_identity(&profile, b"hello")
            .unwrap();
        wallet
            .verify_with_identity(&profile, &identity.identity_id, b"hello", &signature)
            .unwrap();
        let key_info = wallet.active_identity_key_info(&profile).unwrap();
        assert_eq!(key_info.did, identity.did);
        let seed = wallet
            .export_active_identity_ed25519_seed(&profile)
            .unwrap();
        assert_eq!(seed.len(), 32);
        let rotated = wallet
            .rotate_active_identity(&mut profile, Some("alice-2".into()), vec![], 2)
            .unwrap();
        assert_ne!(identity.identity_id, rotated.identity_id);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn wallet_can_create_and_bind_payment_account() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let path = std::env::temp_dir().join(format!("watt-wallet-payment-{unique}.json"));
        let store = FileWalletMetadataStore::new(&path);
        let keystore = InMemoryKeyStore::new();
        let mut wallet = Wallet::new(keystore, store);
        let mut profile = wallet.load_or_create_profile("default", 1).unwrap();
        let account = wallet
            .create_payment_account_web3_evm(
                &mut profile,
                Some("settlement".into()),
                Some("base-sepolia".into()),
                Some("x402".into()),
                1,
            )
            .unwrap();
        assert_eq!(account.kind, PaymentAccountKind::Web3Evm);
        assert!(account.is_key_controlled());
        assert!(
            account
                .address
                .as_deref()
                .is_some_and(|value| value.starts_with("0x"))
        );
        wallet
            .set_active_payment_account(&mut profile, &account.account_id, 2)
            .unwrap();
        let active = wallet.active_payment_account(&profile).unwrap();
        assert_eq!(active.account_id, account.account_id);
        let secret = wallet
            .export_active_payment_account_web3_evm_secret(&profile)
            .unwrap();
        assert_eq!(secret.len(), 32);
        let _ = fs::remove_file(path);
    }
}
