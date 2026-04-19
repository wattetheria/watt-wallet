pub mod delegation;
pub mod error;
pub mod keystore;
pub mod metadata;
pub mod model;
pub mod wallet;

pub use crate::delegation::{
    CapabilityToken, CapabilityTokenClaims, CapabilityTokenOptions, sign_capability_token,
    sign_payload_json, verify_payload_json,
};
pub use crate::error::{Result, WalletError};
pub use crate::keystore::{
    FileKeyStore, InMemoryKeyStore, KeyMaterialInfo, KeyStore, SignatureBytes,
};
pub use crate::metadata::{FileWalletMetadataStore, WalletMetadataStore};
pub use crate::model::{
    IdentityStatus, KeyHandle, LocalIdentity, PaymentAccount, PaymentAccountKind,
    PaymentAccountParams, PaymentAccountStatus, PaymentLayer, SignerCapabilityMetadata,
    SignerPurpose, SigningAlgorithm, WalletProfileMetadata,
};
pub use crate::wallet::Wallet;
