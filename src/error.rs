use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("wallet io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("wallet json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("wallet did error: {0}")]
    Did(#[from] watt_did::DidError),
    #[error("unknown key handle: {0}")]
    UnknownKeyHandle(String),
    #[error("unknown identity id: {0}")]
    UnknownIdentityId(String),
    #[error("no active identity configured")]
    NoActiveIdentity,
    #[error("unknown payment account id: {0}")]
    UnknownPaymentAccountId(String),
    #[error("no active payment account configured")]
    NoActivePaymentAccount,
    #[error("payment account is not active: {0}")]
    PaymentAccountNotActive(String),
    #[error("identity is not active: {0}")]
    IdentityNotActive(String),
    #[error("invalid secret key: {0}")]
    InvalidSecretKey(String),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("metadata error: {0}")]
    Metadata(String),
}

pub type Result<T> = std::result::Result<T, WalletError>;
