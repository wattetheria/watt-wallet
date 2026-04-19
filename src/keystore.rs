use crate::error::{Result, WalletError};
use crate::model::{KeyHandle, SigningAlgorithm};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey as Ed25519SigningKey, Verifier as _,
    VerifyingKey as Ed25519VerifyingKey,
};
use k256::ecdsa::{
    Signature as Secp256k1Signature, SigningKey as Secp256k1SigningKey,
    VerifyingKey as Secp256k1VerifyingKey,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use watt_did::{Did, JsonWebKey, JwkPublicKey};

const ED25519_PUBLIC_KEY_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
const SECP256K1_PUBLIC_KEY_MULTICODEC_PREFIX: [u8; 2] = [0xe7, 0x01];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBytes(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMaterialInfo {
    pub key_handle: KeyHandle,
    pub did: Did,
    pub algorithm: SigningAlgorithm,
    pub public_key_multibase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<JsonWebKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_address: Option<String>,
}

pub trait KeyStore {
    fn generate_ed25519(&mut self) -> Result<KeyMaterialInfo>;
    fn import_ed25519_seed(&mut self, seed: [u8; 32]) -> Result<KeyMaterialInfo>;
    fn export_ed25519_seed(&self, key_handle: &KeyHandle) -> Result<[u8; 32]>;
    fn generate_secp256k1(&mut self) -> Result<KeyMaterialInfo>;
    fn import_secp256k1_secret(&mut self, secret: [u8; 32]) -> Result<KeyMaterialInfo>;
    fn export_secp256k1_secret(&self, key_handle: &KeyHandle) -> Result<[u8; 32]>;
    fn sign_bytes(&self, key_handle: &KeyHandle, payload: &[u8]) -> Result<SignatureBytes>;
    fn verify_bytes(
        &self,
        key_handle: &KeyHandle,
        payload: &[u8],
        signature: &SignatureBytes,
    ) -> Result<()>;
    fn public_key_info(&self, key_handle: &KeyHandle) -> Result<KeyMaterialInfo>;
    fn list_handles(&self) -> Vec<KeyHandle>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryKeyStore {
    keys: HashMap<KeyHandle, KeyRecord>,
}

#[derive(Debug, Clone)]
pub struct FileKeyStore {
    path: PathBuf,
    keys: HashMap<KeyHandle, KeyRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedFileKeyStore {
    keys: Vec<PersistedKeyRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedKeyRecord {
    key_handle: KeyHandle,
    algorithm: SigningAlgorithm,
    secret_key_b64: String,
}

#[derive(Debug, Clone)]
enum KeyRecord {
    Ed25519(Ed25519KeyRecord),
    Secp256k1(Secp256k1KeyRecord),
}

#[derive(Debug, Clone)]
struct Ed25519KeyRecord {
    signing_key: Ed25519SigningKey,
}

#[derive(Debug, Clone)]
struct Secp256k1KeyRecord {
    signing_key: Secp256k1SigningKey,
}

impl InMemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl FileKeyStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let keys = if path.exists() {
            let json = fs::read_to_string(&path)?;
            let persisted: PersistedFileKeyStore = serde_json::from_str(&json)?;
            persisted
                .keys
                .into_iter()
                .map(|entry| {
                    let secret = decode_secret_key(&entry.secret_key_b64)?;
                    let record = match entry.algorithm {
                        SigningAlgorithm::Ed25519 => KeyRecord::Ed25519(Ed25519KeyRecord {
                            signing_key: Ed25519SigningKey::from_bytes(&secret),
                        }),
                        SigningAlgorithm::Secp256k1 => KeyRecord::Secp256k1(Secp256k1KeyRecord {
                            signing_key: secp256k1_signing_key_from_secret(&secret)?,
                        }),
                    };
                    Ok((entry.key_handle, record))
                })
                .collect::<Result<HashMap<_, _>>>()?
        } else {
            HashMap::new()
        };

        Ok(Self { path, keys })
    }

    pub fn flush(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let persisted = PersistedFileKeyStore {
            keys: self
                .keys
                .iter()
                .map(|(key_handle, record)| match record {
                    KeyRecord::Ed25519(record) => PersistedKeyRecord {
                        key_handle: key_handle.clone(),
                        algorithm: SigningAlgorithm::Ed25519,
                        secret_key_b64: STANDARD.encode(record.signing_key.to_bytes()),
                    },
                    KeyRecord::Secp256k1(record) => PersistedKeyRecord {
                        key_handle: key_handle.clone(),
                        algorithm: SigningAlgorithm::Secp256k1,
                        secret_key_b64: STANDARD.encode(record.signing_key.to_bytes()),
                    },
                })
                .collect(),
        };
        fs::write(&self.path, serde_json::to_vec_pretty(&persisted)?)?;
        Ok(())
    }
}

impl KeyStore for InMemoryKeyStore {
    fn generate_ed25519(&mut self) -> Result<KeyMaterialInfo> {
        self.import_ed25519_seed(random_seed())
    }

    fn import_ed25519_seed(&mut self, seed: [u8; 32]) -> Result<KeyMaterialInfo> {
        let key_handle = KeyHandle::generate();
        let signing_key = Ed25519SigningKey::from_bytes(&seed);
        let info = ed25519_key_material_info(&key_handle, &signing_key)?;
        self.keys.insert(
            key_handle,
            KeyRecord::Ed25519(Ed25519KeyRecord { signing_key }),
        );
        Ok(info)
    }

    fn export_ed25519_seed(&self, key_handle: &KeyHandle) -> Result<[u8; 32]> {
        match self
            .keys
            .get(key_handle)
            .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?
        {
            KeyRecord::Ed25519(record) => Ok(record.signing_key.to_bytes()),
            KeyRecord::Secp256k1(_) => Err(WalletError::UnsupportedAlgorithm(
                "expected ed25519 key".to_string(),
            )),
        }
    }

    fn generate_secp256k1(&mut self) -> Result<KeyMaterialInfo> {
        self.import_secp256k1_secret(random_seed())
    }

    fn import_secp256k1_secret(&mut self, secret: [u8; 32]) -> Result<KeyMaterialInfo> {
        let key_handle = KeyHandle::generate();
        let signing_key = secp256k1_signing_key_from_secret(&secret)?;
        let info = secp256k1_key_material_info(&key_handle, &signing_key)?;
        self.keys.insert(
            key_handle,
            KeyRecord::Secp256k1(Secp256k1KeyRecord { signing_key }),
        );
        Ok(info)
    }

    fn export_secp256k1_secret(&self, key_handle: &KeyHandle) -> Result<[u8; 32]> {
        match self
            .keys
            .get(key_handle)
            .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?
        {
            KeyRecord::Secp256k1(record) => Ok(record.signing_key.to_bytes().into()),
            KeyRecord::Ed25519(_) => Err(WalletError::UnsupportedAlgorithm(
                "expected secp256k1 key".to_string(),
            )),
        }
    }

    fn sign_bytes(&self, key_handle: &KeyHandle, payload: &[u8]) -> Result<SignatureBytes> {
        sign_with_record(
            self.keys
                .get(key_handle)
                .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?,
            payload,
        )
    }

    fn verify_bytes(
        &self,
        key_handle: &KeyHandle,
        payload: &[u8],
        signature: &SignatureBytes,
    ) -> Result<()> {
        verify_with_record(
            self.keys
                .get(key_handle)
                .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?,
            payload,
            signature,
        )
    }

    fn public_key_info(&self, key_handle: &KeyHandle) -> Result<KeyMaterialInfo> {
        key_material_info_from_record(
            key_handle,
            self.keys
                .get(key_handle)
                .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?,
        )
    }

    fn list_handles(&self) -> Vec<KeyHandle> {
        self.keys.keys().cloned().collect()
    }
}

impl KeyStore for FileKeyStore {
    fn generate_ed25519(&mut self) -> Result<KeyMaterialInfo> {
        self.import_ed25519_seed(random_seed())
    }

    fn import_ed25519_seed(&mut self, seed: [u8; 32]) -> Result<KeyMaterialInfo> {
        let key_handle = KeyHandle::generate();
        let signing_key = Ed25519SigningKey::from_bytes(&seed);
        let info = ed25519_key_material_info(&key_handle, &signing_key)?;
        self.keys.insert(
            key_handle.clone(),
            KeyRecord::Ed25519(Ed25519KeyRecord { signing_key }),
        );
        self.flush()?;
        Ok(info)
    }

    fn export_ed25519_seed(&self, key_handle: &KeyHandle) -> Result<[u8; 32]> {
        match self
            .keys
            .get(key_handle)
            .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?
        {
            KeyRecord::Ed25519(record) => Ok(record.signing_key.to_bytes()),
            KeyRecord::Secp256k1(_) => Err(WalletError::UnsupportedAlgorithm(
                "expected ed25519 key".to_string(),
            )),
        }
    }

    fn generate_secp256k1(&mut self) -> Result<KeyMaterialInfo> {
        self.import_secp256k1_secret(random_seed())
    }

    fn import_secp256k1_secret(&mut self, secret: [u8; 32]) -> Result<KeyMaterialInfo> {
        let key_handle = KeyHandle::generate();
        let signing_key = secp256k1_signing_key_from_secret(&secret)?;
        let info = secp256k1_key_material_info(&key_handle, &signing_key)?;
        self.keys.insert(
            key_handle.clone(),
            KeyRecord::Secp256k1(Secp256k1KeyRecord { signing_key }),
        );
        self.flush()?;
        Ok(info)
    }

    fn export_secp256k1_secret(&self, key_handle: &KeyHandle) -> Result<[u8; 32]> {
        match self
            .keys
            .get(key_handle)
            .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?
        {
            KeyRecord::Secp256k1(record) => Ok(record.signing_key.to_bytes().into()),
            KeyRecord::Ed25519(_) => Err(WalletError::UnsupportedAlgorithm(
                "expected secp256k1 key".to_string(),
            )),
        }
    }

    fn sign_bytes(&self, key_handle: &KeyHandle, payload: &[u8]) -> Result<SignatureBytes> {
        sign_with_record(
            self.keys
                .get(key_handle)
                .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?,
            payload,
        )
    }

    fn verify_bytes(
        &self,
        key_handle: &KeyHandle,
        payload: &[u8],
        signature: &SignatureBytes,
    ) -> Result<()> {
        verify_with_record(
            self.keys
                .get(key_handle)
                .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?,
            payload,
            signature,
        )
    }

    fn public_key_info(&self, key_handle: &KeyHandle) -> Result<KeyMaterialInfo> {
        key_material_info_from_record(
            key_handle,
            self.keys
                .get(key_handle)
                .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?,
        )
    }

    fn list_handles(&self) -> Vec<KeyHandle> {
        self.keys.keys().cloned().collect()
    }
}

fn sign_with_record(record: &KeyRecord, payload: &[u8]) -> Result<SignatureBytes> {
    match record {
        KeyRecord::Ed25519(record) => Ok(SignatureBytes(
            record.signing_key.sign(payload).to_bytes().to_vec(),
        )),
        KeyRecord::Secp256k1(record) => {
            let signature: Secp256k1Signature = record.signing_key.sign(payload);
            Ok(SignatureBytes(signature.to_der().as_bytes().to_vec()))
        }
    }
}

fn verify_with_record(
    record: &KeyRecord,
    payload: &[u8],
    signature: &SignatureBytes,
) -> Result<()> {
    match record {
        KeyRecord::Ed25519(record) => {
            verify_with_ed25519_signing_key(&record.signing_key, payload, signature)
        }
        KeyRecord::Secp256k1(record) => {
            let signature = Secp256k1Signature::from_der(&signature.0)
                .map_err(|error| WalletError::InvalidSignature(error.to_string()))?;
            let verifying_key = Secp256k1VerifyingKey::from(&record.signing_key);
            verifying_key
                .verify(payload, &signature)
                .map_err(|error| WalletError::InvalidSignature(error.to_string()))
        }
    }
}

fn key_material_info_from_record(
    key_handle: &KeyHandle,
    record: &KeyRecord,
) -> Result<KeyMaterialInfo> {
    match record {
        KeyRecord::Ed25519(record) => ed25519_key_material_info(key_handle, &record.signing_key),
        KeyRecord::Secp256k1(record) => {
            secp256k1_key_material_info(key_handle, &record.signing_key)
        }
    }
}

fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    seed
}

fn ed25519_key_material_info(
    key_handle: &KeyHandle,
    signing_key: &Ed25519SigningKey,
) -> Result<KeyMaterialInfo> {
    let public_key_multibase = encode_ed25519_multibase(signing_key.verifying_key().as_bytes());
    let did = Did::parse(&format!("did:key:{public_key_multibase}"))?;
    let public_key_jwk = Some(JsonWebKey::from_public_key(&JwkPublicKey::Ed25519(
        *signing_key.verifying_key().as_bytes(),
    )));
    Ok(KeyMaterialInfo {
        key_handle: key_handle.clone(),
        did,
        algorithm: SigningAlgorithm::Ed25519,
        public_key_multibase,
        public_key_jwk,
        derived_address: None,
    })
}

fn secp256k1_key_material_info(
    key_handle: &KeyHandle,
    signing_key: &Secp256k1SigningKey,
) -> Result<KeyMaterialInfo> {
    let verifying_key = Secp256k1VerifyingKey::from(signing_key);
    let compressed = verifying_key.to_encoded_point(true);
    let public_key_multibase = encode_secp256k1_multibase(compressed.as_bytes());
    let did = Did::parse(&format!("did:key:{public_key_multibase}"))?;
    Ok(KeyMaterialInfo {
        key_handle: key_handle.clone(),
        did,
        algorithm: SigningAlgorithm::Secp256k1,
        public_key_multibase,
        public_key_jwk: None,
        derived_address: Some(evm_address_from_verifying_key(&verifying_key)),
    })
}

fn encode_ed25519_multibase(public_key: &[u8; 32]) -> String {
    let mut bytes = Vec::from(ED25519_PUBLIC_KEY_MULTICODEC_PREFIX);
    bytes.extend_from_slice(public_key);
    format!("z{}", bs58::encode(bytes).into_string())
}

fn encode_secp256k1_multibase(public_key: &[u8]) -> String {
    let mut bytes = Vec::from(SECP256K1_PUBLIC_KEY_MULTICODEC_PREFIX);
    bytes.extend_from_slice(public_key);
    format!("z{}", bs58::encode(bytes).into_string())
}

fn verify_with_ed25519_signing_key(
    signing_key: &Ed25519SigningKey,
    payload: &[u8],
    signature: &SignatureBytes,
) -> Result<()> {
    let signature = Ed25519Signature::from_slice(&signature.0)
        .map_err(|error| WalletError::InvalidSignature(error.to_string()))?;
    let verifying_key: Ed25519VerifyingKey = signing_key.verifying_key();
    verifying_key
        .verify(payload, &signature)
        .map_err(|error| WalletError::InvalidSignature(error.to_string()))
}

fn decode_secret_key(secret_key_b64: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD
        .decode(secret_key_b64)
        .map_err(|error| WalletError::InvalidSecretKey(error.to_string()))?;
    if bytes.len() != 32 {
        return Err(WalletError::InvalidSecretKey(format!(
            "expected 32-byte secret, got {} bytes",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn secp256k1_signing_key_from_secret(secret: &[u8; 32]) -> Result<Secp256k1SigningKey> {
    Secp256k1SigningKey::from_bytes(secret.into())
        .map_err(|error| WalletError::InvalidSecretKey(error.to_string()))
}

fn evm_address_from_verifying_key(verifying_key: &Secp256k1VerifyingKey) -> String {
    let encoded = verifying_key.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    let mut hasher = Keccak256::new();
    hasher.update(&bytes[1..]);
    let digest = hasher.finalize();
    format!("0x{}", hex::encode(&digest[12..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_keystore_generates_ed25519_and_verifies() {
        let mut store = InMemoryKeyStore::new();
        let info = store.generate_ed25519().unwrap();
        let payload = b"hello watt";
        let signature = store.sign_bytes(&info.key_handle, payload).unwrap();
        store
            .verify_bytes(&info.key_handle, payload, &signature)
            .unwrap();
        assert_eq!(info.did.method(), "key");
        assert_eq!(info.algorithm, SigningAlgorithm::Ed25519);
    }

    #[test]
    fn in_memory_keystore_generates_secp256k1_with_evm_address() {
        let mut store = InMemoryKeyStore::new();
        let info = store.generate_secp256k1().unwrap();
        let payload = b"hello evm";
        let signature = store.sign_bytes(&info.key_handle, payload).unwrap();
        store
            .verify_bytes(&info.key_handle, payload, &signature)
            .unwrap();
        assert_eq!(info.algorithm, SigningAlgorithm::Secp256k1);
        assert!(
            info.derived_address
                .as_deref()
                .is_some_and(|value| value.starts_with("0x"))
        );
    }

    #[test]
    fn file_keystore_round_trips_multiple_key_algorithms() {
        let unique = uuid::Uuid::new_v4();
        let path = std::env::temp_dir().join(format!("watt-wallet-keystore-{unique}.json"));
        let mut store = FileKeyStore::open(&path).unwrap();
        let ed = store.generate_ed25519().unwrap();
        let evm = store.generate_secp256k1().unwrap();
        let payload = b"hello watt";
        let signature = store.sign_bytes(&evm.key_handle, payload).unwrap();
        drop(store);

        let reopened = FileKeyStore::open(&path).unwrap();
        reopened
            .verify_bytes(&evm.key_handle, payload, &signature)
            .unwrap();
        let exported_seed = reopened.export_ed25519_seed(&ed.key_handle).unwrap();
        let exported_secret = reopened.export_secp256k1_secret(&evm.key_handle).unwrap();
        assert_eq!(exported_seed.len(), 32);
        assert_eq!(exported_secret.len(), 32);
        let _ = fs::remove_file(path);
    }
}
