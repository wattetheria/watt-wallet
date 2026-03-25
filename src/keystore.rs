use crate::error::{Result, WalletError};
use crate::model::{KeyHandle, SigningAlgorithm};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use watt_did::{Did, JsonWebKey, JwkPublicKey};

const ED25519_PUBLIC_KEY_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBytes(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMaterialInfo {
    pub key_handle: KeyHandle,
    pub did: Did,
    pub algorithm: SigningAlgorithm,
    pub public_key_multibase: String,
    pub public_key_jwk: JsonWebKey,
}

pub trait KeyStore {
    fn generate_ed25519(&mut self) -> Result<KeyMaterialInfo>;
    fn import_ed25519_seed(&mut self, seed: [u8; 32]) -> Result<KeyMaterialInfo>;
    fn export_ed25519_seed(&self, key_handle: &KeyHandle) -> Result<[u8; 32]>;
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
    keys: HashMap<KeyHandle, Ed25519KeyRecord>,
}

#[derive(Debug, Clone)]
pub struct FileKeyStore {
    path: PathBuf,
    keys: HashMap<KeyHandle, Ed25519KeyRecord>,
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
struct Ed25519KeyRecord {
    signing_key: SigningKey,
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
                    let seed = decode_seed(&entry.secret_key_b64)?;
                    Ok((
                        entry.key_handle,
                        Ed25519KeyRecord {
                            signing_key: SigningKey::from_bytes(&seed),
                        },
                    ))
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
                .map(|(key_handle, record)| PersistedKeyRecord {
                    key_handle: key_handle.clone(),
                    algorithm: SigningAlgorithm::Ed25519,
                    secret_key_b64: STANDARD.encode(record.signing_key.to_bytes()),
                })
                .collect(),
        };
        fs::write(&self.path, serde_json::to_vec_pretty(&persisted)?)?;
        Ok(())
    }
}

impl KeyStore for InMemoryKeyStore {
    fn generate_ed25519(&mut self) -> Result<KeyMaterialInfo> {
        let seed = random_seed();
        self.import_ed25519_seed(seed)
    }

    fn import_ed25519_seed(&mut self, seed: [u8; 32]) -> Result<KeyMaterialInfo> {
        let key_handle = KeyHandle::generate();
        let signing_key = SigningKey::from_bytes(&seed);
        let info = key_material_info(&key_handle, &signing_key)?;
        self.keys
            .insert(key_handle, Ed25519KeyRecord { signing_key });
        Ok(info)
    }

    fn export_ed25519_seed(&self, key_handle: &KeyHandle) -> Result<[u8; 32]> {
        let record = self
            .keys
            .get(key_handle)
            .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?;
        Ok(record.signing_key.to_bytes())
    }

    fn sign_bytes(&self, key_handle: &KeyHandle, payload: &[u8]) -> Result<SignatureBytes> {
        let record = self
            .keys
            .get(key_handle)
            .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?;
        Ok(SignatureBytes(
            record.signing_key.sign(payload).to_bytes().to_vec(),
        ))
    }

    fn verify_bytes(
        &self,
        key_handle: &KeyHandle,
        payload: &[u8],
        signature: &SignatureBytes,
    ) -> Result<()> {
        let record = self
            .keys
            .get(key_handle)
            .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?;
        verify_with_signing_key(&record.signing_key, payload, signature)
    }

    fn public_key_info(&self, key_handle: &KeyHandle) -> Result<KeyMaterialInfo> {
        let record = self
            .keys
            .get(key_handle)
            .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?;
        key_material_info(key_handle, &record.signing_key)
    }

    fn list_handles(&self) -> Vec<KeyHandle> {
        self.keys.keys().cloned().collect()
    }
}

impl KeyStore for FileKeyStore {
    fn generate_ed25519(&mut self) -> Result<KeyMaterialInfo> {
        let seed = random_seed();
        self.import_ed25519_seed(seed)
    }

    fn import_ed25519_seed(&mut self, seed: [u8; 32]) -> Result<KeyMaterialInfo> {
        let key_handle = KeyHandle::generate();
        let signing_key = SigningKey::from_bytes(&seed);
        let info = key_material_info(&key_handle, &signing_key)?;
        self.keys
            .insert(key_handle.clone(), Ed25519KeyRecord { signing_key });
        self.flush()?;
        Ok(info)
    }

    fn export_ed25519_seed(&self, key_handle: &KeyHandle) -> Result<[u8; 32]> {
        let record = self
            .keys
            .get(key_handle)
            .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?;
        Ok(record.signing_key.to_bytes())
    }

    fn sign_bytes(&self, key_handle: &KeyHandle, payload: &[u8]) -> Result<SignatureBytes> {
        let record = self
            .keys
            .get(key_handle)
            .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?;
        Ok(SignatureBytes(
            record.signing_key.sign(payload).to_bytes().to_vec(),
        ))
    }

    fn verify_bytes(
        &self,
        key_handle: &KeyHandle,
        payload: &[u8],
        signature: &SignatureBytes,
    ) -> Result<()> {
        let record = self
            .keys
            .get(key_handle)
            .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?;
        verify_with_signing_key(&record.signing_key, payload, signature)
    }

    fn public_key_info(&self, key_handle: &KeyHandle) -> Result<KeyMaterialInfo> {
        let record = self
            .keys
            .get(key_handle)
            .ok_or_else(|| WalletError::UnknownKeyHandle(key_handle.0.clone()))?;
        key_material_info(key_handle, &record.signing_key)
    }

    fn list_handles(&self) -> Vec<KeyHandle> {
        self.keys.keys().cloned().collect()
    }
}

fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    seed
}

fn key_material_info(key_handle: &KeyHandle, signing_key: &SigningKey) -> Result<KeyMaterialInfo> {
    let public_key_multibase = encode_ed25519_multibase(signing_key.verifying_key().as_bytes());
    let did = Did::parse(&format!("did:key:{public_key_multibase}"))?;
    let public_key_jwk = JsonWebKey::from_public_key(&JwkPublicKey::Ed25519(
        *signing_key.verifying_key().as_bytes(),
    ));
    Ok(KeyMaterialInfo {
        key_handle: key_handle.clone(),
        did,
        algorithm: SigningAlgorithm::Ed25519,
        public_key_multibase,
        public_key_jwk,
    })
}

fn encode_ed25519_multibase(public_key: &[u8; 32]) -> String {
    let mut bytes = Vec::from(ED25519_PUBLIC_KEY_MULTICODEC_PREFIX);
    bytes.extend_from_slice(public_key);
    format!("z{}", bs58::encode(bytes).into_string())
}

fn verify_with_signing_key(
    signing_key: &SigningKey,
    payload: &[u8],
    signature: &SignatureBytes,
) -> Result<()> {
    let signature = Signature::from_slice(&signature.0)
        .map_err(|error| WalletError::InvalidSignature(error.to_string()))?;
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    verifying_key
        .verify(payload, &signature)
        .map_err(|error| WalletError::InvalidSignature(error.to_string()))
}

fn decode_seed(secret_key_b64: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD
        .decode(secret_key_b64)
        .map_err(|error| WalletError::InvalidSecretKey(error.to_string()))?;
    if bytes.len() != 32 {
        return Err(WalletError::InvalidSecretKey(format!(
            "expected 32-byte seed, got {} bytes",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_keystore_generates_signs_and_verifies() {
        let mut store = InMemoryKeyStore::new();
        let info = store.generate_ed25519().unwrap();
        let payload = b"hello watt";
        let signature = store.sign_bytes(&info.key_handle, payload).unwrap();
        store
            .verify_bytes(&info.key_handle, payload, &signature)
            .unwrap();
        assert_eq!(info.did.method(), "key");
    }

    #[test]
    fn file_keystore_round_trips() {
        let unique = uuid::Uuid::new_v4();
        let path = std::env::temp_dir().join(format!("watt-wallet-keystore-{unique}.json"));
        let mut store = FileKeyStore::open(&path).unwrap();
        let info = store.generate_ed25519().unwrap();
        let payload = b"hello watt";
        let signature = store.sign_bytes(&info.key_handle, payload).unwrap();
        drop(store);

        let reopened = FileKeyStore::open(&path).unwrap();
        reopened
            .verify_bytes(&info.key_handle, payload, &signature)
            .unwrap();
        let exported_seed = reopened.export_ed25519_seed(&info.key_handle).unwrap();
        assert_eq!(exported_seed.len(), 32);
        let _ = fs::remove_file(path);
    }
}
