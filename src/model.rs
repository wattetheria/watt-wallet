use serde::{Deserialize, Serialize};
use uuid::Uuid;
use watt_did::Did;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyHandle(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SigningAlgorithm {
    #[default]
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerPurpose {
    Authentication,
    AssertionMethod,
    CapabilityInvocation,
    CapabilityDelegation,
    General,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStatus {
    #[default]
    Active,
    Disabled,
    Rotated,
    Archived,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalIdentity {
    pub identity_id: String,
    pub did: Did,
    pub key_handle: KeyHandle,
    pub algorithm: SigningAlgorithm,
    #[serde(default)]
    pub purposes: Vec<SignerPurpose>,
    pub status: IdentityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub created_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_from: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletProfileMetadata {
    pub profile_id: String,
    #[serde(default)]
    pub identities: Vec<LocalIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_identity_id: Option<String>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerCapabilityMetadata {
    pub identity_id: String,
    pub did: Did,
    pub key_handle: KeyHandle,
    pub algorithm: SigningAlgorithm,
    #[serde(default)]
    pub purposes: Vec<SignerPurpose>,
    pub status: IdentityStatus,
}

impl KeyHandle {
    pub fn generate() -> Self {
        Self(format!("key-{}", Uuid::new_v4()))
    }
}

impl LocalIdentity {
    pub fn new(
        did: Did,
        key_handle: KeyHandle,
        algorithm: SigningAlgorithm,
        purposes: Vec<SignerPurpose>,
        label: Option<String>,
        created_at_ms: u64,
    ) -> Self {
        Self {
            identity_id: format!("identity-{}", Uuid::new_v4()),
            did,
            key_handle,
            algorithm,
            purposes,
            status: IdentityStatus::Active,
            label,
            created_at_ms,
            rotated_from: None,
        }
    }

    pub fn signer_metadata(&self) -> SignerCapabilityMetadata {
        SignerCapabilityMetadata {
            identity_id: self.identity_id.clone(),
            did: self.did.clone(),
            key_handle: self.key_handle.clone(),
            algorithm: self.algorithm,
            purposes: self.purposes.clone(),
            status: self.status,
        }
    }
}

impl WalletProfileMetadata {
    pub fn new(profile_id: impl Into<String>, now_ms: u64) -> Self {
        Self {
            profile_id: profile_id.into(),
            identities: vec![],
            active_identity_id: None,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        }
    }

    pub fn add_identity(&mut self, identity: LocalIdentity) {
        if self.active_identity_id.is_none() {
            self.active_identity_id = Some(identity.identity_id.clone());
        }
        self.identities.push(identity);
    }

    pub fn identity(&self, identity_id: &str) -> Option<&LocalIdentity> {
        self.identities
            .iter()
            .find(|identity| identity.identity_id == identity_id)
    }

    pub fn identity_mut(&mut self, identity_id: &str) -> Option<&mut LocalIdentity> {
        self.identities
            .iter_mut()
            .find(|identity| identity.identity_id == identity_id)
    }

    pub fn active_identity(&self) -> Option<&LocalIdentity> {
        self.active_identity_id
            .as_deref()
            .and_then(|identity_id| self.identity(identity_id))
    }

    pub fn set_active_identity(&mut self, identity_id: &str, now_ms: u64) -> bool {
        if self.identity(identity_id).is_some() {
            self.active_identity_id = Some(identity_id.to_owned());
            self.updated_at_ms = now_ms;
            true
        } else {
            false
        }
    }

    pub fn rotate_identity(
        &mut self,
        from_identity_id: &str,
        mut replacement: LocalIdentity,
        now_ms: u64,
    ) -> bool {
        if let Some(previous) = self.identity_mut(from_identity_id) {
            previous.status = IdentityStatus::Rotated;
            replacement.rotated_from = Some(previous.identity_id.clone());
            self.add_identity(replacement.clone());
            self.active_identity_id = Some(replacement.identity_id);
            self.updated_at_ms = now_ms;
            true
        } else {
            false
        }
    }

    pub fn export_json(&self) -> crate::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn import_json(json: &str) -> crate::Result<Self> {
        Ok(serde_json::from_str(json)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_tracks_active_identity() {
        let did = Did::parse("did:web:example.com:agents:alice").unwrap();
        let identity = LocalIdentity::new(
            did,
            KeyHandle::generate(),
            SigningAlgorithm::Ed25519,
            vec![SignerPurpose::General],
            Some("alice".into()),
            1,
        );
        let identity_id = identity.identity_id.clone();
        let mut profile = WalletProfileMetadata::new("default", 1);
        profile.add_identity(identity);
        assert_eq!(
            profile.active_identity_id.as_deref(),
            Some(identity_id.as_str())
        );
    }
}
