use crate::error::{Result, WalletError};
use crate::keystore::{KeyStore, SignatureBytes};
use crate::model::KeyHandle;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use watt_did::{Did, ProofAlgorithm, ProofEnvelope, UcanCapability};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityTokenClaims {
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub aud: Vec<String>,
    pub iat: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(default)]
    pub capabilities: Vec<UcanCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityTokenOptions {
    pub issuer_did: Did,
    pub subject: String,
    pub audience: Vec<String>,
    pub issued_at_ms: u64,
    pub not_before_ms: Option<u64>,
    pub expires_at_ms: Option<u64>,
    pub capabilities: Vec<UcanCapability>,
    pub verification_method: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityToken {
    pub token: String,
    pub claims: CapabilityTokenClaims,
    pub proof: ProofEnvelope,
}

pub fn sign_capability_token<K: KeyStore>(
    keystore: &K,
    key_handle: &KeyHandle,
    options: CapabilityTokenOptions,
) -> Result<CapabilityToken> {
    let claims = CapabilityTokenClaims {
        iss: options.issuer_did.to_string(),
        sub: options.subject,
        aud: options.audience,
        iat: options.issued_at_ms,
        nbf: options.not_before_ms,
        exp: options.expires_at_ms,
        capabilities: options.capabilities,
    };
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": options.verification_method.clone(),
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature: SignatureBytes = keystore.sign_bytes(key_handle, signing_input.as_bytes())?;
    let token = format!(
        "{header_b64}.{payload_b64}.{}",
        URL_SAFE_NO_PAD.encode(signature.0)
    );
    Ok(CapabilityToken {
        token: token.clone(),
        claims,
        proof: ProofEnvelope {
            algorithm: ProofAlgorithm::Jwt,
            value: token,
            verification_method: options.verification_method,
            challenge: None,
            nonce: None,
            created_at: None,
            expires_at: None,
        },
    })
}

pub fn sign_payload_json<K: KeyStore, T: Serialize>(
    keystore: &K,
    key_handle: &KeyHandle,
    payload: &T,
) -> Result<SignatureBytes> {
    let bytes = serde_json::to_vec(payload)?;
    keystore.sign_bytes(key_handle, &bytes)
}

pub fn verify_payload_json<K: KeyStore, T: Serialize>(
    keystore: &K,
    key_handle: &KeyHandle,
    payload: &T,
    signature: &SignatureBytes,
) -> Result<()> {
    let bytes = serde_json::to_vec(payload)?;
    keystore.verify_bytes(key_handle, &bytes, signature)
}

pub fn require_capabilities_present(claims: &CapabilityTokenClaims) -> Result<()> {
    if claims.capabilities.is_empty() {
        return Err(WalletError::Metadata(
            "capability token must include at least one capability".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::InMemoryKeyStore;
    use crate::keystore::KeyStore;
    use watt_did::proof::ProofVerifier;
    use watt_did::{CompactJoseEdDsaVerifier, DidKey, JoseValidationOptions};

    #[test]
    fn capability_token_signing_produces_compact_jwt() {
        let mut keystore = InMemoryKeyStore::new();
        let info = keystore.generate_ed25519().unwrap();
        let token = sign_capability_token(
            &keystore,
            &info.key_handle,
            CapabilityTokenOptions {
                issuer_did: info.did.clone(),
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
                verification_method: None,
            },
        )
        .unwrap();
        assert_eq!(token.token.split('.').count(), 3);
        assert_eq!(token.proof.algorithm, ProofAlgorithm::Jwt);
    }

    #[test]
    fn capability_token_can_be_verified_by_watt_did() {
        let mut keystore = InMemoryKeyStore::new();
        let info = keystore.generate_ed25519().unwrap();
        let token = sign_capability_token(
            &keystore,
            &info.key_handle,
            CapabilityTokenOptions {
                issuer_did: info.did.clone(),
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
                verification_method: None,
            },
        )
        .unwrap();

        let document = DidKey::from_did(info.did.clone())
            .unwrap()
            .to_document()
            .unwrap();
        let verifier = CompactJoseEdDsaVerifier::new(JoseValidationOptions {
            expected_issuer: Some(info.did.to_string()),
            expected_subject: Some("agent-1".into()),
            expected_audience: vec!["wattetheria".into()],
            current_time_ms: Some(150),
            require_exp: true,
            require_sub: true,
        });

        verifier.verify(&token.proof, &info.did, &document).unwrap();
    }
}
