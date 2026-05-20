use crate::error::{Result, WalletError};
use crate::keystore::{
    KeyStore, SignatureBytes, evm_address_from_secp256k1_multibase_public_key,
    verify_ed25519_with_multibase_public_key, verify_secp256k1_with_multibase_public_key,
};
use crate::model::KeyHandle;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use serde_json::Value;
use watt_did::{
    Did, DidError, PaymentAccountBindingProof, PaymentAccountBindingVerifier,
    PaymentAccountCustody, ProofAlgorithm, ProofEnvelope,
};

/// Fields that go into the canonical challenge bytes both signers sign.
///
/// The struct's field order is the canonical order: JCS canonicalises by key
/// alphabetically, so the bytes are independent of in-memory layout. This is
/// the contract: any party that wants to verify must produce these exact
/// bytes from the proof fields.
#[derive(Debug, Serialize)]
struct CanonicalBindingChallenge<'a> {
    agent_did: &'a str,
    can_sign: bool,
    capabilities: &'a [String],
    custody: &'a PaymentAccountCustody,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at_ms: Option<u64>,
    issued_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    payment_address: &'a str,
    rail: &'a str,
    receive_only: bool,
}

#[derive(Debug, Clone, Copy)]
struct BindingChallengeInput<'a> {
    agent_did: &'a Did,
    payment_address: &'a str,
    rail: &'a str,
    network: Option<&'a str>,
    custody: &'a PaymentAccountCustody,
    receive_only: bool,
    can_sign: bool,
    capabilities: &'a [String],
    issued_at_ms: u64,
    expires_at_ms: Option<u64>,
    nonce: Option<&'a str>,
}

/// Parameters needed to mint a [`PaymentAccountBindingProof`].
///
/// Keep this generic over the keystore so callers can use either
/// [`crate::InMemoryKeyStore`] or [`crate::FileKeyStore`].
#[derive(Debug)]
pub struct PaymentAccountBindingProofOptions<'a> {
    pub agent_did: Did,
    pub agent_key_handle: &'a KeyHandle,
    /// Multibase-encoded ed25519 public key bound to `agent_did`.
    pub agent_public_key_multibase: String,
    pub rail: String,
    pub network: Option<String>,
    pub custody: PaymentAccountCustody,
    pub receive_only: bool,
    pub can_sign: bool,
    pub capabilities: Vec<String>,
    pub issued_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub nonce: Option<String>,
    /// Spending-capable accounts must provide both the signer handle and the
    /// matching secp256k1 multibase public key. Watch-only accounts pass
    /// `None` here and the resulting proof has no `payment_account_proof`.
    pub payment_signer: Option<PaymentAccountSigner<'a>>,
    /// Watch-only accounts must still declare the EVM address they observe.
    /// For spending-capable accounts this is ignored and derived from the
    /// signer's public key to avoid the binding lying about which address it
    /// can sign for.
    pub watch_only_payment_address: Option<String>,
}

#[derive(Debug)]
pub struct PaymentAccountSigner<'a> {
    pub key_handle: &'a KeyHandle,
    /// Multibase-encoded secp256k1 public key for the signing key.
    pub public_key_multibase: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WalletPaymentAccountBindingVerifier;

impl PaymentAccountBindingVerifier for WalletPaymentAccountBindingVerifier {
    fn verify_payment_account_binding(
        &self,
        proof: &PaymentAccountBindingProof,
    ) -> watt_did::Result<()> {
        verify_payment_account_binding_proof(proof).map_err(|error| {
            DidError::VerificationFailed(format!(
                "payment account binding verification failed: {error}"
            ))
        })
    }
}

pub fn build_payment_account_binding_proof<K: KeyStore>(
    keystore: &K,
    options: PaymentAccountBindingProofOptions<'_>,
) -> Result<PaymentAccountBindingProof> {
    let payment_address = resolve_payment_address(&options)?;
    let challenge_bytes = canonical_binding_challenge(BindingChallengeInput {
        agent_did: &options.agent_did,
        payment_address: &payment_address,
        rail: &options.rail,
        network: options.network.as_deref(),
        custody: &options.custody,
        receive_only: options.receive_only,
        can_sign: options.can_sign,
        capabilities: &options.capabilities,
        issued_at_ms: options.issued_at_ms,
        expires_at_ms: options.expires_at_ms,
        nonce: options.nonce.as_deref(),
    })?;
    let challenge_string = String::from_utf8(challenge_bytes.clone()).map_err(|error| {
        WalletError::Metadata(format!(
            "canonical binding challenge not valid utf-8: {error}"
        ))
    })?;
    let agent_signature = keystore.sign_bytes(options.agent_key_handle, &challenge_bytes)?;
    let agent_proof = ProofEnvelope {
        algorithm: ProofAlgorithm::Custom("ed25519-binding".to_owned()),
        value: STANDARD.encode(&agent_signature.0),
        verification_method: Some(options.agent_public_key_multibase),
        challenge: Some(challenge_string.clone()),
        nonce: options.nonce.clone(),
        created_at: None,
        expires_at: None,
    };
    let payment_account_proof = match options.payment_signer.as_ref() {
        Some(signer) => {
            let signature = keystore.sign_bytes(signer.key_handle, &challenge_bytes)?;
            Some(ProofEnvelope {
                algorithm: ProofAlgorithm::Custom("secp256k1-binding".to_owned()),
                value: STANDARD.encode(&signature.0),
                verification_method: Some(signer.public_key_multibase.clone()),
                challenge: Some(challenge_string),
                nonce: options.nonce.clone(),
                created_at: None,
                expires_at: None,
            })
        }
        None => None,
    };
    let proof = PaymentAccountBindingProof {
        agent_did: options.agent_did,
        payment_address,
        rail: options.rail,
        network: options.network,
        custody: options.custody,
        receive_only: options.receive_only,
        can_sign: options.can_sign,
        capabilities: options.capabilities,
        issued_at_ms: options.issued_at_ms,
        expires_at_ms: options.expires_at_ms,
        nonce: options.nonce,
        agent_proof,
        payment_account_proof,
    };
    proof
        .validate_basic()
        .map_err(|error| WalletError::Metadata(error.to_string()))?;
    Ok(proof)
}

pub fn verify_payment_account_binding_proof(proof: &PaymentAccountBindingProof) -> Result<()> {
    proof
        .validate_basic()
        .map_err(|error| WalletError::Metadata(error.to_string()))?;
    let challenge_bytes = canonical_binding_challenge(BindingChallengeInput {
        agent_did: &proof.agent_did,
        payment_address: &proof.payment_address,
        rail: &proof.rail,
        network: proof.network.as_deref(),
        custody: &proof.custody,
        receive_only: proof.receive_only,
        can_sign: proof.can_sign,
        capabilities: &proof.capabilities,
        issued_at_ms: proof.issued_at_ms,
        expires_at_ms: proof.expires_at_ms,
        nonce: proof.nonce.as_deref(),
    })?;
    let challenge_string = std::str::from_utf8(&challenge_bytes).map_err(|error| {
        WalletError::Metadata(format!(
            "canonical binding challenge not valid utf-8: {error}"
        ))
    })?;
    let agent_public_key = proof
        .agent_proof
        .verification_method
        .as_deref()
        .ok_or_else(|| {
            WalletError::Metadata(
                "agent_proof.verification_method is required to verify binding".to_string(),
            )
        })?;
    if let Some(challenge) = proof.agent_proof.challenge.as_deref()
        && challenge != challenge_string
    {
        return Err(WalletError::InvalidSignature(
            "agent_proof.challenge does not match canonical binding challenge".to_string(),
        ));
    }
    let agent_signature = decode_base64_signature(&proof.agent_proof.value, "agent_proof.value")?;
    verify_ed25519_with_multibase_public_key(agent_public_key, &challenge_bytes, &agent_signature)?;

    match proof.payment_account_proof.as_ref() {
        Some(payment_account_proof) => {
            let payment_public_key = payment_account_proof
                .verification_method
                .as_deref()
                .ok_or_else(|| {
                    WalletError::Metadata(
                        "payment_account_proof.verification_method is required to verify binding"
                            .to_string(),
                    )
                })?;
            let derived_address =
                evm_address_from_secp256k1_multibase_public_key(payment_public_key)?;
            if !addresses_equal(&derived_address, &proof.payment_address) {
                return Err(WalletError::InvalidSignature(format!(
                    "payment_account_proof public key derives {derived_address} but proof claims {}",
                    proof.payment_address
                )));
            }
            if let Some(challenge) = payment_account_proof.challenge.as_deref()
                && challenge != challenge_string
            {
                return Err(WalletError::InvalidSignature(
                    "payment_account_proof.challenge does not match canonical binding challenge"
                        .to_string(),
                ));
            }
            let payment_signature = decode_base64_signature(
                &payment_account_proof.value,
                "payment_account_proof.value",
            )?;
            verify_secp256k1_with_multibase_public_key(
                payment_public_key,
                &challenge_bytes,
                &payment_signature,
            )?;
            Ok(())
        }
        None => {
            // Watch-only accounts intentionally have no payment_account_proof
            // and rely on the agent's attestation alone. validate_basic above
            // already enforced that this combination is only valid for
            // watch-only custody.
            Ok(())
        }
    }
}

fn resolve_payment_address(options: &PaymentAccountBindingProofOptions<'_>) -> Result<String> {
    match options.payment_signer.as_ref() {
        Some(signer) => {
            evm_address_from_secp256k1_multibase_public_key(&signer.public_key_multibase)
        }
        None => options.watch_only_payment_address.clone().ok_or_else(|| {
            WalletError::Metadata(
                "watch_only_payment_address is required when payment_signer is absent".to_string(),
            )
        }),
    }
}

fn canonical_binding_challenge(input: BindingChallengeInput<'_>) -> Result<Vec<u8>> {
    let agent_did_string = input.agent_did.to_string();
    let challenge = CanonicalBindingChallenge {
        agent_did: &agent_did_string,
        can_sign: input.can_sign,
        capabilities: input.capabilities,
        custody: input.custody,
        expires_at_ms: input.expires_at_ms,
        issued_at_ms: input.issued_at_ms,
        network: input.network,
        nonce: input.nonce,
        payment_address: input.payment_address,
        rail: input.rail,
        receive_only: input.receive_only,
    };
    let value: Value = serde_json::to_value(&challenge)?;
    serde_jcs::to_string(&value)
        .map(String::into_bytes)
        .map_err(|error| {
            WalletError::Metadata(format!("canonicalize binding challenge failed: {error}"))
        })
}

fn decode_base64_signature(value: &str, field: &str) -> Result<SignatureBytes> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|error| WalletError::InvalidSignature(format!("{field}: {error}")))?;
    Ok(SignatureBytes(bytes))
}

fn addresses_equal(left: &str, right: &str) -> bool {
    let left = left.trim_start_matches("0x").to_ascii_lowercase();
    let right = right.trim_start_matches("0x").to_ascii_lowercase();
    left == right
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::{InMemoryKeyStore, KeyStore};

    fn fresh_signers() -> (
        InMemoryKeyStore,
        crate::keystore::KeyMaterialInfo,
        crate::keystore::KeyMaterialInfo,
    ) {
        let mut keystore = InMemoryKeyStore::new();
        let agent_info = keystore.generate_ed25519().expect("ed25519 key");
        let payment_info = keystore.generate_secp256k1().expect("secp256k1 key");
        (keystore, agent_info, payment_info)
    }

    fn build_options<'a>(
        agent_info: &'a crate::keystore::KeyMaterialInfo,
        payment_info: &'a crate::keystore::KeyMaterialInfo,
    ) -> PaymentAccountBindingProofOptions<'a> {
        PaymentAccountBindingProofOptions {
            agent_did: agent_info.did.clone(),
            agent_key_handle: &agent_info.key_handle,
            agent_public_key_multibase: agent_info.public_key_multibase.clone(),
            rail: "x402".to_owned(),
            network: Some("base-sepolia".to_owned()),
            custody: PaymentAccountCustody::LocalGenerated,
            receive_only: false,
            can_sign: true,
            capabilities: vec!["payment.authorize".to_owned(), "payment.submit".to_owned()],
            issued_at_ms: 1_716_120_000_000,
            expires_at_ms: Some(1_716_220_000_000),
            nonce: Some("nonce-1".to_owned()),
            payment_signer: Some(PaymentAccountSigner {
                key_handle: &payment_info.key_handle,
                public_key_multibase: payment_info.public_key_multibase.clone(),
            }),
            watch_only_payment_address: None,
        }
    }

    #[test]
    fn spending_capable_roundtrip_succeeds() {
        let (keystore, agent_info, payment_info) = fresh_signers();
        let proof = build_payment_account_binding_proof(
            &keystore,
            build_options(&agent_info, &payment_info),
        )
        .expect("build proof");
        assert_eq!(proof.agent_did, agent_info.did);
        assert!(proof.payment_account_proof.is_some());
        verify_payment_account_binding_proof(&proof).expect("verify proof");
    }

    #[test]
    fn wallet_payment_account_binding_verifier_implements_did_trait() {
        let (keystore, agent_info, payment_info) = fresh_signers();
        let proof = build_payment_account_binding_proof(
            &keystore,
            build_options(&agent_info, &payment_info),
        )
        .expect("build proof");
        let verifier = WalletPaymentAccountBindingVerifier;

        verifier
            .verify_payment_account_binding(&proof)
            .expect("verify proof through watt-did trait");
    }

    #[test]
    fn payment_address_is_derived_from_signer_pubkey() {
        let (keystore, agent_info, payment_info) = fresh_signers();
        let proof = build_payment_account_binding_proof(
            &keystore,
            build_options(&agent_info, &payment_info),
        )
        .expect("build proof");
        let expected =
            evm_address_from_secp256k1_multibase_public_key(&payment_info.public_key_multibase)
                .expect("derive");
        assert!(
            addresses_equal(&proof.payment_address, &expected),
            "expected {expected}, got {}",
            proof.payment_address
        );
    }

    #[test]
    fn watch_only_roundtrip_succeeds_without_payment_account_proof() {
        let (mut keystore, _, _) = fresh_signers();
        let agent_info = keystore.generate_ed25519().expect("ed25519 key");
        let observed = "0x122F8Fcaf2152420445Aa424E1D8C0306935B5c9";
        let options = PaymentAccountBindingProofOptions {
            agent_did: agent_info.did.clone(),
            agent_key_handle: &agent_info.key_handle,
            agent_public_key_multibase: agent_info.public_key_multibase.clone(),
            rail: "x402".to_owned(),
            network: Some("base-sepolia".to_owned()),
            custody: PaymentAccountCustody::WatchOnly,
            receive_only: true,
            can_sign: false,
            capabilities: vec!["payment.observe".to_owned()],
            issued_at_ms: 1_716_120_000_000,
            expires_at_ms: None,
            nonce: None,
            payment_signer: None,
            watch_only_payment_address: Some(observed.to_owned()),
        };
        let proof = build_payment_account_binding_proof(&keystore, options).expect("build proof");
        assert!(proof.payment_account_proof.is_none());
        assert_eq!(proof.payment_address, observed);
        verify_payment_account_binding_proof(&proof).expect("verify watch-only proof");
    }

    #[test]
    fn tampered_payment_address_fails_verification() {
        let (keystore, agent_info, payment_info) = fresh_signers();
        let mut proof = build_payment_account_binding_proof(
            &keystore,
            build_options(&agent_info, &payment_info),
        )
        .expect("build proof");
        proof.payment_address = "0x0000000000000000000000000000000000000001".to_owned();
        let err =
            verify_payment_account_binding_proof(&proof).expect_err("tampered address must reject");
        assert!(
            matches!(err, WalletError::InvalidSignature(_)),
            "expected InvalidSignature, got {err:?}"
        );
        let did_err = WalletPaymentAccountBindingVerifier
            .verify_payment_account_binding(&proof)
            .expect_err("tampered address must reject through watt-did trait");
        assert!(
            matches!(did_err, DidError::VerificationFailed(_)),
            "expected VerificationFailed, got {did_err:?}"
        );
    }

    #[test]
    fn tampered_agent_did_fails_verification() {
        let (keystore, agent_info, payment_info) = fresh_signers();
        let mut proof = build_payment_account_binding_proof(
            &keystore,
            build_options(&agent_info, &payment_info),
        )
        .expect("build proof");
        proof.agent_did =
            Did::parse("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH").expect("did");
        let err = verify_payment_account_binding_proof(&proof)
            .expect_err("tampered agent_did must reject");
        assert!(
            matches!(err, WalletError::InvalidSignature(_)),
            "expected InvalidSignature, got {err:?}"
        );
    }

    #[test]
    fn tampered_nonce_fails_verification() {
        let (keystore, agent_info, payment_info) = fresh_signers();
        let mut proof = build_payment_account_binding_proof(
            &keystore,
            build_options(&agent_info, &payment_info),
        )
        .expect("build proof");
        proof.nonce = Some("nonce-2".to_owned());
        let err =
            verify_payment_account_binding_proof(&proof).expect_err("tampered nonce must reject");
        assert!(
            matches!(err, WalletError::InvalidSignature(_)),
            "expected InvalidSignature, got {err:?}"
        );
    }
}
