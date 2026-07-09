// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SSH Agent protocol message building and signing.

use crate::error::{AgentError, Result};
use crate::wire;
use ssh_key::PrivateKey;
use tracing::debug;
use zeroize::Zeroizing;

use super::credentials::SshCredentials;
use super::{SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE};

/// Build an SSH_AGENT_IDENTITIES_ANSWER response.
pub(super) fn build_identities_response(creds: Option<&SshCredentials>) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    response.push(SSH_AGENT_IDENTITIES_ANSWER);

    match creds {
        Some(c) => {
            response.extend_from_slice(&1u32.to_be_bytes());

            let blob_len = u32::try_from(c.certificate_blob.len())
                .map_err(|_| AgentError::Protocol("certificate too large".to_string()))?;
            response.extend_from_slice(&blob_len.to_be_bytes());
            response.extend_from_slice(&c.certificate_blob);

            let comment_bytes = c.comment.as_bytes();
            let comment_len = u32::try_from(comment_bytes.len())
                .map_err(|_| AgentError::Protocol("comment too large".to_string()))?;
            response.extend_from_slice(&comment_len.to_be_bytes());
            response.extend_from_slice(comment_bytes);

            debug!("Returning 1 identity");
        }
        None => {
            response.extend_from_slice(&0u32.to_be_bytes());
            debug!("Returning 0 identities");
        }
    }

    Ok(response)
}

/// Build an SSH_AGENT_SIGN_RESPONSE.
pub(super) fn build_sign_response(sig_blob: &[u8]) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    response.push(SSH_AGENT_SIGN_RESPONSE);

    // Signature blob
    let sig_len = u32::try_from(sig_blob.len())
        .map_err(|_| AgentError::Protocol("signature too large".to_string()))?;
    response.extend_from_slice(&sig_len.to_be_bytes());
    response.extend_from_slice(sig_blob);

    Ok(response)
}

/// Parse a sign request and extract the data to sign.
///
/// Returns the data to sign.
pub(super) fn parse_sign_request(buf: &[u8]) -> Result<Vec<u8>> {
    // Parse sign request:
    // byte    SSH_AGENTC_SIGN_REQUEST
    // string  key_blob
    // string  data
    // uint32  flags

    // Skip message type byte
    let mut offset = 1;

    // Read key blob (skip it)
    let key_blob_len = wire::read_u32(buf, &mut offset)?;
    let key_blob_usize = usize::try_from(key_blob_len)
        .map_err(|_| AgentError::Protocol("key blob length overflow".to_string()))?;
    let key_blob_end = offset
        .checked_add(key_blob_usize)
        .ok_or_else(|| AgentError::Protocol("key blob offset overflow".to_string()))?;
    if key_blob_end > buf.len() {
        return Err(AgentError::Protocol("invalid key blob length".to_string()));
    }
    offset = key_blob_end;

    // Read data to sign
    let data_len = wire::read_u32(buf, &mut offset)?;
    let data_usize = usize::try_from(data_len)
        .map_err(|_| AgentError::Protocol("data length overflow".to_string()))?;
    let data_end = offset
        .checked_add(data_usize)
        .ok_or_else(|| AgentError::Protocol("data offset overflow".to_string()))?;
    let data = buf
        .get(offset..data_end)
        .ok_or_else(|| AgentError::Protocol("invalid data length".to_string()))?;

    Ok(data.to_vec())
}

/// Sign data with the private key and return the encoded signature.
pub(super) fn sign_data(private_key: &PrivateKey, data: &[u8]) -> Result<Vec<u8>> {
    // For SSH agent protocol, we need to sign the data directly and return
    // the signature in SSH wire format: string algorithm + string signature

    let (alg_name, sig_bytes) = match private_key.key_data() {
        ssh_key::private::KeypairData::Ed25519(keypair) => {
            use ed25519_dalek::{Signer, SigningKey};

            // The public half is derived from the seed, so the keypair's
            // stored public key is not consulted here.
            let seed = Zeroizing::new(keypair.private.to_bytes());
            let signing_key = SigningKey::from_bytes(&seed);
            let signature = signing_key.sign(data);

            ("ssh-ed25519", signature.to_bytes().to_vec())
        }
        _ => {
            return Err(AgentError::Protocol(
                "unsupported key algorithm".to_string(),
            ));
        }
    };

    // Encode in SSH wire format
    let mut buf = Vec::new();

    // Algorithm name
    buf.extend_from_slice(&wire::encode_string(alg_name)?);

    // Signature blob
    buf.extend_from_slice(&wire::encode_bytes(&sig_bytes)?);

    Ok(buf)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    #[test]
    fn test_build_identities_response_none() {
        let response = build_identities_response(None).unwrap();

        assert_eq!(response[0], SSH_AGENT_IDENTITIES_ANSWER);
        // Count should be 0
        assert_eq!(&response[1..5], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_build_sign_response() {
        let sig_blob = vec![0x01, 0x02, 0x03, 0x04];
        let response = build_sign_response(&sig_blob).unwrap();

        assert_eq!(response[0], SSH_AGENT_SIGN_RESPONSE);
        // Length should be 4
        assert_eq!(&response[1..5], &[0, 0, 0, 4]);
        // Signature data
        assert_eq!(&response[5..9], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_sign_data_ed25519_verifies_under_stored_public_key() {
        use ssh_key::private::{Ed25519Keypair, KeypairData};

        let keypair = Ed25519Keypair::from_seed(&[7u8; 32]);
        let public_key_bytes = keypair.public.0;
        let private_key = PrivateKey::new(KeypairData::Ed25519(keypair), "test").unwrap();

        let data = b"ssh agent signing round trip";
        let blob = sign_data(&private_key, data).unwrap();

        // SSH wire format: string algorithm (11 bytes) + string signature (64 bytes)
        assert_eq!(blob.len(), 83);
        assert_eq!(&blob[..4], &11u32.to_be_bytes());
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        assert_eq!(&blob[15..19], &64u32.to_be_bytes());
        let signature: [u8; 64] = blob[19..].try_into().unwrap();

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes).unwrap();
        verifying_key
            .verify_strict(data, &ed25519_dalek::Signature::from_bytes(&signature))
            .unwrap();
    }
}
