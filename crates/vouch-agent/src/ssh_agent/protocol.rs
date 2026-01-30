// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SSH Agent protocol message building and signing.

use crate::error::{AgentError, Result};
use crate::wire;
use ssh_key::PrivateKey;
use tracing::debug;

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
    let key_blob_end = offset + key_blob_len as usize;
    if key_blob_end > buf.len() {
        return Err(AgentError::Protocol("invalid key blob length".to_string()));
    }
    offset = key_blob_end;

    // Read data to sign
    let data_len = wire::read_u32(buf, &mut offset)?;
    let data_end = offset + data_len as usize;
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
            // Get the signing key bytes and create a signature
            let signing_key_bytes = keypair.private.to_bytes();
            let public_key_bytes = keypair.public.0;

            // Combine private + public for ed25519-dalek format (64 bytes)
            let mut full_key = [0u8; 64];
            full_key[..32].copy_from_slice(&signing_key_bytes);
            full_key[32..].copy_from_slice(&public_key_bytes);

            // Use ed25519 signing
            use ed25519_dalek::{Signer, SigningKey};
            let signing_key = SigningKey::from_keypair_bytes(&full_key)
                .map_err(|e| AgentError::Protocol(format!("invalid ed25519 key: {e}")))?;
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
    buf.extend_from_slice(&wire::encode_string(alg_name));

    // Signature blob
    buf.extend_from_slice(&wire::encode_bytes(&sig_bytes));

    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
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
}
