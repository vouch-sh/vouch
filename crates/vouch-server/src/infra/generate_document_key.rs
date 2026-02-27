// SPDX-License-Identifier: BUSL-1.1
//! Generate a P-384 document encryption key pair via KMS.
//!
//! Uses `kms:GenerateDataKeyPair` with `ECC_NIST_P384` to produce a key pair
//! where the private key is encrypted by KMS. The output is a JSON object
//! suitable for embedding as the `document_key` field in an S3 config.
//!
//! ## Usage
//!
//! ```bash
//! vouch-server generate-document-key --kms-key-id mrk-abc > document_key.json
//! ```
//!
//! Then merge the output into your S3 config JSON under `"document_key"`.

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::Args;

/// Generate a P-384 document encryption key pair via KMS.
#[derive(Args)]
pub struct GenerateDocumentKeyArgs {
    /// KMS key ID, ARN, or alias for GenerateDataKeyPair.
    #[arg(long)]
    pub kms_key_id: String,

    /// AWS region override.
    #[arg(long, env = "AWS_REGION")]
    pub region: Option<String>,
}

/// Run the generate-document-key subcommand.
pub async fn run(args: GenerateDocumentKeyArgs) -> Result<()> {
    // 1. Build AWS SDK config and create KMS client
    let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(region) = &args.region {
        config_loader = config_loader.region(aws_config::Region::new(region.clone()));
    }
    let sdk_config = config_loader.load().await;
    let kms_client = aws_sdk_kms::Client::new(&sdk_config);

    // 2. Generate a P-384 data key pair via KMS
    tracing::info!(
        "Generating P-384 data key pair via KMS (key: {})",
        args.kms_key_id
    );

    let response = kms_client
        .generate_data_key_pair()
        .key_id(&args.kms_key_id)
        .key_pair_spec(aws_sdk_kms::types::DataKeyPairSpec::EccNistP384)
        .send()
        .await
        .context("KMS GenerateDataKeyPair failed")?;

    // 3. Validate the plaintext private key can produce a valid HPKE key pair
    let private_key_der_blob = response
        .private_key_plaintext()
        .context("KMS response missing private_key_plaintext")?;

    let (derived_public, _derived_private) =
        crate::crypto::document_crypto::p384_hpke_keys_from_private_key_der(
            private_key_der_blob.as_ref(),
        )
        .context("Failed to derive HPKE key pair from KMS private key")?;

    // 4. Cross-check: verify KMS public key matches the derived public key
    let public_key_der_blob = response
        .public_key()
        .context("KMS response missing public_key")?;

    let kms_public =
        crate::crypto::document_crypto::p384_public_key_from_der(public_key_der_blob.as_ref())
            .context("Failed to parse KMS public key SPKI DER")?;

    if kms_public.0 != derived_public.0 {
        anyhow::bail!(
            "KMS public key does not match derived public key \
             (KMS: {} bytes, derived: {} bytes)",
            kms_public.0.len(),
            derived_public.0.len()
        );
    }

    tracing::info!(
        "P-384 key pair validated (public key: {} bytes)",
        derived_public.0.len()
    );

    // 5. Extract the encrypted private key (KMS ciphertext blob)
    let encrypted_private_key_blob = response
        .private_key_ciphertext_blob()
        .context("KMS response missing private_key_ciphertext_blob")?;

    // 6. Output JSON
    // `kms_key_id` + `encrypted_private_key` map to S3DocumentKeyConfig fields.
    // `public_key` is informational for operators (not consumed by the server).
    let output = serde_json::json!({
        "kms_key_id": args.kms_key_id,
        "encrypted_private_key": BASE64.encode(encrypted_private_key_blob.as_ref()),
        "public_key": BASE64.encode(public_key_der_blob.as_ref()),
    });

    let json = serde_json::to_string_pretty(&output).context("Failed to serialize output JSON")?;
    println!("{json}");

    tracing::info!("Document key JSON written to stdout");

    Ok(())
}
