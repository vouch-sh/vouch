// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Generate a document encryption key pair via KMS.
//!
//! Uses `kms:GenerateDataKeyPairWithoutPlaintext` to produce a key pair where
//! the private key is returned only in encrypted form. The plaintext private
//! key never leaves KMS — the server decrypts it at startup via `kms:Decrypt`.
//! The output is a JSON object suitable for embedding as the `document_key`
//! field in an S3 config.
//!
//! P-384 is the only supported algorithm today; the `--algorithm` flag exists
//! so post-quantum algorithms (draft-ietf-hpke-pq) can be added without
//! changing the command's interface or output shape.
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

use crate::infra::s3_config::DocumentKeyAlgorithm;

/// Generate a document encryption key pair via KMS
/// (without plaintext private key).
#[derive(Args)]
pub struct GenerateDocumentKeyArgs {
    /// KMS key ID, ARN, or alias for
    /// `GenerateDataKeyPairWithoutPlaintext`.
    #[arg(long)]
    pub kms_key_id: String,

    /// Key algorithm for the generated key pair.
    #[arg(long, value_enum, default_value = "p384")]
    pub algorithm: DocumentKeyAlgorithm,

    /// AWS region override.
    #[arg(long, env = "AWS_REGION")]
    pub region: Option<String>,
}

/// Run the generate-document-key subcommand.
#[expect(
    clippy::print_stdout,
    reason = "the generated key is this subcommand's output, meant to be piped"
)]
pub async fn run(args: GenerateDocumentKeyArgs) -> Result<()> {
    // 1. Build AWS SDK config and create KMS client. This subcommand runs as
    // an operator CLI tool, not on EC2, so there is no resolved FIPS setting
    // to pass -- the SDK's own environment-based default applies.
    let sdk_config = crate::config::aws_config_loader(args.region.as_deref(), None)?
        .load()
        .await;
    let kms_client = aws_sdk_kms::Client::new(&sdk_config);

    // 2. Generate a data key pair via KMS
    let key_pair_spec = match args.algorithm {
        DocumentKeyAlgorithm::P384 => aws_sdk_kms::types::DataKeyPairSpec::EccNistP384,
    };
    tracing::info!(
        "Generating {:?} data key pair via KMS (key: {})",
        args.algorithm,
        args.kms_key_id
    );

    let response = kms_client
        .generate_data_key_pair_without_plaintext()
        .key_id(&args.kms_key_id)
        .key_pair_spec(key_pair_spec)
        .send()
        .await
        .context("KMS GenerateDataKeyPairWithoutPlaintext failed")?;

    // 3. Extract the public key (informational for operators)
    let public_key_der_blob = response
        .public_key()
        .context("KMS response missing public_key")?;

    // 4. Extract the encrypted private key (KMS ciphertext blob)
    let encrypted_private_key_blob = response
        .private_key_ciphertext_blob()
        .context("KMS response missing private_key_ciphertext_blob")?;

    // 5. Output JSON
    // `kms_key_id` + `encrypted_private_key` + `algorithm` map to
    // S3DocumentKeyConfig fields.
    // `public_key` is informational for operators (not consumed by the server).
    let output = serde_json::json!({
        "kms_key_id": args.kms_key_id,
        "encrypted_private_key": BASE64.encode(encrypted_private_key_blob.as_ref()),
        "algorithm": args.algorithm,
        "public_key": BASE64.encode(public_key_der_blob.as_ref()),
    });

    let json = serde_json::to_string_pretty(&output).context("Failed to serialize output JSON")?;
    println!("{json}");

    tracing::info!("Document key JSON written to stdout");

    Ok(())
}
