// SPDX-License-Identifier: BUSL-1.1
//! Decrypt a KMS-encrypted S3 config envelope to plain JSON.
//!
//! This subcommand reads an `EncryptedEnvelope` (from a local file or S3),
//! decrypts the AES-256 data key via plain `kms:Decrypt` (no NitroTPM), and
//! AES-256-GCM decrypts the inner config. The wrapper fields (`tls`, `_acme`,
//! `version`) are merged back into the output.
//!
//! ## Usage
//!
//! ```bash
//! # From a local file
//! vouch-server decrypt-config --input encrypted.json
//!
//! # From S3
//! vouch-server decrypt-config --s3-bucket my-bucket --s3-key config.json
//!
//! # With explicit KMS key ID (overrides envelope's kms_key_id)
//! vouch-server decrypt-config --input encrypted.json --kms-key-id mrk-abc
//! ```

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::Args;

use crate::crypto::tpm_decrypt::{EncryptedEnvelope, aes_256_gcm_decrypt};

/// Decrypt a KMS-encrypted S3 config envelope to plain JSON.
#[derive(Args)]
pub struct DecryptConfigArgs {
    /// Path to a local JSON file containing the encrypted envelope.
    #[arg(long)]
    pub input: Option<String>,

    /// S3 bucket to fetch the envelope from (alternative to --input).
    #[arg(long, env = "VOUCH_S3_CONFIG_BUCKET")]
    pub s3_bucket: Option<String>,

    /// S3 object key (default: config.json).
    #[arg(long, env = "VOUCH_S3_CONFIG_KEY", default_value = "config.json")]
    pub s3_key: String,

    /// KMS key ID override. If not specified, uses the envelope's kms_key_id.
    #[arg(long)]
    pub kms_key_id: Option<String>,

    /// AWS region override.
    #[arg(long, env = "AWS_REGION")]
    pub region: Option<String>,
}

/// Load envelope bytes from either a local file or S3.
async fn load_envelope(args: &DecryptConfigArgs) -> Result<Vec<u8>> {
    if let Some(path) = &args.input {
        tracing::info!("Reading envelope from local file: {path}");
        std::fs::read(path).with_context(|| format!("Failed to read file: {path}"))
    } else if let Some(bucket) = &args.s3_bucket {
        tracing::info!("Fetching envelope from s3://{}/{}", bucket, args.s3_key);

        let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = &args.region {
            config_loader = config_loader.region(aws_config::Region::new(region.clone()));
        }
        let sdk_config = config_loader.load().await;
        let s3_client = aws_sdk_s3::Client::new(&sdk_config);

        let response = s3_client
            .get_object()
            .bucket(bucket)
            .key(&args.s3_key)
            .send()
            .await
            .with_context(|| format!("Failed to fetch s3://{}/{}", bucket, args.s3_key))?;

        let body = response
            .body
            .collect()
            .await
            .context("Failed to read S3 object body")?;

        Ok(body.into_bytes().to_vec())
    } else {
        anyhow::bail!("Either --input or --s3-bucket must be specified");
    }
}

/// Run the decrypt-config subcommand.
pub async fn run(args: DecryptConfigArgs) -> Result<()> {
    // 1. Load and parse the encrypted envelope
    let envelope_bytes = load_envelope(&args).await?;
    let envelope: EncryptedEnvelope = serde_json::from_slice(&envelope_bytes)
        .context("Failed to parse input as EncryptedEnvelope JSON")?;

    tracing::info!(
        "Envelope parsed: version={}, kms_key_id={}",
        envelope.version,
        envelope.kms_key_id
    );

    // 2. Build AWS SDK config and create KMS client
    let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(region) = &args.region {
        config_loader = config_loader.region(aws_config::Region::new(region.clone()));
    }
    let sdk_config = config_loader.load().await;
    let kms_client = aws_sdk_kms::Client::new(&sdk_config);

    // 3. Decrypt the data key via plain kms:Decrypt (no NitroTPM attestation).
    //    In production, decrypt_envelope() uses NitroTPM-attested KMS to ensure
    //    decryption only happens on trusted instances. This operator tool skips
    //    attestation so it can run on dev machines for debugging/inspection.
    let key_id = args.kms_key_id.as_deref().unwrap_or(&envelope.kms_key_id);

    let encrypted_data_key = BASE64
        .decode(&envelope.encrypted_data_key)
        .context("Failed to base64-decode encrypted_data_key")?;

    tracing::info!("Decrypting data key via KMS (key: {key_id})");

    let decrypt_response = kms_client
        .decrypt()
        .key_id(key_id)
        .ciphertext_blob(aws_smithy_types::Blob::new(encrypted_data_key))
        .send()
        .await
        .context("KMS Decrypt failed")?;

    let data_key = decrypt_response
        .plaintext()
        .context("KMS Decrypt response missing plaintext")?;

    // 4. AES-256-GCM decrypt the config payload
    let encrypted_data = BASE64
        .decode(&envelope.encrypted_data)
        .context("Failed to base64-decode encrypted_data")?;

    let plaintext = aes_256_gcm_decrypt(data_key.as_ref(), &encrypted_data)
        .context("AES-256-GCM decryption failed")?;

    tracing::info!("Config decrypted ({} bytes)", plaintext.len());

    // 5. Re-merge wrapper fields (version, tls, _acme) into the output
    let mut config: serde_json::Value =
        serde_json::from_slice(&plaintext).context("Failed to parse decrypted config as JSON")?;

    if let Some(obj) = config.as_object_mut() {
        obj.insert(
            "version".to_string(),
            serde_json::Value::Number(envelope.version.into()),
        );

        if let Some(tls) = &envelope.tls {
            let tls_value = serde_json::to_value(tls).context("Failed to serialize TLS config")?;
            obj.insert("tls".to_string(), tls_value);
        }

        if let Some(acme) = &envelope.acme {
            let acme_value =
                serde_json::to_value(acme).context("Failed to serialize ACME config")?;
            obj.insert("_acme".to_string(), acme_value);
        }
    }

    // 6. Output plain JSON to stdout
    let output = serde_json::to_string_pretty(&config)
        .context("Failed to serialize decrypted config to JSON")?;
    println!("{output}");

    tracing::info!("Decrypted config written to stdout");

    Ok(())
}
