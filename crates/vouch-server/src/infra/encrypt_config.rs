// SPDX-License-Identifier: BUSL-1.1
//! Encrypt a plain S3Config JSON into a KMS-encrypted envelope.
//!
//! This subcommand takes a plain `S3Config` JSON file, generates an AES-256
//! data key via `kms:GenerateDataKey`, AES-256-GCM encrypts the inner config,
//! and writes an `EncryptedEnvelope` JSON to stdout.
//!
//! ## Usage
//!
//! ```bash
//! # From a local file
//! vouch-server encrypt-config --kms-key-id mrk-abc --input config.json > encrypted.json
//!
//! # From S3
//! vouch-server encrypt-config --kms-key-id mrk-abc \
//!   --s3-bucket my-bucket --s3-key config.json > encrypted.json
//! ```

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::Args;
use zeroize::Zeroizing;

use super::s3_config::{S3AcmeConfig, S3Config, S3TlsConfig};
use crate::crypto::tpm_decrypt::{EncryptedEnvelope, aes_256_gcm_encrypt};

/// Encrypt a plain S3Config JSON into a KMS-encrypted envelope.
#[derive(Args)]
pub struct EncryptConfigArgs {
    /// KMS key ID, ARN, or alias for GenerateDataKey.
    #[arg(long)]
    pub kms_key_id: String,

    /// Path to a local JSON file containing the S3Config.
    #[arg(long)]
    pub input: Option<String>,

    /// S3 bucket to fetch the config from (alternative to --input).
    #[arg(long, env = "VOUCH_S3_CONFIG_BUCKET")]
    pub s3_bucket: Option<String>,

    /// S3 object key (default: config.json).
    #[arg(long, env = "VOUCH_S3_CONFIG_KEY", default_value = "config.json")]
    pub s3_key: String,

    /// AWS region override.
    #[arg(long, env = "AWS_REGION")]
    pub region: Option<String>,
}

/// Load config bytes from either a local file or S3.
async fn load_config(args: &EncryptConfigArgs) -> Result<Vec<u8>> {
    if let Some(path) = &args.input {
        // Read from local file
        tracing::info!("Reading config from local file: {path}");
        std::fs::read(path).with_context(|| format!("Failed to read file: {path}"))
    } else if let Some(bucket) = &args.s3_bucket {
        // Fetch from S3
        tracing::info!("Fetching config from s3://{}/{}", bucket, args.s3_key);

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

/// Run the encrypt-config subcommand.
pub async fn run(args: EncryptConfigArgs) -> Result<()> {
    // 1. Load and validate the config
    let config_bytes = load_config(&args).await?;
    let config: S3Config =
        serde_json::from_slice(&config_bytes).context("Failed to parse input as S3Config JSON")?;

    tracing::info!("Config parsed successfully");

    // 2. Extract wrapper fields (tls, _acme, version) that live outside
    //    the encrypted payload
    let wrapper_tls: Option<S3TlsConfig> = config.tls.clone();
    let wrapper_acme: Option<S3AcmeConfig> = config.acme.clone();
    let wrapper_version: u32 = config.version.unwrap_or(1);

    // 3. Remove tls, _acme, and version from the inner JSON so they
    //    only appear in the wrapper
    let mut inner_value: serde_json::Value =
        serde_json::from_slice(&config_bytes).context("Failed to parse config as JSON value")?;
    if let Some(obj) = inner_value.as_object_mut() {
        obj.remove("tls");
        obj.remove("_acme");
        obj.remove("version");
    }
    let inner_json =
        serde_json::to_vec(&inner_value).context("Failed to re-serialize inner config")?;

    tracing::info!(
        "Inner config: {} bytes (tls, _acme, and version moved to wrapper)",
        inner_json.len()
    );

    // 4. Build AWS SDK config and create KMS client
    let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(region) = &args.region {
        config_loader = config_loader.region(aws_config::Region::new(region.clone()));
    }
    let sdk_config = config_loader.load().await;
    let kms_client = aws_sdk_kms::Client::new(&sdk_config);

    // 5. Generate an AES-256 data key via KMS
    tracing::info!(
        "Generating AES-256 data key via KMS (key: {})",
        args.kms_key_id
    );

    let generate_response = kms_client
        .generate_data_key()
        .key_id(&args.kms_key_id)
        .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
        .send()
        .await
        .context("KMS GenerateDataKey failed")?;

    let plaintext_key_blob = generate_response
        .plaintext()
        .context("KMS GenerateDataKey response missing plaintext")?;
    let plaintext_key = Zeroizing::new(plaintext_key_blob.as_ref().to_vec());

    let ciphertext_blob = generate_response
        .ciphertext_blob()
        .context("KMS GenerateDataKey response missing ciphertext_blob")?;
    let encrypted_data_key = BASE64.encode(ciphertext_blob.as_ref());

    tracing::info!(
        "AES-256 data key generated (encrypted key: {} bytes)",
        ciphertext_blob.as_ref().len()
    );

    // 6. AES-256-GCM encrypt the inner config JSON
    let ciphertext = aes_256_gcm_encrypt(&plaintext_key, &inner_json)
        .context("AES-256-GCM encryption failed")?;

    // 7. Build the envelope
    let envelope = EncryptedEnvelope {
        kms_key_id: args.kms_key_id.clone(),
        encrypted_data_key,
        encrypted_data: BASE64.encode(&ciphertext),
        version: wrapper_version,
        tls: wrapper_tls,
        acme: wrapper_acme,
    };

    // 8. Serialize as pretty JSON to stdout
    let output =
        serde_json::to_string_pretty(&envelope).context("Failed to serialize envelope to JSON")?;
    println!("{output}");

    tracing::info!("Encrypted envelope written to stdout");

    Ok(())
}
