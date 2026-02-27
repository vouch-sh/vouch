// SPDX-License-Identifier: BUSL-1.1
//! Encrypt a plain S3Config JSON into a KMS-encrypted envelope.
//!
//! This subcommand takes a plain `S3Config` JSON file, generates a P-384 data key
//! pair via `kms:GenerateDataKeyPair`, HPKE-seals the inner config with the public
//! key, and writes an `EncryptedEnvelope` JSON to stdout. The same key pair is
//! reused at runtime for `HpkeDocumentCrypto` (database-level document encryption).
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

use super::s3_config::{S3AcmeConfig, S3Config, S3TlsConfig};
use crate::crypto::document_crypto::{DocumentCrypto, HpkeDocumentCrypto};
use crate::crypto::tpm_decrypt::{EncryptedEnvelope, HPKE_CONFIG_INFO, build_hpke_aad};

/// Encrypt a plain S3Config JSON into a KMS-encrypted envelope.
#[derive(Args)]
pub struct EncryptConfigArgs {
    /// KMS key ID, ARN, or alias for GenerateDataKeyPair.
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

    // 2. Extract wrapper fields (tls, _acme, version) that live outside the encrypted payload
    let wrapper_tls: Option<S3TlsConfig> = config.tls.clone();
    let wrapper_acme: Option<S3AcmeConfig> = config.acme.clone();
    let wrapper_version: u32 = config.version.unwrap_or(1);

    // 3. Remove tls and version from the inner JSON so they only appear in the wrapper
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

    // 5. Generate a P-384 data key pair via KMS
    tracing::info!(
        "Generating P-384 data key pair via KMS (key: {})",
        args.kms_key_id
    );

    let generate_response = kms_client
        .generate_data_key_pair()
        .key_id(&args.kms_key_id)
        .key_pair_spec(aws_sdk_kms::types::DataKeyPairSpec::EccNistP384)
        .send()
        .await
        .context("KMS GenerateDataKeyPair failed")?;

    // Extract the plaintext public key DER (for the envelope's `public_key` field)
    let public_key_der_blob = generate_response
        .public_key()
        .context("KMS GenerateDataKeyPair response missing public_key")?;
    let public_key_der = public_key_der_blob.as_ref().to_vec();

    // Extract the plaintext private key DER and derive the HPKE key pair
    let private_key_der_blob = generate_response
        .private_key_plaintext()
        .context("KMS GenerateDataKeyPair response missing private_key_plaintext")?;
    let (hpke_public_key, hpke_private_key) =
        crate::crypto::document_crypto::p384_hpke_keys_from_private_key_der(
            private_key_der_blob.as_ref(),
        )
        .context("Failed to extract P-384 HPKE key pair from KMS response")?;

    // The encrypted private key (KMS ciphertext blob — decrypted at runtime via KMS)
    let encrypted_private_key_blob = generate_response
        .private_key_ciphertext_blob()
        .context("KMS GenerateDataKeyPair response missing private_key_ciphertext_blob")?;
    let encrypted_private_key = BASE64.encode(encrypted_private_key_blob.as_ref());

    tracing::info!(
        "P-384 data key pair generated (public key: {} bytes DER, encrypted private key: {} bytes)",
        public_key_der.len(),
        encrypted_private_key_blob.as_ref().len()
    );

    // 6. HPKE seal the inner config JSON
    let crypto = HpkeDocumentCrypto::new(hpke_public_key, hpke_private_key)
        .context("Failed to create HPKE crypto for config encryption")?;

    let aad = build_hpke_aad(wrapper_version);
    let sealed = crypto
        .seal(HPKE_CONFIG_INFO, &aad, &inner_json)
        .context("HPKE seal failed")?;

    let encapped_key = sealed
        .encapped_key
        .context("HPKE seal did not produce encapped_key")?;

    // 7. Build the envelope
    let envelope = EncryptedEnvelope {
        kms_key_id: args.kms_key_id.clone(),
        encrypted_private_key,
        public_key: BASE64.encode(&public_key_der),
        encapped_key,
        encrypted_data: sealed.data,
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
