// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Generate a Client Certificate CA for mTLS (RFC 8705).
//!
//! Creates a self-signed X.509 CA certificate using an existing KMS key
//! or a newly generated local P-256 key. Outputs JSON suitable for
//! `VOUCH_CLIENT_CERT_CA_CERT` (and `VOUCH_CLIENT_CERT_CA_KEY` for
//! local mode).
//!
//! ## Usage
//!
//! ```bash
//! # KMS mode (production) — reuse OIDC signing key or any P-256 KMS key
//! vouch-server generate-client-cert-ca \
//!   --kms-key-id alias/vouch-oidc-signing
//!
//! # Local mode (dev)
//! vouch-server generate-client-cert-ca
//! ```

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::Args;
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;

use crate::crypto::client_cert_ca::{
    build_ca_cert_kms, build_ca_cert_local, cert_der_to_pem, key_der_to_pem,
};
use crate::crypto::kms_signer::KmsSignerP256;

/// Generate a Client Certificate CA for mTLS.
#[derive(Args)]
pub struct GenerateClientCertCaArgs {
    /// KMS key ID for the CA signing key.
    /// Can be the same as `VOUCH_OIDC_SIGNING_KMS_KEY_ID`.
    /// If omitted, generates a local P-256 key pair.
    #[arg(long)]
    pub kms_key_id: Option<String>,

    /// Subject CN for the CA certificate.
    #[arg(long, default_value = "Vouch Client CA")]
    pub subject: String,

    /// Validity in days (default: 3650, ~10 years).
    #[arg(long, default_value = "3650")]
    pub validity_days: u32,

    /// AWS region override.
    #[arg(long, env = "AWS_REGION")]
    pub region: Option<String>,
}

/// Run the generate-client-cert-ca subcommand.
pub async fn run(args: GenerateClientCertCaArgs) -> Result<()> {
    if let Some(key_id) = &args.kms_key_id {
        run_kms(key_id, &args).await
    } else {
        run_local(&args)
    }
}

/// Generate CA certificate using KMS P-256 key.
async fn run_kms(key_id: &str, args: &GenerateClientCertCaArgs) -> Result<()> {
    tracing::info!("Generating CA certificate using KMS key: {}", key_id);

    let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(region) = &args.region {
        config_loader = config_loader.region(aws_config::Region::new(region.clone()));
    }
    let sdk_config = config_loader.load().await;
    let kms_client = aws_sdk_kms::Client::new(&sdk_config);

    let signer = KmsSignerP256::new(kms_client, key_id.to_string()).await?;
    let ca_cert_der = build_ca_cert_kms(&signer, &args.subject, args.validity_days).await?;

    let ca_cert_pem =
        cert_der_to_pem(&ca_cert_der).context("Failed to encode CA certificate as PEM")?;

    let output = serde_json::json!({
        "ca_cert": BASE64.encode(ca_cert_pem.as_bytes()),
    });

    let json = serde_json::to_string_pretty(&output).context("Failed to serialize output JSON")?;
    println!("{json}");

    tracing::info!("CA certificate JSON written to stdout");
    Ok(())
}

/// Generate local P-256 CA key + self-signed certificate.
fn run_local(args: &GenerateClientCertCaArgs) -> Result<()> {
    tracing::info!("Generating local P-256 CA key pair");

    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let pkcs8_der = signing_key
        .to_pkcs8_der()
        .map_err(|e| anyhow::anyhow!("Failed to encode CA key to PKCS#8: {e}"))?;

    let ca_cert_der = build_ca_cert_local(&signing_key, &args.subject, args.validity_days)?;

    let ca_cert_pem =
        cert_der_to_pem(&ca_cert_der).context("Failed to encode CA certificate as PEM")?;
    let key_pem =
        key_der_to_pem(pkcs8_der.as_bytes()).context("Failed to encode CA private key as PEM")?;

    let output = serde_json::json!({
        "ca_cert": BASE64.encode(ca_cert_pem.as_bytes()),
        "private_key": BASE64.encode(key_pem.as_bytes()),
    });

    let json = serde_json::to_string_pretty(&output).context("Failed to serialize output JSON")?;
    println!("{json}");

    tracing::info!("CA certificate + private key JSON written to stdout");
    Ok(())
}
