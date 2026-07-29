// SPDX-License-Identifier: Apache-2.0 OR MIT
//! In-process EC2 instance bootstrap: IMDS discovery plus one SSM `GetParameter`.
//!
//! Replaces the AMI's `vouch-config.service` / `vouch-fetch-config.sh`, a oneshot
//! unit that shelled out to the AWS CLI for exactly this. [`discover`] degrades to
//! `Ok(None)` when IMDS is unreachable — not running on EC2, or
//! `AWS_EC2_METADATA_DISABLED=true` — so non-EC2 deployments pay nothing. Once IMDS
//! has answered, the `VouchConfigParameter` instance tag is the opt-in for the SSM
//! fetch: without a visible tag the server keeps the instance facts and starts from
//! env/CLI alone. With the tag present, an SSM failure is terminal for that attempt:
//! there is no silent fallback to an empty config. The systemd unit's
//! `Restart=always` / `RestartSec=30` retries transient failures; a persistent
//! failure becomes "never healthy", which an ASG replaces.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result};
use aws_config::imds::client::Client as ImdsClient;

const REGION_PATH: &str = "/latest/meta-data/placement/region";
const AZ_PATH: &str = "/latest/meta-data/placement/availability-zone";
const PARTITION_PATH: &str = "/latest/meta-data/services/partition";
const CONFIG_PARAMETER_TAG_PATH: &str = "/latest/meta-data/tags/instance/VouchConfigParameter";

/// Instance facts and configuration blob discovered from IMDS and SSM.
pub struct Bootstrap {
    /// AWS region, from IMDS `placement/region`.
    pub region: String,
    /// AWS availability zone, from IMDS `placement/availability-zone`.
    pub availability_zone: String,
    /// AWS partition, from IMDS `services/partition`. `None` on instance
    /// generations that 404 on this path.
    pub partition: Option<String>,
    /// Parsed `KEY=VALUE` bootstrap parameter contents. Empty when the
    /// instance has no visible `VouchConfigParameter` tag (SSM fetch skipped).
    pub params: BTreeMap<String, String>,
}

/// Discover instance facts and fetch the bootstrap configuration parameter.
///
/// Returns `Ok(None)` when IMDS is unreachable — not running on EC2, or
/// `AWS_EC2_METADATA_DISABLED=true` — in which case the caller falls back to
/// CLI flags and process environment only. The SSM fetch happens only when
/// the `VouchConfigParameter` instance tag is visible (requires launching
/// with `InstanceMetadataTags=enabled`); without it, the instance facts are
/// returned with empty `params`. Returns `Err` when the tag named a
/// parameter but the SSM `GetParameter` call or parameter parsing failed;
/// that failure is never papered over, since doing so would start the
/// server with no S3 config.
///
/// The caller skips this entirely when `s3_config_bucket` is already
/// configured (CLI flag or env), so local development and deployments that
/// fully configure via env/CLI pay nothing.
///
/// # Errors
///
/// Returns an error if IMDS is reachable but the availability-zone lookup
/// fails, or — when the `VouchConfigParameter` tag is visible — if the SSM
/// `GetParameter` call fails, the parameter has no value, or the value
/// cannot be parsed as `KEY=VALUE` lines.
pub async fn discover() -> Result<Option<Bootstrap>> {
    if std::env::var("AWS_EC2_METADATA_DISABLED").is_ok_and(|v| v.eq_ignore_ascii_case("true")) {
        tracing::debug!("AWS_EC2_METADATA_DISABLED=true; skipping IMDS/SSM bootstrap");
        return Ok(None);
    }

    let imds = ImdsClient::builder()
        .max_attempts(1)
        .connect_timeout(Duration::from_secs(1))
        .read_timeout(Duration::from_secs(1))
        .build();

    let region = match imds.get(REGION_PATH).await {
        Ok(value) => value.as_ref().to_string(),
        Err(e) => {
            tracing::info!("IMDS unreachable ({e}); not running on EC2, using env/CLI config");
            return Ok(None);
        }
    };

    // IMDS answered: we are on EC2 from here on, so further failures are
    // real errors rather than a silent fallback.
    let availability_zone = imds
        .get(AZ_PATH)
        .await
        .map(|v| v.as_ref().to_string())
        .context("IMDS reachable but availability-zone lookup failed")?;

    let partition = imds
        .get(PARTITION_PATH)
        .await
        .ok()
        .map(|v| v.as_ref().to_string());

    let parameter_name = match imds.get(CONFIG_PARAMETER_TAG_PATH).await {
        Ok(value) => value.as_ref().to_string(),
        Err(_) => {
            // IMDS returns 404 identically whether the tag is unset or the
            // instance was launched without InstanceMetadataTags=enabled;
            // distinguishing them would need a second request to
            // /latest/meta-data/tags/instance. Either way the tag is the
            // opt-in for SSM config, so keep the instance facts and let the
            // server start from env/CLI alone.
            tracing::warn!(
                "VouchConfigParameter instance tag not visible (tag unset, or instance \
                 launched without InstanceMetadataTags=enabled); skipping SSM config fetch"
            );
            return Ok(Some(Bootstrap {
                region,
                availability_zone,
                partition,
                params: BTreeMap::new(),
            }));
        }
    };

    // No use_fips override for this SSM call: whether to use FIPS endpoints
    // is itself a value the parameter fetched here may carry, so it cannot
    // apply to the fetch that discovers it.
    let sdk_config = crate::config::aws_config_loader(Some(&region), None)?
        .load()
        .await;
    let ssm_client = aws_sdk_ssm::Client::new(&sdk_config);

    let response = ssm_client
        .get_parameter()
        .name(&parameter_name)
        .with_decryption(true)
        .send()
        .await
        .with_context(|| {
            format!(
                "SSM GetParameter failed for '{parameter_name}' in region {region} \
                 (IMDS reachable, az={availability_zone})"
            )
        })?;

    let value = response
        .parameter()
        .and_then(|p| p.value())
        .with_context(|| format!("SSM parameter '{parameter_name}' has no value"))?;

    let params = parse_env_blob(value)
        .with_context(|| format!("failed to parse SSM parameter '{parameter_name}'"))?;

    Ok(Some(Bootstrap {
        region,
        availability_zone,
        partition,
        params,
    }))
}

/// Parse a systemd `EnvironmentFile`-compatible `KEY=VALUE` blob.
///
/// Accepts blank lines and `#`-prefixed comment lines. Rejects anything else
/// with a hard error naming the offending line — no `export ` prefix, no CRLF
/// line endings, no quoted values — so format drift from what systemd's
/// `EnvironmentFile=` and the Terraform-managed parameter actually produce is
/// loud rather than silently mis-split.
///
/// # Errors
///
/// Returns an error for any line that is not blank, a comment, or a strict
/// `KEY=VALUE` pair.
pub fn parse_env_blob(text: &str) -> Result<BTreeMap<String, String>> {
    let mut params = BTreeMap::new();
    for (idx, raw_line) in text.split('\n').enumerate() {
        let line_no = idx.saturating_add(1);
        if raw_line.contains('\r') {
            anyhow::bail!("line {line_no}: CRLF line endings are not accepted");
        }
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("export ") {
            anyhow::bail!(
                "line {line_no}: 'export' prefix is not accepted \
                 (systemd EnvironmentFile does not support it)"
            );
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            anyhow::bail!("line {line_no}: expected KEY=VALUE, got '{trimmed}'");
        };
        if key.is_empty() {
            anyhow::bail!("line {line_no}: empty key");
        }
        if value.starts_with('"') || value.starts_with('\'') {
            anyhow::bail!("line {line_no}: quoted values are not accepted, got '{trimmed}'");
        }
        params.insert(key.to_string(), value.to_string());
    }
    Ok(params)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test code: panic on assertion failure is acceptable"
    )]
    use super::parse_env_blob;

    #[test]
    fn accepts_basic_pairs() {
        let blob = "FOO=bar\nBAZ=qux\n";
        let params = parse_env_blob(blob).expect("valid blob");
        assert_eq!(params.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(params.get("BAZ").map(String::as_str), Some("qux"));
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn accepts_comments_and_blank_lines() {
        let blob = "# a comment\n\nFOO=bar\n   \n# another\nBAZ=qux";
        let params = parse_env_blob(blob).expect("valid blob");
        assert_eq!(params.len(), 2);
        assert_eq!(params.get("FOO").map(String::as_str), Some("bar"));
    }

    #[test]
    fn accepts_empty_value() {
        let params = parse_env_blob("FOO=\n").expect("valid blob");
        assert_eq!(params.get("FOO").map(String::as_str), Some(""));
    }

    #[test]
    fn accepts_value_containing_equals() {
        let params = parse_env_blob("FOO=a=b=c\n").expect("valid blob");
        assert_eq!(params.get("FOO").map(String::as_str), Some("a=b=c"));
    }

    #[test]
    fn rejects_export_prefix() {
        let err = parse_env_blob("export FOO=bar\n").unwrap_err();
        assert!(err.to_string().contains("export"), "got: {err}");
    }

    #[test]
    fn rejects_crlf() {
        let err = parse_env_blob("FOO=bar\r\nBAZ=qux\r\n").unwrap_err();
        assert!(err.to_string().contains("CRLF"), "got: {err}");
    }

    #[test]
    fn rejects_quoted_value_with_spaces() {
        let err = parse_env_blob("FOO=\"bar baz\"\n").unwrap_err();
        assert!(err.to_string().contains("quoted"), "got: {err}");
    }

    #[test]
    fn rejects_single_quoted_value() {
        let err = parse_env_blob("FOO='bar'\n").unwrap_err();
        assert!(err.to_string().contains("quoted"), "got: {err}");
    }

    #[test]
    fn rejects_missing_equals() {
        let err = parse_env_blob("NOT_A_PAIR\n").unwrap_err();
        assert!(err.to_string().contains("KEY=VALUE"), "got: {err}");
    }

    #[test]
    fn rejects_empty_key() {
        let err = parse_env_blob("=novalue\n").unwrap_err();
        assert!(err.to_string().contains("empty key"), "got: {err}");
    }

    #[test]
    fn empty_blob_yields_empty_map() {
        let params = parse_env_blob("").expect("valid blob");
        assert!(params.is_empty());
    }
}
