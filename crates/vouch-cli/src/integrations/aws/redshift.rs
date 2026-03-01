// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS Redshift integration utilities.
//!
//! Provides SigV4-signed `GetClusterCredentialsWithIAM` API calls to obtain
//! temporary database credentials for Amazon Redshift clusters. Uses the newer
//! IAM-identity-based API that auto-maps IAM identity to a database user.

use anyhow::{Context, Result};
use secrecy::SecretString;

use super::sigv4::sign_and_send_form_post;
use super::sts::StsCredentials;

/// Temporary Redshift database credentials.
pub struct RedshiftCredentials {
    /// Database user (e.g., "IAMR:role-name").
    pub db_user: String,
    /// Temporary database password.
    pub db_password: SecretString,
    /// When the credentials expire (ISO 8601).
    pub expiration: String,
}

impl std::fmt::Debug for RedshiftCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedshiftCredentials")
            .field("db_user", &self.db_user)
            .field("db_password", &"[REDACTED]")
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// Get temporary Redshift credentials using `GetClusterCredentialsWithIAM`.
///
/// This uses the newer IAM-identity-based API which auto-maps the IAM
/// identity to a database user, avoiding the need to specify `DbUser`.
pub async fn get_cluster_credentials(
    http_client: &reqwest::Client,
    cluster_id: &str,
    db_name: Option<&str>,
    duration_seconds: Option<u32>,
    region: &str,
    domain_suffix: &str,
    creds: &StsCredentials,
) -> Result<RedshiftCredentials> {
    let endpoint = format!("https://redshift.{region}.{domain_suffix}");

    let mut params: Vec<(&str, &str)> = vec![
        ("Action", "GetClusterCredentialsWithIAM"),
        ("Version", "2012-12-01"),
        ("ClusterIdentifier", cluster_id),
    ];

    let db_name_owned;
    if let Some(db) = db_name {
        db_name_owned = db.to_string();
        params.push(("DbName", &db_name_owned));
    }

    let duration_str;
    if let Some(dur) = duration_seconds {
        duration_str = dur.to_string();
        params.push(("DurationSeconds", &duration_str));
    }

    let response_body =
        sign_and_send_form_post(http_client, &endpoint, "redshift", region, creds, &params)
            .await
            .context("failed to call Redshift GetClusterCredentialsWithIAM")?;

    parse_redshift_xml_response(&response_body)
}

/// Parse Redshift `GetClusterCredentialsWithIAM` XML response.
fn parse_redshift_xml_response(xml: &str) -> Result<RedshiftCredentials> {
    let doc = roxmltree::Document::parse(xml).context("failed to parse Redshift XML response")?;

    // Find the result element
    let result_node = doc
        .descendants()
        .find(|n| n.has_tag_name("GetClusterCredentialsWithIAMResult"))
        .context("missing GetClusterCredentialsWithIAMResult in Redshift response")?;

    let extract = |tag: &str| -> Result<String> {
        result_node
            .children()
            .find(|n| n.has_tag_name(tag))
            .and_then(|n| n.text())
            .map(String::from)
            .with_context(|| format!("missing {tag} in Redshift response"))
    };

    let db_user = extract("DbUser")?;
    let db_password = extract("DbPassword")?;
    let expiration = extract("Expiration")?;

    Ok(RedshiftCredentials {
        db_user,
        db_password: SecretString::from(db_password),
        expiration,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_redshift_xml_response_valid() {
        let xml = r#"
<GetClusterCredentialsWithIAMResponse xmlns="http://redshift.amazonaws.com/doc/2012-12-01/">
  <GetClusterCredentialsWithIAMResult>
    <DbUser>IAMR:my-role</DbUser>
    <DbPassword>EXAMPLEpassword123</DbPassword>
    <Expiration>2025-02-27T19:44:51.001Z</Expiration>
  </GetClusterCredentialsWithIAMResult>
</GetClusterCredentialsWithIAMResponse>
        "#;

        let creds = parse_redshift_xml_response(xml).expect("valid XML");
        assert_eq!(creds.db_user, "IAMR:my-role");
        assert_eq!(creds.expiration, "2025-02-27T19:44:51.001Z");
        use secrecy::ExposeSecret;
        assert_eq!(creds.db_password.expose_secret(), "EXAMPLEpassword123");
    }

    #[test]
    fn test_parse_redshift_xml_response_missing_db_user() {
        let xml = r#"
<GetClusterCredentialsWithIAMResponse>
  <GetClusterCredentialsWithIAMResult>
    <DbPassword>EXAMPLEpassword</DbPassword>
    <Expiration>2025-02-27T19:44:51Z</Expiration>
  </GetClusterCredentialsWithIAMResult>
</GetClusterCredentialsWithIAMResponse>
        "#;

        let result = parse_redshift_xml_response(xml);
        assert!(result.is_err());
        let err = result.expect_err("should fail");
        assert!(err.to_string().contains("DbUser"));
    }

    #[test]
    fn test_parse_redshift_xml_response_missing_result() {
        let xml = r#"
<GetClusterCredentialsWithIAMResponse>
</GetClusterCredentialsWithIAMResponse>
        "#;

        let result = parse_redshift_xml_response(xml);
        assert!(result.is_err());
    }

    #[test]
    fn test_redshift_credentials_debug_redacted() {
        let creds = RedshiftCredentials {
            db_user: "IAMR:test".to_string(),
            db_password: SecretString::from("secret-pw".to_string()),
            expiration: "2025-01-01T00:00:00Z".to_string(),
        };
        let debug = format!("{creds:?}");
        assert!(!debug.contains("secret-pw"));
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("IAMR:test"));
    }
}
