// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS Redshift integration utilities.
//!
//! Provides SigV4-signed API calls to obtain temporary database credentials for
//! Amazon Redshift. Supports both provisioned clusters (`GetClusterCredentialsWithIAM`
//! on the `redshift` service) and Redshift Serverless workgroups (`GetCredentials`
//! on the `redshift-serverless` service).

use anyhow::{Context, Result};
use secrecy::SecretString;
use vouch_cli::{tr, tr_args};

use super::sigv4::{sign_and_send_form_post, sign_and_send_json_rpc};
use super::sts::StsCredentials;

/// Temporary Redshift database credentials.
pub(crate) struct RedshiftCredentials {
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
pub(crate) async fn get_cluster_credentials(
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
            .context(tr!("err-failed-call-redshift-getclustercredentialswithiam"))?;

    parse_redshift_xml_response(&response_body)
}

/// Get temporary Redshift Serverless credentials using `GetCredentials`.
///
/// The Redshift Serverless API uses JSON-RPC protocol (unlike the provisioned
/// Redshift API which uses XML query protocol). Requests use
/// `Content-Type: application/x-amz-json-1.1` with
/// `X-Amz-Target: RedshiftServerless.GetCredentials`.
pub(crate) async fn get_serverless_credentials(
    http_client: &reqwest::Client,
    workgroup: &str,
    db_name: Option<&str>,
    region: &str,
    domain_suffix: &str,
    creds: &StsCredentials,
) -> Result<RedshiftCredentials> {
    let endpoint = format!("https://redshift-serverless.{region}.{domain_suffix}");

    let mut body = serde_json::json!({
        "workgroupName": workgroup,
    });

    if let Some(db) = db_name {
        body.as_object_mut()
            .context(tr!("err-body-must-be-an-object"))?
            .insert(
                "dbName".to_string(),
                serde_json::Value::String(db.to_string()),
            );
    }

    let response_body = sign_and_send_json_rpc(
        http_client,
        &endpoint,
        "redshift-serverless",
        "RedshiftServerless.GetCredentials",
        region,
        creds,
        &body,
    )
    .await
    .context(tr!("err-failed-call-redshift-serverless-getcredentials"))?;

    parse_serverless_json_response(&response_body)
}

/// Parse Redshift `GetClusterCredentialsWithIAM` XML response.
fn parse_redshift_xml_response(xml: &str) -> Result<RedshiftCredentials> {
    let doc =
        roxmltree::Document::parse(xml).context(tr!("err-failed-parse-redshift-xml-response"))?;

    // Find the result element
    let result_node = doc
        .descendants()
        .find(|n| n.has_tag_name("GetClusterCredentialsWithIAMResult"))
        .context(tr!(
            "err-missing-getclustercredentialswithiamresult-in-redshi"
        ))?;

    let extract = |tag: &str| -> Result<String> {
        result_node
            .children()
            .find(|n| n.has_tag_name(tag))
            .and_then(|n| n.text())
            .map(String::from)
            .with_context(|| tr_args!("err-missing-redshift-response", tag = tag))
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

/// Parse Redshift Serverless `GetCredentials` JSON response.
///
/// Response format:
/// ```json
/// {
///   "dbUser": "IAMR:role-name",
///   "dbPassword": "...",
///   "expiration": 1740700800.0,
///   "nextRefreshTime": 1740700500.0
/// }
/// ```
///
/// The `expiration` field is a Unix timestamp (seconds since epoch),
/// which we convert to ISO 8601 for consistency with the provisioned API.
fn parse_serverless_json_response(json: &str) -> Result<RedshiftCredentials> {
    let parsed: serde_json::Value = serde_json::from_str(json)
        .context(tr!("err-failed-parse-redshift-serverless-json-response"))?;

    let db_user = parsed
        .get("dbUser")
        .and_then(|v| v.as_str())
        .context(tr!("err-missing-dbuser-in-redshift-serverless-response"))?
        .to_string();

    let db_password = parsed
        .get("dbPassword")
        .and_then(|v| v.as_str())
        .context(tr!(
            "err-missing-dbpassword-in-redshift-serverless-response"
        ))?
        .to_string();

    // expiration is a Unix timestamp (f64 seconds since epoch)
    let expiration_ts = parsed
        .get("expiration")
        .and_then(|v| v.as_f64())
        .context(tr!(
            "err-missing-expiration-in-redshift-serverless-response"
        ))?;

    #[expect(
        clippy::cast_possible_truncation,
        reason = "Redshift expiration is a Unix timestamp (seconds), well below i64::MAX"
    )]
    let expiration_secs = expiration_ts as i64;
    let expiration = jiff::Timestamp::from_second(expiration_secs)
        .context(tr!(
            "err-invalid-expiration-timestamp-in-redshift-serverless"
        ))?
        .to_string();

    Ok(RedshiftCredentials {
        db_user,
        db_password: SecretString::from(db_password),
        expiration,
    })
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
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
    fn test_parse_serverless_json_response_valid() {
        let json = r#"{
            "dbUser": "IAMR:my-role",
            "dbPassword": "EXAMPLEpassword456",
            "expiration": 1740700800.0,
            "nextRefreshTime": 1740700500.0
        }"#;

        let creds = parse_serverless_json_response(json).expect("valid JSON");
        assert_eq!(creds.db_user, "IAMR:my-role");
        use secrecy::ExposeSecret;
        assert_eq!(creds.db_password.expose_secret(), "EXAMPLEpassword456");
        // 1740700800 = 2025-02-28T00:00:00Z
        assert!(creds.expiration.contains("2025-02-28"));
    }

    #[test]
    fn test_parse_serverless_json_response_missing_db_user() {
        let json = r#"{
            "dbPassword": "EXAMPLEpassword",
            "expiration": 1740700800.0
        }"#;

        let result = parse_serverless_json_response(json);
        assert!(result.is_err());
        let err = result.expect_err("should fail");
        assert!(err.to_string().contains("dbUser"));
    }

    #[test]
    fn test_parse_serverless_json_response_missing_password() {
        let json = r#"{
            "dbUser": "IAMR:my-role",
            "expiration": 1740700800.0
        }"#;

        let result = parse_serverless_json_response(json);
        assert!(result.is_err());
        let err = result.expect_err("should fail");
        assert!(err.to_string().contains("dbPassword"));
    }

    #[test]
    fn test_parse_serverless_json_response_missing_expiration() {
        let json = r#"{
            "dbUser": "IAMR:my-role",
            "dbPassword": "EXAMPLEpassword"
        }"#;

        let result = parse_serverless_json_response(json);
        assert!(result.is_err());
        let err = result.expect_err("should fail");
        assert!(err.to_string().contains("expiration"));
    }

    #[test]
    fn test_parse_serverless_json_response_empty() {
        let result = parse_serverless_json_response("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_serverless_json_response_empty_object() {
        let result = parse_serverless_json_response("{}");
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
