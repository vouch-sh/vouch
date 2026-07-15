// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS credential (OIDC token issuance) audit-log operations.

use super::audit::{AuditEventKind, AuditStore};
use super::documents::audit::AwsCredentialAuditData;
use anyhow::Result;

/// Log an AWS credential event (audit log).
pub async fn log_aws_credential_event(
    audit: &AuditStore,
    user_id: &str,
    user_email: &str,
    mut data: AwsCredentialAuditData,
    ip: Option<std::net::IpAddr>,
) -> Result<String> {
    data.client_ip = ip.map(|a| a.to_string());
    (data.country_code, data.asn, data.org_name) = crate::geo::audit_fields(ip);
    let data_json = serde_json::to_string(&data)?;

    audit
        .insert_event(
            AuditEventKind::AwsCredential,
            Some(user_id),
            Some(user_email),
            &data_json,
        )
        .await
}
