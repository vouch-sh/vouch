// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS account access runtime (`account-access-runtime`) API.
//!
//! rest-json over `GET`, authenticated with an IAM Identity Center bearer
//! token in `Authorization` (no SigV4). Every request is scoped to an
//! account access manager tenant (`aa-…`). The token must carry the
//! `account_access:read_only` scope for `ListRoles` and
//! `account_access:assume` for `GetRoleCredentials`; a token without them
//! is rejected with 401 `UnauthorizedException`.
//!
//! Like the control plane, the service is dualstack `.api.aws` only and
//! commercial-partition only.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use vouch_cli::tr;
use vouch_common::aws::Partition;

use super::account_access::{EntitledRole, THROTTLE_BACKOFF_MS};
use super::sigv4::aws_api_error;
use super::sts::StsCredentials;
use crate::exit_code::CliError;

/// Service name recorded on [`CliError::AwsApi`] errors.
const SERVICE: &str = "account-access-runtime";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListRolesResponse {
    #[serde(default)]
    roles: Vec<AccessDetails>,
    next_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccessDetails {
    account_id: Option<String>,
    account_name: Option<String>,
    role_arn: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetRoleCredentialsResponse {
    credentials_details: CredentialsDetails,
}

/// `CredentialsDetails` is a union; `programmaticAccess` is the member
/// returned for `accessType=PROGRAMMATIC_ACCESS`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialsDetails {
    programmatic_access: Option<ProgrammaticAccessDetails>,
}

/// The secret fields are plain `String` here (the workspace builds
/// `secrecy` without its `serde` feature) and are wrapped into
/// `SecretString` in [`RuntimeClient::get_role_credentials`].
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProgrammaticAccessDetails {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    /// RFC 3339 timestamp.
    expiration: String,
}

/// An account access runtime client for one tenant and one user's token.
///
/// Owns its fields so discovery can share one client across concurrent
/// probe tasks.
pub(crate) struct RuntimeClient {
    http_client: reqwest::Client,
    endpoint: String,
    tenant_id: String,
    access_token: SecretString,
    /// Delays between `ThrottlingException` retries.
    backoff_ms: &'static [u64],
}

impl RuntimeClient {
    /// A client for the runtime endpoint in `region`, the region of the
    /// Identity Center instance the account access manager application uses.
    ///
    /// # Errors
    ///
    /// Fails outside the commercial partition, where the service does not
    /// exist.
    pub(crate) fn new(
        http_client: reqwest::Client,
        region: &str,
        tenant_id: String,
        access_token: SecretString,
    ) -> Result<Self> {
        let endpoint = Partition::from_region(region).account_access_runtime_endpoint(region)?;
        Ok(Self {
            http_client,
            endpoint,
            tenant_id,
            access_token,
            backoff_ms: &THROTTLE_BACKOFF_MS,
        })
    }

    /// List the roles the token's user is entitled to.
    ///
    /// Paginates automatically with a 100-page safety cap. Entries missing
    /// the role ARN or account ID are skipped with a warning, so a shape
    /// change does not read as "no entitlements".
    pub(crate) async fn list_roles(&self) -> Result<Vec<EntitledRole>> {
        let mut roles = Vec::new();
        let mut next_token: Option<String> = None;
        let max_pages: u32 = 100;

        for page in 0..max_pages {
            let mut query = vec![("tenantId", self.tenant_id.as_str()), ("maxResults", "100")];
            if let Some(token) = next_token.as_deref() {
                query.push(("nextToken", token));
            }
            let body = self
                .get_with_throttle_retry("/access", &query)
                .await
                .context(tr!("err-failed-list-aam-runtime-roles"))?;
            let resp: ListRolesResponse = serde_json::from_str(&body)
                .context(tr!("err-failed-parse-account-access-response"))?;

            for entry in resp.roles {
                let (Some(role_arn), Some(account)) = (entry.role_arn, entry.account_id) else {
                    tracing::warn!("skipping ListRoles entry without a role ARN or account ID");
                    continue;
                };
                roles.push(EntitledRole {
                    role_arn,
                    account,
                    account_name: entry.account_name,
                });
            }

            match resp.next_token {
                Some(token) if !token.is_empty() => next_token = Some(token),
                _ => break,
            }
            if page == max_pages.saturating_sub(1) {
                tracing::warn!("account access ListRoles reached {max_pages}-page safety cap");
            }
        }

        Ok(roles)
    }

    /// Get temporary credentials for an entitled role.
    ///
    /// `session_name` is the role session name CloudTrail records.
    ///
    /// # Errors
    ///
    /// A role the user is not entitled to, or whose trust policy does not
    /// trust account access manager, fails with 403 `AccessDeniedException`,
    /// which `exit_code::aws_access_denied` recognizes.
    pub(crate) async fn get_role_credentials(
        &self,
        role_arn: &str,
        session_name: &str,
    ) -> Result<StsCredentials> {
        let query = [
            ("tenantId", self.tenant_id.as_str()),
            ("roleArn", role_arn),
            ("accessType", "PROGRAMMATIC_ACCESS"),
            ("sessionName", session_name),
        ];
        let body = self
            .get_with_throttle_retry("/access/credentials", &query)
            .await
            .context(tr!("err-failed-get-aam-runtime-role-credentials"))?;
        let resp: GetRoleCredentialsResponse =
            serde_json::from_str(&body).context(tr!("err-failed-parse-account-access-response"))?;
        let details = resp
            .credentials_details
            .programmatic_access
            .context(tr!("err-failed-parse-account-access-response"))?;
        let expiration: jiff::Timestamp = details
            .expiration
            .parse()
            .context(tr!("err-failed-parse-account-access-response"))?;

        Ok(StsCredentials {
            access_key_id: details.access_key_id,
            secret_access_key: SecretString::from(details.secret_access_key),
            session_token: SecretString::from(details.session_token),
            expiration,
        })
    }

    /// Send one `GET`, retrying `ThrottlingException` with bounded backoff.
    ///
    /// A 401 gains a context line naming the scopes, the usual cause being
    /// a Vouch application that lacks them.
    async fn get_with_throttle_retry(&self, path: &str, query: &[(&str, &str)]) -> Result<String> {
        let url = format!("{}{path}", self.endpoint);
        let mut backoff = self.backoff_ms.iter();
        loop {
            let response = self
                .http_client
                .get(&url)
                .bearer_auth(self.access_token.expose_secret())
                .query(query)
                .send()
                .await
                .context(tr!("err-failed-send-aws-api-request"))?;

            let status = response.status();
            if status.is_success() {
                return response
                    .text()
                    .await
                    .context(tr!("err-failed-read-aws-api-response-body"));
            }

            let err = aws_api_error(response, SERVICE).await;
            if status == reqwest::StatusCode::UNAUTHORIZED {
                return Err(
                    anyhow::Error::from(err).context(tr!("aws-err-aam-runtime-unauthorized"))
                );
            }
            let throttled = matches!(
                &err,
                CliError::AwsApi { code: Some(code), .. } if code == "ThrottlingException"
            ) || status == reqwest::StatusCode::TOO_MANY_REQUESTS;
            if !throttled {
                return Err(err.into());
            }
            let Some(delay_ms) = backoff.next() else {
                return Err(err.into());
            };
            tracing::debug!("account-access-runtime {path} throttled; retrying in {delay_ms}ms");
            tokio::time::sleep(std::time::Duration::from_millis(*delay_ms)).await;
        }
    }

    /// Point the client at a mock server, retrying throttles without delay.
    #[cfg(test)]
    fn with_endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = endpoint;
        self.backoff_ms = &[0; THROTTLE_BACKOFF_MS.len()];
        self
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use crate::exit_code;
    use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TENANT: &str = "aa-trxjin7wp";
    const ROLE: &str = "arn:aws:iam::486135724840:role/vouch/VouchReadOnly";

    fn new_client(region: &str) -> Result<RuntimeClient> {
        RuntimeClient::new(
            reqwest::Client::new(),
            region,
            TENANT.to_string(),
            SecretString::from("idc-token"),
        )
    }

    fn client(server: &MockServer) -> RuntimeClient {
        new_client("us-east-1")
            .expect("commercial region")
            .with_endpoint(server.uri())
    }

    #[test]
    fn new_targets_commercial_dualstack_endpoint() {
        let client = new_client("us-east-1").expect("commercial");
        assert_eq!(
            client.endpoint,
            "https://account-access-runtime.us-east-1.api.aws"
        );
    }

    #[test]
    fn new_rejects_non_commercial_partition() {
        assert!(new_client("us-gov-west-1").is_err());
    }

    #[tokio::test]
    async fn list_roles_sends_bearer_and_tenant_and_follows_pagination() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/access"))
            .and(header("authorization", "Bearer idc-token"))
            .and(query_param("tenantId", TENANT))
            .and(query_param_is_missing("nextToken"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"nextToken":"page-2","roles":[{{"accountId":"486135724840",
                   "accountName":"vouch-prod","isFavorite":false,"roleArn":"{ROLE}"}}]}}"#
            )))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/access"))
            .and(query_param("nextToken", "page-2"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"nextToken":null,"roles":[
                    {"accountId":"111122223333","roleArn":"arn:aws:iam::111122223333:role/Dev"},
                    {"accountId":"111122223333"}
                ]}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;

        let roles = client(&server).list_roles().await.expect("list roles");

        let arns: Vec<&str> = roles.iter().map(|r| r.role_arn.as_str()).collect();
        assert_eq!(arns, vec![ROLE, "arn:aws:iam::111122223333:role/Dev"]);
        assert_eq!(
            roles.first().and_then(|r| r.account_name.as_deref()),
            Some("vouch-prod")
        );
    }

    #[tokio::test]
    async fn get_role_credentials_requests_programmatic_access_with_session_name() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/access/credentials"))
            .and(header("authorization", "Bearer idc-token"))
            .and(query_param("tenantId", TENANT))
            .and(query_param("roleArn", ROLE))
            .and(query_param("accessType", "PROGRAMMATIC_ACCESS"))
            .and(query_param("sessionName", "jplock@vouch.sh"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"credentialsDetails":{"programmaticAccess":{
                    "accessKeyId":"ASIAEXAMPLE","secretAccessKey":"secret",
                    "sessionToken":"session","expiration":"2026-11-05T21:35:37Z",
                    "expiresAt":1.793914537E9}}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;

        let creds = client(&server)
            .get_role_credentials(ROLE, "jplock@vouch.sh")
            .await
            .expect("credentials");

        assert_eq!(creds.access_key_id, "ASIAEXAMPLE");
        assert_eq!(creds.secret_access_key.expose_secret(), "secret");
        assert_eq!(creds.session_token.expose_secret(), "session");
        assert_eq!(creds.expiration.to_string(), "2026-11-05T21:35:37Z");
    }

    #[tokio::test]
    async fn get_role_credentials_without_programmatic_access_member_is_an_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/access/credentials"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"credentialsDetails":{}}"#),
            )
            .mount(&server)
            .await;

        let result = client(&server)
            .get_role_credentials(ROLE, "jplock@vouch.sh")
            .await;
        assert!(result.is_err());
    }

    /// The live service answers a token without the scopes this way.
    #[tokio::test]
    async fn unauthorized_names_the_missing_scopes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/access"))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header(
                        "x-amzn-errortype",
                        "UnauthorizedException:http://internal.amazon.com/coral/x/",
                    )
                    .set_body_string(r#"{"message":"Authorization failed"}"#),
            )
            .mount(&server)
            .await;

        let err = client(&server)
            .list_roles()
            .await
            .expect_err("401 must fail");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("account_access:assume"),
            "message should name the scopes: {rendered}"
        );
        assert!(exit_code::aws_error_code_matches(
            &err,
            "UnauthorizedException"
        ));
        assert!(!exit_code::aws_access_denied(&err));
    }

    #[tokio::test]
    async fn access_denied_is_classified_as_a_denial() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/access/credentials"))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header("x-amzn-errortype", "AccessDeniedException")
                    .set_body_string(r#"{"message":"not entitled"}"#),
            )
            .mount(&server)
            .await;

        let err = client(&server)
            .get_role_credentials(ROLE, "jplock@vouch.sh")
            .await
            .expect_err("403 must fail");
        assert!(exit_code::aws_access_denied(&err));
    }

    #[tokio::test]
    async fn throttling_is_retried_then_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/access"))
            .respond_with(
                ResponseTemplate::new(429).insert_header("x-amzn-errortype", "ThrottlingException"),
            )
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/access"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"roles":[],"nextToken":null}"#),
            )
            .expect(1)
            .mount(&server)
            .await;

        let roles = client(&server).list_roles().await.expect("retried");
        assert!(roles.is_empty());
    }

    #[tokio::test]
    async fn throttling_gives_up_after_the_backoff_schedule() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/access"))
            .respond_with(
                ResponseTemplate::new(429).insert_header("x-amzn-errortype", "ThrottlingException"),
            )
            .expect(
                u64::try_from(THROTTLE_BACKOFF_MS.len())
                    .expect("small")
                    .saturating_add(1),
            )
            .mount(&server)
            .await;

        let err = client(&server)
            .list_roles()
            .await
            .expect_err("persistent throttling must fail");
        assert!(exit_code::aws_error_code_matches(
            &err,
            "ThrottlingException"
        ));
    }
}
