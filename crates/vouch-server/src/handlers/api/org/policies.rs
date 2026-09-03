// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Device posture policy validation API — `POST /api/v1/org/policies/validate`.

use crate::error::ServiceError;
use crate::handlers::extractors::OrgAdmin;
use crate::services::policy as posture;
use axum::Json;
use axum::http::StatusCode;
use serde::Deserialize;

/// Response for the policy editor's validate call.
#[derive(Debug, serde::Serialize)]
pub(crate) struct ValidateResponse {
    pub valid: bool,
    /// The text that was validated — generated from `rule`, or echoed from
    /// `policy_text`. Absent only when generation itself failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_result: Option<TestResult>,
}

/// Result of dry-running policy text against the sample device.
#[derive(Debug, serde::Serialize)]
pub(crate) struct TestResult {
    pub pass: bool,
    /// True when the verdict reflects an empty event history rather than
    /// the policy's logic. The editor renders the explanation from the
    /// i18n catalog.
    pub reads_history: bool,
}

/// Request to validate a policy (JSON API for the policy editor): raw
/// `policy_text` or a builder `rule`, exactly one of the two.
#[derive(Debug, Deserialize)]
pub(crate) struct ValidateRequest {
    #[serde(default)]
    pub policy_text: Option<String>,
    #[serde(default)]
    pub rule: Option<posture::rule::RuleSpec>,
    /// Which decision point to dry-run `policy_text` against; a `rule`
    /// carries its own. Defaults to token issuance.
    #[serde(default)]
    pub decision: Option<posture::catalog::DecisionPoint>,
    /// Device the dry run evaluates; the built-in sample device when
    /// absent.
    #[serde(default)]
    pub test_posture: Option<vouch_common::posture::DevicePosture>,
}

fn invalid(text: Option<String>, error: String) -> Json<ValidateResponse> {
    Json(ValidateResponse {
        valid: false,
        policy_text: text,
        error: Some(error),
        test_result: None,
    })
}

/// POST /api/v1/org/policies/validate — validate a policy (JSON).
pub(crate) async fn validate_policy_api(
    _admin: OrgAdmin,
    Json(req): Json<ValidateRequest>,
) -> Result<Json<ValidateResponse>, ServiceError> {
    // Authenticate before parsing: policy text is attacker-influenced
    // input, so only an authenticated org admin may reach the parser.
    let (policy_text, decision) = match (req.policy_text, req.rule) {
        (Some(_), Some(_)) | (None, None) => {
            return Err(ServiceError::api(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Provide exactly one of policy_text or rule",
            ));
        }
        (Some(text), None) => (
            text,
            req.decision
                .unwrap_or(posture::catalog::DecisionPoint::IssueToken),
        ),
        (None, Some(rule)) => match posture::rule::generate(&rule) {
            Ok(text) => (text, rule.decision),
            Err(e) => return Ok(invalid(None, e.to_string())),
        },
    };

    if policy_text.is_empty() || policy_text.chars().count() > posture::catalog::MAX_POLICY_TEXT_LEN
    {
        return Ok(invalid(
            Some(policy_text),
            format!(
                "Policy text must be between 1 and {} characters",
                posture::catalog::MAX_POLICY_TEXT_LEN
            ),
        ));
    }

    if let Err(e) = posture::validate_policy_text(&policy_text) {
        return Ok(invalid(Some(policy_text), format!("{e}")));
    }

    let test_posture = req
        .test_posture
        .unwrap_or_else(posture::catalog::sample_posture);
    let test_result = match posture::test_policy_text(&policy_text, &test_posture, decision) {
        Ok(result) => Some(TestResult {
            pass: result.pass,
            reads_history: result.reads_history,
        }),
        Err(_) => Some(TestResult {
            pass: false,
            reads_history: false,
        }),
    };

    Ok(Json(ValidateResponse {
        valid: true,
        policy_text: Some(policy_text),
        error: None,
        test_result,
    }))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use axum::http::StatusCode;

    use crate::test_utils::*;

    // ── Validation API — accepted input ──────────────────────────────────────

    #[tokio::test]
    async fn test_policy_validate_valid_expression() {
        let (app, state) = test_app().await;
        let (_admin, token) = create_test_org_admin(&state).await;
        let auth = format!("Bearer {token}");

        let body = serde_json::json!({
            "policy_text": "forbid (principal, action == Vouch::Action::\"IssueToken\", resource) unless { context.device.os == \"macos\" };"
        });
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::OK,
            "valid policy text should return 200: {resp}"
        );
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(json["valid"], true, "valid field must be true");
        assert!(
            json.get("error").is_none() || json["error"].is_null(),
            "no error for valid policy text"
        );
        assert_eq!(
            json["test_result"]["pass"], true,
            "without test_posture the built-in sample device is used, which runs macOS"
        );
        assert_eq!(
            json["policy_text"], body["policy_text"],
            "raw policy_text is echoed back"
        );
    }

    #[tokio::test]
    async fn test_policy_validate_with_test_posture() {
        let (app, state) = test_app().await;
        let (_admin, token) = create_test_org_admin(&state).await;
        let auth = format!("Bearer {token}");

        let body = serde_json::json!({
            "policy_text": "forbid (principal, action == Vouch::Action::\"IssueToken\", resource) unless { context.device.os == \"macos\" };",
            "test_posture": {
                "type": "device_posture",
                "posture_version": 1,
                "os": "macos"
            }
        });
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::OK,
            "valid policy with matching posture should return 200: {resp}"
        );
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(json["valid"], true, "valid must be true");
        assert_eq!(
            json["test_result"]["pass"], true,
            "test_result.pass must be true when posture matches"
        );
    }

    #[tokio::test]
    async fn test_policy_validate_with_failing_test_posture() {
        let (app, state) = test_app().await;
        let (_admin, token) = create_test_org_admin(&state).await;
        let auth = format!("Bearer {token}");

        // Expression checks for macos but posture reports linux
        let body = serde_json::json!({
            "policy_text": "forbid (principal, action == Vouch::Action::\"IssueToken\", resource) unless { context.device.os == \"macos\" };",
            "test_posture": {
                "type": "device_posture",
                "posture_version": 1,
                "os": "linux"
            }
        });
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "Response should be 200: {resp}");
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(json["valid"], true, "the policy text itself is valid");
        assert_eq!(
            json["test_result"]["pass"], false,
            "test_result.pass must be false when posture does not match"
        );
    }

    // ── Validation API — rejected input ──────────────────────────────────────

    #[tokio::test]
    async fn test_policy_validate_accepts_builder_rule() {
        let (app, state) = test_app().await;
        let (_admin, token) = create_test_org_admin(&state).await;
        let auth = format!("Bearer {token}");

        let body = serde_json::json!({
            "rule": {
                "decision": "issue_token",
                "body": { "kind": "device", "conditions": [
                    { "kind": "field", "field": "disk_encryption_enabled", "op": "eq", "value": true }
                ]}
            }
        });
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "builder rule must validate: {resp}");
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(json["valid"], true, "{resp}");
        let text = json["policy_text"].as_str().expect("generated text");
        assert!(
            text.contains("unless {\n    context.device.disk_encryption_enabled\n}"),
            "generated text carries the condition: {text}"
        );
        assert_eq!(
            json["test_result"]["pass"], true,
            "the sample device has disk encryption on"
        );
    }

    #[tokio::test]
    async fn test_policy_validate_rule_dry_runs_as_its_own_decision() {
        let (app, state) = test_app().await;
        let (_admin, token) = create_test_org_admin(&state).await;
        let auth = format!("Bearer {token}");

        // A step-up rule on exchange: with no history it must DENY when
        // evaluated as an exchange (as IssueToken it would trivially pass).
        let body = serde_json::json!({
            "rule": {
                "decision": "exchange_token",
                "body": { "kind": "history", "conditions": [
                    { "shape": "not_happened_within", "event": "login_success",
                      "window": { "amount": 15, "unit": "m" } }
                ]}
            }
        });
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{resp}");
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(json["valid"], true, "{resp}");
        assert_eq!(
            json["test_result"]["reads_history"], true,
            "a temporal rule is history-dependent"
        );
        assert_eq!(
            json["test_result"]["pass"], false,
            "an exchange-scoped forbid must fire when dry-run as an exchange"
        );
    }

    #[tokio::test]
    async fn test_policy_validate_rejects_both_or_neither_input() {
        let (app, state) = test_app().await;
        let (_admin, token) = create_test_org_admin(&state).await;
        let auth = format!("Bearer {token}");

        for body in [
            serde_json::json!({}),
            serde_json::json!({
                "policy_text": "permit (principal, action, resource);",
                "rule": {
                    "decision": "issue_token",
                    "body": { "kind": "device", "conditions": [
                        { "kind": "field", "field": "tty", "op": "eq", "value": true }
                    ]}
                }
            }),
        ] {
            let (status, resp) = http_post_json(
                &app,
                "/api/v1/org/policies/validate",
                &body.to_string(),
                &[("Authorization", &auth)],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "exactly one of policy_text/rule is required: {resp}"
            );
        }
    }

    #[tokio::test]
    async fn test_policy_validate_reports_rule_errors_as_invalid() {
        let (app, state) = test_app().await;
        let (_admin, token) = create_test_org_admin(&state).await;
        let auth = format!("Bearer {token}");

        // Device conditions on exchange cannot generate.
        let body = serde_json::json!({
            "rule": {
                "decision": "exchange_token",
                "body": { "kind": "device", "conditions": [
                    { "kind": "field", "field": "tty", "op": "eq", "value": true }
                ]}
            }
        });
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{resp}");
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(json["valid"], false, "{resp}");
        assert!(
            json["error"].as_str().unwrap().contains("token issuance"),
            "the error explains the device-on-exchange restriction: {resp}"
        );
    }

    #[tokio::test]
    async fn test_policy_validate_requires_auth() {
        let (app, _state) = test_app().await;

        let body = serde_json::json!({"policy_text": "forbid (principal, action == Vouch::Action::\"IssueToken\", resource) unless { context.device.os == \"macos\" };"});
        let (status, _resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "Unauthenticated request must return 401"
        );
    }

    #[tokio::test]
    async fn test_policy_validate_requires_org_admin() {
        let (app, state) = test_app().await;
        let org = create_test_org(&state.store, "example.com").await;
        let member =
            create_test_user_in_org(&state.store, "member@example.com", &org.id, false).await;
        let auth_id = create_test_authenticator(&state.store, &member.id).await;
        let token = create_test_session_with(
            &state,
            TestSessionSpec {
                user_id: &member.id,
                email: &member.email,
                auth_id: Some(&auth_id),
                ..Default::default()
            },
        )
        .await;
        let auth = format!("Bearer {token}");

        let body = serde_json::json!({"policy_text": "forbid (principal, action == Vouch::Action::\"IssueToken\", resource) unless { context.device.os == \"macos\" };"});
        let (status, _resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "Non-admin user must receive 403"
        );
    }

    #[tokio::test]
    async fn test_policy_validate_empty_expression() {
        let (app, state) = test_app().await;
        let (_admin, token) = create_test_org_admin(&state).await;
        let auth = format!("Bearer {token}");

        let body = serde_json::json!({"policy_text": ""});
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::OK,
            "Empty expression returns 200: {resp}"
        );
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            json["valid"], false,
            "valid must be false for empty expression"
        );
        assert!(
            json["error"].as_str().is_some(),
            "error message must be present"
        );
    }

    #[tokio::test]
    async fn test_policy_validate_too_long_expression() {
        let (app, state) = test_app().await;
        let (_admin, token) = create_test_org_admin(&state).await;
        let auth = format!("Bearer {token}");

        let long_expr = "a".repeat(4097);
        let body = serde_json::json!({"policy_text": long_expr});
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::OK,
            "Over-length expression returns 200: {resp}"
        );
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            json["valid"], false,
            "valid must be false for >4096 char expression"
        );
        assert!(
            json["error"].as_str().is_some(),
            "error message must be present"
        );
    }

    #[tokio::test]
    async fn test_policy_validate_invalid_syntax() {
        let (app, state) = test_app().await;
        let (_admin, token) = create_test_org_admin(&state).await;
        let auth = format!("Bearer {token}");

        // An unterminated string literal cannot parse
        let body = serde_json::json!({"policy_text": "posture.os == \"unterminated"});
        let (status, resp) = http_post_json(
            &app,
            "/api/v1/org/policies/validate",
            &body.to_string(),
            &[("Authorization", &auth)],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "Invalid policy returns 200: {resp}");
        let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            json["valid"], false,
            "valid must be false for invalid syntax"
        );
        assert!(
            json["error"].as_str().is_some(),
            "error message must be present for invalid policy text"
        );
    }
}
