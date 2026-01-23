//! Admin handlers for server setup and user management.

use crate::AppState;
use crate::config::config_keys;
use crate::db;
use axum::{
    Form,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use std::sync::Arc;

/// Query params for admin pages.
#[derive(Debug, Deserialize)]
pub struct AdminQuery {
    token: Option<String>,
}

/// Form data for OIDC configuration.
#[derive(Debug, Deserialize)]
pub struct OidcConfigForm {
    client_id: String,
    client_secret: String,
    allowed_domains: Option<String>,
    org_name: Option<String>,
}

/// Form data for testing OIDC configuration (empty, uses saved config).
#[derive(Debug, Deserialize)]
pub struct OidcTestForm {
    #[serde(default)]
    #[allow(dead_code)]
    _unused: Option<String>,
}

/// Check if the request is authorized for admin access.
fn is_admin_authorized(state: &AppState, query: &AdminQuery) -> bool {
    // Check bootstrap token
    if let Some(token) = &query.token
        && state.config.verify_bootstrap_token(token)
    {
        return true;
    }

    // For now, bootstrap token is the only way to access admin.
    // In a full implementation, you'd check OIDC session cookies here.
    false
}

/// HTML template for admin pages.
const ADMIN_STYLE: &str = r#"
<style>
    * { box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: #f5f5f5;
        margin: 0;
        padding: 20px;
    }
    .container {
        max-width: 800px;
        margin: 0 auto;
    }
    .card {
        background: white;
        border-radius: 12px;
        padding: 32px;
        margin-bottom: 24px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    h1 { color: #1a1a2e; margin: 0 0 8px; }
    h2 { color: #333; margin: 0 0 16px; font-size: 18px; }
    p { color: #666; margin: 0 0 16px; line-height: 1.5; }
    .step { margin-bottom: 24px; }
    .step-number {
        display: inline-block;
        width: 28px;
        height: 28px;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 50%;
        text-align: center;
        line-height: 28px;
        font-weight: 600;
        margin-right: 12px;
    }
    .step-title { font-weight: 600; color: #333; }
    label {
        display: block;
        font-weight: 500;
        color: #333;
        margin-bottom: 6px;
    }
    input[type="text"], input[type="password"] {
        width: 100%;
        padding: 12px;
        font-size: 14px;
        border: 2px solid #e0e0e0;
        border-radius: 8px;
        margin-bottom: 16px;
        font-family: monospace;
    }
    input:focus {
        outline: none;
        border-color: #667eea;
    }
    .code-box {
        background: #f8f9fa;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        padding: 12px 16px;
        font-family: monospace;
        font-size: 14px;
        margin: 12px 0;
        word-break: break-all;
    }
    button, .btn {
        display: inline-block;
        padding: 12px 24px;
        font-size: 14px;
        font-weight: 600;
        color: white;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border: none;
        border-radius: 8px;
        cursor: pointer;
        text-decoration: none;
        transition: transform 0.2s, box-shadow 0.2s;
    }
    button:hover, .btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
    }
    .btn-secondary {
        background: #6c757d;
        margin-right: 8px;
    }
    .btn-danger {
        background: #dc3545;
    }
    .btn-small {
        padding: 6px 12px;
        font-size: 12px;
    }
    .success {
        background: #d4edda;
        color: #155724;
        padding: 12px 16px;
        border-radius: 8px;
        margin-bottom: 16px;
    }
    .error {
        background: #f8d7da;
        color: #721c24;
        padding: 12px 16px;
        border-radius: 8px;
        margin-bottom: 16px;
    }
    .warning {
        background: #fff3cd;
        color: #856404;
        padding: 12px 16px;
        border-radius: 8px;
        margin-bottom: 16px;
    }
    table {
        width: 100%;
        border-collapse: collapse;
    }
    th, td {
        text-align: left;
        padding: 12px;
        border-bottom: 1px solid #e0e0e0;
    }
    th { font-weight: 600; color: #333; }
    .nav {
        display: flex;
        gap: 16px;
        margin-bottom: 24px;
    }
    .nav a {
        color: #667eea;
        text-decoration: none;
        font-weight: 500;
    }
    .nav a:hover { text-decoration: underline; }
    .badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 500;
    }
    .badge-success { background: #d4edda; color: #155724; }
    .badge-warning { background: #fff3cd; color: #856404; }
</style>
"#;

/// Admin setup wizard page.
/// GET /admin/setup
pub async fn setup_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AdminQuery>,
) -> Response {
    if !is_admin_authorized(&state, &query) {
        return (StatusCode::UNAUTHORIZED, Html(unauthorized_html())).into_response();
    }

    let token = query.token.as_deref().unwrap_or("");
    let redirect_uri = format!("{}/oauth/callback", state.config.verification_base_url);
    let oidc_configured = state.config.oidc_configured();

    let status_badge = if oidc_configured {
        r#"<span class="badge badge-success">Configured</span>"#
    } else {
        r#"<span class="badge badge-warning">Not Configured</span>"#
    };

    let current_client_id = state.config.oidc_client_id.as_deref().unwrap_or("");
    let current_domains = state
        .config
        .allowed_domains
        .as_ref()
        .map(|d| d.join(", "))
        .unwrap_or_default();
    let current_org = state.config.org_name.as_deref().unwrap_or("");

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vouch Admin Setup</title>
    {ADMIN_STYLE}
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/admin/setup?token={token}">Setup</a>
            <a href="/admin/users?token={token}">Users</a>
        </div>

        <div class="card">
            <h1>Vouch Admin Setup</h1>
            <p>Configure your Vouch server for Google Workspace authentication.</p>
        </div>

        <div class="card">
            <h2>Google OIDC Configuration {status_badge}</h2>

            <div class="step">
                <span class="step-number">1</span>
                <span class="step-title">Create Google Cloud OAuth App</span>
                <ol style="margin-top: 12px; padding-left: 48px; color: #666;">
                    <li>Go to <a href="https://console.cloud.google.com/apis/credentials" target="_blank">Google Cloud Console</a> &rarr; APIs & Services &rarr; Credentials</li>
                    <li>Click "Create Credentials" &rarr; "OAuth 2.0 Client ID"</li>
                    <li>Choose "Web application" as the application type</li>
                    <li>Add this redirect URI:</li>
                </ol>
                <div class="code-box">{redirect_uri}</div>
            </div>

            <div class="step">
                <span class="step-number">2</span>
                <span class="step-title">Enter Credentials</span>
                <form method="POST" action="/admin/setup/oidc?token={token}" style="margin-top: 16px;">
                    <label for="client_id">Client ID</label>
                    <input type="text" id="client_id" name="client_id" placeholder="123456789.apps.googleusercontent.com" value="{current_client_id}" required>

                    <label for="client_secret">Client Secret</label>
                    <input type="password" id="client_secret" name="client_secret" placeholder="GOCSPX-..." required>

                    <label for="org_name">Organization Name (optional)</label>
                    <input type="text" id="org_name" name="org_name" placeholder="Acme Corp" value="{current_org}">

                    <label for="allowed_domains">Allowed Email Domains (optional, comma-separated)</label>
                    <input type="text" id="allowed_domains" name="allowed_domains" placeholder="company.com, subsidiary.com" value="{current_domains}">

                    <div style="margin-top: 8px;">
                        <button type="submit">Save Configuration</button>
                    </div>
                </form>
            </div>
        </div>

        <div class="card">
            <h2>Test Configuration</h2>
            <p>Verify your OIDC settings work correctly before enabling.</p>
            <form method="POST" action="/admin/setup/test?token={token}" style="margin-top: 16px;">
                <input type="hidden" name="client_id" value="{current_client_id}">
                <input type="hidden" name="client_secret" value="">
                <button type="submit" class="btn-secondary" {}>Test Connection</button>
            </form>
        </div>
    </div>
</body>
</html>"#,
        if oidc_configured { "" } else { "disabled" }
    );

    Html(html).into_response()
}

/// Save OIDC configuration.
/// POST /admin/setup/oidc
pub async fn setup_save_oidc(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AdminQuery>,
    Form(form): Form<OidcConfigForm>,
) -> Response {
    if !is_admin_authorized(&state, &query) {
        return (StatusCode::UNAUTHORIZED, Html(unauthorized_html())).into_response();
    }

    let token = query.token.as_deref().unwrap_or("");

    // Validate inputs
    if form.client_id.trim().is_empty() || form.client_secret.trim().is_empty() {
        return Html(error_page(
            "Invalid Input",
            "Client ID and Client Secret are required.",
            &format!("/admin/setup?token={token}"),
        ))
        .into_response();
    }

    // Save to database
    let db = &state.db;

    if let Err(e) =
        db::set_config(db, config_keys::OIDC_ISSUER, "https://accounts.google.com").await
    {
        tracing::error!("Failed to save OIDC issuer: {}", e);
        return Html(error_page(
            "Database Error",
            "Failed to save configuration.",
            &format!("/admin/setup?token={token}"),
        ))
        .into_response();
    }

    if let Err(e) = db::set_config(db, config_keys::OIDC_CLIENT_ID, form.client_id.trim()).await {
        tracing::error!("Failed to save OIDC client ID: {}", e);
        return Html(error_page(
            "Database Error",
            "Failed to save configuration.",
            &format!("/admin/setup?token={token}"),
        ))
        .into_response();
    }

    if let Err(e) = db::set_config(
        db,
        config_keys::OIDC_CLIENT_SECRET,
        form.client_secret.trim(),
    )
    .await
    {
        tracing::error!("Failed to save OIDC client secret: {}", e);
        return Html(error_page(
            "Database Error",
            "Failed to save configuration.",
            &format!("/admin/setup?token={token}"),
        ))
        .into_response();
    }

    // Save optional fields
    if let Some(domains) = &form.allowed_domains {
        let domains = domains.trim();
        if !domains.is_empty()
            && let Err(e) = db::set_config(db, config_keys::ALLOWED_DOMAINS, domains).await
        {
            tracing::error!("Failed to save allowed domains: {}", e);
        }
    }

    if let Some(org_name) = &form.org_name {
        let org_name = org_name.trim();
        if !org_name.is_empty()
            && let Err(e) = db::set_config(db, config_keys::ORG_NAME, org_name).await
        {
            tracing::error!("Failed to save org name: {}", e);
        }
    }

    tracing::info!("OIDC configuration saved");

    // Redirect with success message
    Html(success_page(
        "Configuration Saved",
        "OIDC configuration has been saved successfully. The server will use the new configuration for subsequent requests. Note: You may need to restart the server for changes to take effect immediately.",
        &format!("/admin/setup?token={token}"),
    ))
    .into_response()
}

/// Test OIDC configuration.
/// POST /admin/setup/test
pub async fn setup_test_oidc(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AdminQuery>,
    Form(_form): Form<OidcTestForm>,
) -> Response {
    if !is_admin_authorized(&state, &query) {
        return (StatusCode::UNAUTHORIZED, Html(unauthorized_html())).into_response();
    }

    let token = query.token.as_deref().unwrap_or("");

    // Get current config
    let client_id = match &state.config.oidc_client_id {
        Some(id) => id.clone(),
        None => {
            return Html(error_page(
                "Not Configured",
                "OIDC is not configured. Please save your credentials first.",
                &format!("/admin/setup?token={token}"),
            ))
            .into_response();
        }
    };

    // Test by fetching Google's OIDC discovery document
    let client = reqwest::Client::new();
    let discovery_url = "https://accounts.google.com/.well-known/openid-configuration";

    match client.get(discovery_url).send().await {
        Ok(resp) if resp.status().is_success() => Html(success_page(
            "Connection Successful",
            &format!(
                "Successfully connected to Google's OIDC endpoint. Client ID: {}...{}",
                client_id.chars().take(8).collect::<String>(),
                client_id
                    .chars()
                    .rev()
                    .take(4)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect::<String>()
            ),
            &format!("/admin/setup?token={token}"),
        ))
        .into_response(),
        Ok(resp) => Html(error_page(
            "Connection Failed",
            &format!("Google OIDC endpoint returned status: {}", resp.status()),
            &format!("/admin/setup?token={token}"),
        ))
        .into_response(),
        Err(e) => Html(error_page(
            "Connection Failed",
            &format!("Failed to connect to Google: {e}"),
            &format!("/admin/setup?token={token}"),
        ))
        .into_response(),
    }
}

/// List enrolled users.
/// GET /admin/users
#[allow(clippy::format_collect)]
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AdminQuery>,
) -> Response {
    if !is_admin_authorized(&state, &query) {
        return (StatusCode::UNAUTHORIZED, Html(unauthorized_html())).into_response();
    }

    let token = query.token.as_deref().unwrap_or("");

    let users = match db::list_users_with_auth_count(&state.db).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Failed to list users: {}", e);
            return Html(error_page(
                "Database Error",
                "Failed to load users.",
                &format!("/admin/setup?token={token}"),
            ))
            .into_response();
        }
    };

    let user_rows: String = if users.is_empty() {
        r#"<tr><td colspan="4" style="text-align: center; color: #666;">No users enrolled yet.</td></tr>"#.to_string()
    } else {
        users
            .iter()
            .map(|u| {
                format!(
                    r#"<tr>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>
                            <form method="POST" action="/admin/users/{}/delete?token={}" style="display: inline;">
                                <button type="submit" class="btn-danger btn-small" onclick="return confirm('Delete user {}?')">Delete</button>
                            </form>
                        </td>
                    </tr>"#,
                    html_escape(&u.email),
                    u.authenticator_count,
                    html_escape(&u.created_at),
                    html_escape(&u.id),
                    token,
                    html_escape(&u.email)
                )
            })
            .collect()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vouch Admin - Users</title>
    {ADMIN_STYLE}
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/admin/setup?token={token}">Setup</a>
            <a href="/admin/users?token={token}">Users</a>
        </div>

        <div class="card">
            <h1>Enrolled Users</h1>
            <p>Manage users who have enrolled security keys.</p>
        </div>

        <div class="card">
            <table>
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>Keys</th>
                        <th>Enrolled</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {user_rows}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>"#
    );

    Html(html).into_response()
}

/// Delete a user.
/// POST /admin/users/:id/delete
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AdminQuery>,
    Path(user_id): Path<String>,
) -> Response {
    if !is_admin_authorized(&state, &query) {
        return (StatusCode::UNAUTHORIZED, Html(unauthorized_html())).into_response();
    }

    let token = query.token.as_deref().unwrap_or("");

    if let Err(e) = db::delete_user(&state.db, &user_id).await {
        tracing::error!("Failed to delete user: {}", e);
        return Html(error_page(
            "Database Error",
            "Failed to delete user.",
            &format!("/admin/users?token={token}"),
        ))
        .into_response();
    }

    tracing::info!("Deleted user: {}", user_id);

    Redirect::to(&format!("/admin/users?token={token}")).into_response()
}

/// HTML for unauthorized access.
fn unauthorized_html() -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unauthorized</title>
    {ADMIN_STYLE}
</head>
<body>
    <div class="container">
        <div class="card" style="text-align: center;">
            <h1 style="color: #dc3545;">Unauthorized</h1>
            <p>You need a valid admin token to access this page.</p>
            <p style="font-size: 14px; color: #999;">
                Set <code>VOUCH_ADMIN_BOOTSTRAP_TOKEN</code> and visit<br>
                <code>/admin/setup?token=YOUR_TOKEN</code>
            </p>
        </div>
    </div>
</body>
</html>"#
    )
}

/// HTML for error page with back link.
fn error_page(title: &str, message: &str, back_url: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - {title}</title>
    {ADMIN_STYLE}
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="error">
                <strong>{title}</strong><br>
                {message}
            </div>
            <a href="{back_url}" class="btn">Back</a>
        </div>
    </div>
</body>
</html>"#
    )
}

/// HTML for success page with continue link.
fn success_page(title: &str, message: &str, continue_url: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Success - {title}</title>
    {ADMIN_STYLE}
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="success">
                <strong>{title}</strong><br>
                {message}
            </div>
            <a href="{continue_url}" class="btn">Continue</a>
        </div>
    </div>
</body>
</html>"#
    )
}

/// Simple HTML escaping.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
