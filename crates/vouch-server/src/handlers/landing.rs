//! Landing page handler for user discovery.

use crate::AppState;
use axum::{extract::State, response::Html};
use std::sync::Arc;

/// Landing page showing enrollment instructions.
/// GET /
#[allow(clippy::unused_async, clippy::too_many_lines)]
pub async fn landing_page(State(state): State<Arc<AppState>>) -> Html<String> {
    let server_url = &state.config.verification_base_url;
    let org_name = state.config.get_org_display_name();

    // Build download links section if any are configured
    let download_section = build_download_section(&state.config);

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vouch - {org_name}</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 16px;
            padding: 48px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 600px;
            width: 100%;
        }}
        .logo {{
            font-size: 48px;
            margin-bottom: 16px;
        }}
        h1 {{
            margin: 0 0 8px;
            font-size: 28px;
            color: #1a1a2e;
        }}
        .subtitle {{
            color: #666;
            margin: 0 0 32px;
            font-size: 16px;
        }}
        .section {{
            margin-bottom: 32px;
        }}
        .section-title {{
            font-weight: 600;
            color: #333;
            margin-bottom: 12px;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .code-box {{
            background: #1a1a2e;
            color: #4ade80;
            padding: 16px 20px;
            border-radius: 8px;
            font-family: 'SF Mono', Monaco, 'Courier New', monospace;
            font-size: 14px;
            overflow-x: auto;
            position: relative;
        }}
        .code-box::before {{
            content: '$';
            color: #888;
            margin-right: 8px;
        }}
        .copy-btn {{
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            background: #333;
            border: none;
            color: #888;
            padding: 6px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            transition: all 0.2s;
        }}
        .copy-btn:hover {{
            background: #444;
            color: #fff;
        }}
        .download-links {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }}
        .download-btn {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 12px 20px;
            background: #f5f5f5;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            color: #333;
            text-decoration: none;
            font-weight: 500;
            transition: all 0.2s;
        }}
        .download-btn:hover {{
            border-color: #667eea;
            background: #f0f0ff;
        }}
        .info-box {{
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 16px;
            border-radius: 0 8px 8px 0;
            margin-top: 8px;
        }}
        .info-box p {{
            margin: 0;
            color: #666;
            font-size: 14px;
        }}
        .features {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin-top: 24px;
        }}
        .feature {{
            text-align: center;
            padding: 16px;
        }}
        .feature-icon {{
            font-size: 24px;
            margin-bottom: 8px;
        }}
        .feature-text {{
            font-size: 13px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🔐</div>
        <h1>Welcome to Vouch</h1>
        <p class="subtitle">{org_name}'s hardware-backed authentication system</p>

        <div class="section">
            <div class="section-title">Enroll Your Security Key</div>
            <div class="code-box">
                vouch enroll --server {server_url}
                <button class="copy-btn" onclick="copyCommand(this, 'vouch enroll --server {server_url}')">Copy</button>
            </div>
            <div class="info-box">
                <p>This command will open a browser window for verification. Have your YubiKey ready.</p>
            </div>
        </div>

        {download_section}

        <div class="section">
            <div class="section-title">Already Enrolled?</div>
            <div class="code-box">
                vouch login --server {server_url}
                <button class="copy-btn" onclick="copyCommand(this, 'vouch login --server {server_url}')">Copy</button>
            </div>
        </div>

        <div class="features">
            <div class="feature">
                <div class="feature-icon">🔑</div>
                <div class="feature-text">Hardware-backed authentication</div>
            </div>
            <div class="feature">
                <div class="feature-icon">⏱️</div>
                <div class="feature-text">Short-lived credentials</div>
            </div>
            <div class="feature">
                <div class="feature-icon">🛡️</div>
                <div class="feature-text">Phishing-resistant</div>
            </div>
        </div>
    </div>

    <script>
        function copyCommand(btn, text) {{
            navigator.clipboard.writeText(text).then(() => {{
                const original = btn.textContent;
                btn.textContent = 'Copied!';
                btn.style.color = '#4ade80';
                setTimeout(() => {{
                    btn.textContent = original;
                    btn.style.color = '';
                }}, 2000);
            }});
        }}
    </script>
</body>
</html>"#
    );

    Html(html)
}

/// Build the download section HTML if any download URLs are configured.
fn build_download_section(config: &crate::config::ServerConfig) -> String {
    let has_downloads = config.cli_download_macos.is_some()
        || config.cli_download_linux.is_some()
        || config.cli_download_windows.is_some();

    if !has_downloads {
        return String::new();
    }

    let mut links = Vec::new();

    if let Some(url) = &config.cli_download_macos {
        links.push(format!(
            r#"<a href="{url}" class="download-btn">
                <span>🍎</span>
                <span>macOS</span>
            </a>"#
        ));
    }

    if let Some(url) = &config.cli_download_linux {
        links.push(format!(
            r#"<a href="{url}" class="download-btn">
                <span>🐧</span>
                <span>Linux</span>
            </a>"#
        ));
    }

    if let Some(url) = &config.cli_download_windows {
        links.push(format!(
            r#"<a href="{url}" class="download-btn">
                <span>🪟</span>
                <span>Windows</span>
            </a>"#
        ));
    }

    format!(
        r#"<div class="section">
            <div class="section-title">Download the CLI</div>
            <div class="download-links">
                {}
            </div>
        </div>"#,
        links.join("\n                ")
    )
}
