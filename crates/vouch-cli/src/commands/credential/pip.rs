// SPDX-License-Identifier: Apache-2.0 OR MIT
//! pip keyring credential helper.
//!
//! Implements the `keyring` CLI so pip and uv can fetch fresh CodeArtifact
//! tokens instead of relying on static tokens that expire in ~12h.
//!
//! pip and uv run whichever `keyring` executable is on `PATH`, so they can only
//! send what the real keyring CLI accepts. [`KeyringArgs`] mirrors that CLI's
//! argument parser (`keyring/cli.py` in jaraco/keyring), so any call real
//! keyring parses also parses here, regardless of option order or spelling.
//! Observed calls:
//!   - pip 26.2+: `keyring --mode=creds --output=json get <url> <username>`
//!   - pip before 26.2: `keyring get <url> <username>`
//!   - uv: `keyring get <url> <username>`, or `keyring get <url> --mode creds`
//!
//! `set` and `del` are accepted and ignored, since vouch fetches tokens on
//! demand. Setup configures pip with `keyring-provider = subprocess` and links
//! a `keyring` executable to the vouch binary.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use std::borrow::Cow;
use vouch_cli::tr;
use zeroize::Zeroizing;

use crate::integrations::aws::codeartifact::parse_codeartifact_url;
use crate::server_url::{InsecureOptIn, ServerUrlError};
use crate::session;

/// CodeArtifact's HTTP basic-auth username, which `vouch setup codeartifact
/// --tool pip` puts in the index URL (`https://aws@…`).
const CODEARTIFACT_USERNAME: &str = "aws";

/// Arguments of the `keyring` CLI, mirroring the argparse definition in
/// jaraco/keyring `keyring/cli.py`. Like argparse, options may appear before
/// or after the positionals, as `--mode=creds` or `--mode creds`, and long
/// options may be abbreviated. An option keyring does not define is a usage
/// error rather than being guessed at.
#[derive(Debug, clap::Parser)]
#[command(name = "keyring", infer_long_args = true)]
pub(crate) struct KeyringArgs {
    /// Accepted for compatibility; vouch is the backend.
    #[arg(short = 'p', long = "keyring-path", hide = true)]
    _keyring_path: Option<String>,
    /// Accepted for compatibility; vouch is the backend.
    #[arg(short = 'b', long = "keyring-backend", hide = true)]
    _keyring_backend: Option<String>,
    /// Accepted for compatibility; there are no backends to list.
    #[arg(long = "list-backends", hide = true)]
    _list_backends: bool,
    /// Accepted for compatibility; there is nothing to disable.
    #[arg(long = "disable", hide = true)]
    _disable: bool,
    /// What `get` returns: the password alone, or username and password.
    #[arg(long = "mode", value_enum, default_value_t = GetMode::Password, hide = true)]
    mode: GetMode,
    /// How `get` prints the credential.
    #[arg(long = "output", value_enum, default_value_t = OutputFormat::Plain, hide = true)]
    output: OutputFormat,
    /// Keyring operation (get, set, del).
    #[arg(help = tr!("arg-credential-pip-operation-help"))]
    operation: Option<String>,
    /// Service URL passed by pip (the CodeArtifact index URL).
    #[arg(help = tr!("arg-credential-pip-service-url-help"))]
    service: Option<String>,
    /// Username passed by pip (typically "aws").
    #[arg(help = tr!("arg-credential-pip-username-help"))]
    username: Option<String>,
}

/// keyring's `--mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum GetMode {
    Password,
    Creds,
}

/// keyring's `--output`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OutputFormat {
    Plain,
    Json,
}

/// The credential keyring prints, in field order: `credential._vars()`.
#[derive(Serialize)]
struct Credential<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
    password: &'a str,
}

impl KeyringArgs {
    /// What a successful `get` prints, matching keyring's `_emit_plain` (each
    /// value on its own line) and `_emit_json` (`json.dumps` of the values).
    /// `password` mode carries no username; `creds` mode returns the username
    /// the caller passed, or CodeArtifact's `aws` when it passed none.
    fn render(&self, password: &str) -> Result<Zeroizing<String>> {
        let credential = Credential {
            username: match self.mode {
                GetMode::Password => None,
                GetMode::Creds => Some(self.username.as_deref().unwrap_or(CODEARTIFACT_USERNAME)),
            },
            password,
        };
        let mut out = Zeroizing::new(String::new());
        match self.output {
            OutputFormat::Json => {
                out.push_str(&Zeroizing::new(serde_json::to_string(&credential)?))
            }
            OutputFormat::Plain => {
                if let Some(username) = credential.username {
                    out.push_str(username);
                    out.push('\n');
                }
                out.push_str(password);
            }
        }
        out.push('\n');
        Ok(out)
    }
}

/// Run the pip keyring credential helper.
///
/// Only `get` does anything. `set` and `del` are ignored since vouch manages
/// tokens dynamically, and any other operation succeeds silently, as before.
pub(crate) async fn run(args: &KeyringArgs, opt_in: InsecureOptIn) -> Result<()> {
    match args.operation.as_deref() {
        Some("get") => {
            let url = args.service.as_deref().context(
                "keyring get requires a service URL. \
                 Usage: vouch credential pip get <url> [username]",
            )?;
            let token = fetch_token(url, opt_in).await?;
            print!("{}", args.render(token.expose_secret())?.as_str());
            Ok(())
        }
        _ => Ok(()),
    }
}

/// pip's keyring fallback and 401 paths pass the bare network location
/// (`host`, no scheme) as the service; add `https://` to those. An argument
/// that names a scheme is left alone, so the shared parser still rejects any
/// that is not `https`.
fn with_default_scheme(service: &str) -> Cow<'_, str> {
    if service.contains("://") {
        Cow::Borrowed(service)
    } else {
        Cow::Owned(format!("https://{service}"))
    }
}

/// Fetch a fresh CodeArtifact token for the registry `url` names.
async fn fetch_token(url: &str, opt_in: InsecureOptIn) -> Result<SecretString> {
    let registry = parse_codeartifact_url(&with_default_scheme(url)).ok_or_else(|| {
        anyhow::anyhow!(
            "URL does not appear to be a CodeArtifact registry: {url}\n\
             Expected format: https://{{domain}}-{{owner}}.d.codeartifact.{{region}}.amazonaws.com/..."
        )
    })?;

    let session = session::resolve_session(opt_in).await.map_err(|e| {
        if ServerUrlError::is_in(&e) {
            e
        } else {
            e.context(tr!(
                "err-vouch-is-not-enrolled-run-vouch-enroll-set-up-authen"
            ))
        }
    })?;

    // The keyring shim carries no arguments, so the AWS account backing this
    // domain is recovered from the saved CodeArtifact profile.
    let target = super::codeartifact::CodeArtifactTarget::new(
        registry.domain,
        registry.domain_owner,
        registry.region,
    );
    let token = super::codeartifact::get_token(&session.server_url, &target)
        .await
        .context(tr!("err-failed-get-codeartifact-token"))?;

    Ok(token.authorization_token)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use clap::Parser;

    const HOST: &str = "my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com";

    fn parse(argv: &[&str]) -> KeyringArgs {
        KeyringArgs::try_parse_from(std::iter::once("keyring").chain(argv.iter().copied())).unwrap()
    }

    #[test]
    fn test_parse_codeartifact_from_pip_url() {
        // pip passes the full index URL including /pypi/{repo}/simple/ path
        let url = "https://my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com/pypi/my-repo/simple/";
        let registry = parse_codeartifact_url(url);
        assert!(registry.is_some());
        let r = registry.unwrap();
        assert_eq!(r.domain, "my-domain");
        assert_eq!(r.domain_owner, "123456789012");
        assert_eq!(r.region, "us-east-1");
    }

    // pip `network/auth.py` passes the bare netloc to the keyring helper.
    #[test]
    fn test_bare_host_gets_https() {
        let registry = parse_codeartifact_url(&with_default_scheme(HOST)).unwrap();
        assert_eq!(registry.domain, "my-domain");
        assert_eq!(registry.region, "us-east-1");
    }

    #[test]
    fn test_explicit_non_https_scheme_is_still_rejected() {
        for service in [
            format!("http://{HOST}"),
            format!("http://{HOST}/pypi/r/simple/"),
        ] {
            assert_eq!(with_default_scheme(&service), service);
            assert!(parse_codeartifact_url(&with_default_scheme(&service)).is_none());
        }
    }

    #[test]
    fn test_bare_lookalike_host_is_rejected() {
        for host in [
            "my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.evil.com",
            "evil.com@my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com",
            "my-domain-123456789012.d.codeartifact.us-east-1.amazonaws.com:8443",
            "pypi.org",
            "",
        ] {
            assert!(
                parse_codeartifact_url(&with_default_scheme(host)).is_none(),
                "{host}"
            );
        }
    }

    #[test]
    fn test_non_codeartifact_url_returns_none() {
        assert!(parse_codeartifact_url("https://pypi.org/simple/").is_none());
        assert!(parse_codeartifact_url("https://files.pythonhosted.org/packages/").is_none());
    }

    // pip 26.2+ `KeyringCLIProvider._get_creds` (pip/_internal/network/auth.py):
    // `cmd = [self.keyring, "--mode=creds", "--output=json", "get", service_name]`
    // followed by the username when it has one.
    #[test]
    fn test_parses_pip_creds_json_call() {
        let url = format!("https://{HOST}/pypi/r/simple/");
        let args = parse(&["--mode=creds", "--output=json", "get", &url, "aws"]);
        assert_eq!(args.mode, GetMode::Creds);
        assert_eq!(args.output, OutputFormat::Json);
        assert_eq!(args.operation.as_deref(), Some("get"));
        assert_eq!(args.service.as_deref(), Some(url.as_str()));
        assert_eq!(args.username.as_deref(), Some("aws"));

        let args = parse(&["--mode=creds", "--output=json", "get", HOST]);
        assert_eq!(args.service.as_deref(), Some(HOST));
        assert_eq!(args.username, None);
    }

    // pip before 26.2 and uv with a username: `keyring get <url> <username>`,
    // which keyring's defaults (`--mode password`, `--output plain`) serve.
    #[test]
    fn test_parses_plain_get_call() {
        let args = parse(&["get", HOST, "aws"]);
        assert_eq!(args.mode, GetMode::Password);
        assert_eq!(args.output, OutputFormat::Plain);
        assert_eq!(args.service.as_deref(), Some(HOST));
        assert_eq!(args.username.as_deref(), Some("aws"));
    }

    // uv `fetch_subprocess` (crates/uv-auth/src/keyring.rs) appends
    // `--mode creds` after the service when it has no username.
    #[test]
    fn test_parses_uv_trailing_mode_option() {
        let args = parse(&["get", HOST, "--mode", "creds"]);
        assert_eq!(args.mode, GetMode::Creds);
        assert_eq!(args.service.as_deref(), Some(HOST));
        assert_eq!(args.username, None);
    }

    // keyring's argparse parser accepts abbreviated long options and its
    // backend-selection options; both must parse here too.
    #[test]
    fn test_parses_other_keyring_spellings() {
        let args = parse(&["--mo", "creds", "--out", "json", "get", HOST]);
        assert_eq!(args.mode, GetMode::Creds);
        assert_eq!(args.output, OutputFormat::Json);

        let args = parse(&["-b", "some.Backend", "-p", "/tmp", "get", HOST, "aws"]);
        assert_eq!(args.service.as_deref(), Some(HOST));
        assert_eq!(args.username.as_deref(), Some("aws"));
    }

    // An option real keyring rejects is a usage error, not a guess.
    #[test]
    fn test_rejects_options_keyring_does_not_define() {
        for argv in [
            &["--format=json", "get", HOST][..],
            &["--mode=token", "get", HOST][..],
            &["--output=yaml", "get", HOST][..],
        ] {
            let argv = std::iter::once("keyring").chain(argv.iter().copied());
            assert!(KeyringArgs::try_parse_from(argv).is_err());
        }
    }

    // keyring `_emit_plain` prints each of `credential._vars()` on its own
    // line; `_emit_json` prints `json.dumps(credential._vars())`. Password
    // mode's credential has only a password.
    #[test]
    fn test_render_matches_keyring_output() {
        let cases = [
            (vec!["get", HOST, "aws"], "s3cret\n"),
            (
                vec!["--output=json", "get", HOST, "aws"],
                "{\"password\":\"s3cret\"}\n",
            ),
            (vec!["--mode=creds", "get", HOST, "aws"], "aws\ns3cret\n"),
            (
                vec!["--mode=creds", "--output=json", "get", HOST, "aws"],
                "{\"username\":\"aws\",\"password\":\"s3cret\"}\n",
            ),
        ];
        for (argv, expected) in cases {
            let rendered = parse(&argv).render("s3cret").unwrap();
            assert_eq!(rendered.as_str(), expected, "{argv:?}");
        }
    }

    #[test]
    fn test_creds_mode_without_username_returns_codeartifact_username() {
        let rendered = parse(&["get", HOST, "--mode", "creds"])
            .render("s3cret")
            .unwrap();
        assert_eq!(rendered.as_str(), "aws\ns3cret\n");

        let args = parse(&["--mode=creds", "--output=json", "get", HOST]);
        let json: serde_json::Value =
            serde_json::from_str(args.render("s3cret").unwrap().as_str()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"username": "aws", "password": "s3cret"})
        );
    }

    #[tokio::test]
    async fn test_set_operation_succeeds_silently() {
        let args = parse(&["set", "https://example.com", "user"]);
        assert!(run(&args, InsecureOptIn::Env).await.is_ok());
    }

    #[tokio::test]
    async fn test_del_operation_succeeds_silently() {
        let args = parse(&["del", "https://example.com", "user"]);
        assert!(run(&args, InsecureOptIn::Env).await.is_ok());
    }

    #[tokio::test]
    async fn test_unknown_operation_succeeds_silently() {
        assert!(run(&parse(&["unknown"]), InsecureOptIn::Env).await.is_ok());
        assert!(run(&parse(&[]), InsecureOptIn::Env).await.is_ok());
    }

    #[tokio::test]
    async fn test_get_without_url_returns_error() {
        let result = run(&parse(&["get"]), InsecureOptIn::Env).await;
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("keyring get requires a service URL"));
    }

    #[tokio::test]
    async fn test_get_non_codeartifact_url_returns_error() {
        let args = parse(&[
            "--mode=creds",
            "--output=json",
            "get",
            "https://pypi.org/simple/",
            "user",
        ]);
        let result = run(&args, InsecureOptIn::Env).await;
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("does not appear to be a CodeArtifact registry"));
    }
}
