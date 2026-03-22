// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Print the current session token for use with curl or other tools.

use anyhow::Result;
use secrecy::ExposeSecret;

/// Print the raw access token to stdout (no trailing newline).
///
/// Designed for use in subshells and piping:
/// ```bash
/// curl -H "Authorization: Bearer $(vouch credential token)" ...
/// ```
pub(crate) async fn run() -> Result<()> {
    let token = crate::session::resolve_token().await?;
    print!("{}", token.expose_secret());
    Ok(())
}
