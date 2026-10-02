// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Print the current session's access token, for inspecting its claims.

use crate::session;
use anyhow::Result;
use secrecy::ExposeSecret;

/// Print the raw access token to stdout (no trailing newline), for decoding
/// its claims. The token is DPoP-bound, so a server refuses it as `Bearer`;
/// sending it requires a DPoP proof signed with the client key.
pub(crate) async fn run() -> Result<()> {
    let token = session::resolve_token().await?;
    print!("{}", token.expose_secret());
    Ok(())
}
