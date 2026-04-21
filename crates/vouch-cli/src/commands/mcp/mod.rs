// SPDX-License-Identifier: Apache-2.0 OR MIT
//! MCP (Model Context Protocol) server for AI agent credential access.
//!
//! Exposes Vouch credential commands as MCP tools over stdio transport.
//! AI agents (Claude Code, Cursor, etc.) call these tools to get
//! cloud credentials backed by FIDO2 human presence proof.
//!
//! Tools return usage instructions (profile names, file paths), never
//! raw secrets. Native CLI tools (aws, ssh) call Vouch's credential
//! helpers directly — credentials never enter the AI conversation.

mod tools;

use anyhow::Result;

/// Run the MCP server over stdio.
///
/// This is invoked by `vouch mcp` and speaks the MCP JSON-RPC protocol
/// over stdin/stdout. Claude Code (or any MCP client) spawns this process.
pub(crate) async fn run(server: &str) -> Result<()> {
    use rmcp::ServiceExt;

    let mcp_server = tools::VouchMcpServer::new(server.to_string());

    // Serve the MCP server over stdio (stdin/stdout)
    let service = mcp_server
        .serve(rmcp::transport::io::stdio())
        .await
        .map_err(|e| anyhow::anyhow!("MCP server initialization failed: {e}"))?;

    // Block until the MCP client disconnects
    service
        .waiting()
        .await
        .map_err(|e| anyhow::anyhow!("MCP server error: {e}"))?;

    Ok(())
}
