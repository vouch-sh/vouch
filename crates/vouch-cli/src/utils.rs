// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared utility functions for the CLI.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Ensure a directory exists with secure permissions (0o700 on Unix).
///
/// Creates the directory and all parent directories if they don't exist.
/// On Unix systems, sets permissions to 0o700 (owner read/write/execute only).
pub fn ensure_secure_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)
            .with_context(|| format!("failed to create directory {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

/// Write content to a file with secure permissions (0o600 on Unix).
///
/// Creates parent directories if they don't exist.
/// On Unix systems, sets file permissions to 0o600 (owner read/write only).
pub fn write_secure_file(path: &Path, content: &str) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;

    // Set restrictive permissions on the file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

// Tests for these utilities are in vouch-tests integration tests
// since they require filesystem access with tempfile.
