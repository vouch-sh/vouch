// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OS keychain storage for the FAPI 2.0 client key.
//!
//! Uses the [`keyring`] crate to store and retrieve the [`ClientKeyFile`] JSON
//! in the platform-native credential store:
//!
//! - **macOS**: Security framework (Keychain)
//! - **Linux**: Secret Service (GNOME Keyring / KDE Wallet) or `keyutils`
//! - **Windows**: Windows Credential Manager (DPAPI)
//!
//! All functions return [`FapiError::KeychainAccess`] on failure, allowing
//! callers to fall back to file-based storage (e.g., in CI/headless environments).

use super::error::FapiError;
use super::key::{ClientKey, ClientKeyFile};

/// Keyring service name for vouch credentials.
const SERVICE: &str = "vouch";
/// Keyring account name for the FAPI client key.
const ACCOUNT: &str = "client_key";

/// Load a [`ClientKeyFile`] from the OS keychain.
///
/// Returns `Ok(Some(key_file))` if the entry exists and is valid JSON,
/// `Ok(None)` if the entry does not exist, or `Err` on other failures.
///
/// # Errors
///
/// Returns [`FapiError::KeychainAccess`] if the keychain cannot be accessed.
/// Returns [`FapiError::Serialization`] if the stored value is not valid JSON.
pub fn load_from_keychain() -> Result<Option<ClientKeyFile>, FapiError> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT)
        .map_err(|e| FapiError::KeychainAccess(e.to_string()))?;

    match entry.get_password() {
        Ok(json) => {
            let key_file: ClientKeyFile = serde_json::from_str(&json)?;
            Ok(Some(key_file))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(FapiError::KeychainAccess(e.to_string())),
    }
}

/// Save a [`ClientKeyFile`] to the OS keychain.
///
/// # Errors
///
/// Returns [`FapiError::KeychainAccess`] if the keychain cannot be accessed.
/// Returns [`FapiError::Serialization`] if the key file cannot be serialized.
pub fn save_to_keychain(key_file: &ClientKeyFile) -> Result<(), FapiError> {
    let json = serde_json::to_string(key_file)?;

    let entry = keyring::Entry::new(SERVICE, ACCOUNT)
        .map_err(|e| FapiError::KeychainAccess(e.to_string()))?;

    entry
        .set_password(&json)
        .map_err(|e| FapiError::KeychainAccess(e.to_string()))
}

/// Delete the client key from the OS keychain.
///
/// Returns `Ok(())` even if the entry does not exist (idempotent).
///
/// # Errors
///
/// Returns [`FapiError::KeychainAccess`] if the keychain cannot be accessed.
pub fn delete_from_keychain() -> Result<(), FapiError> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT)
        .map_err(|e| FapiError::KeychainAccess(e.to_string()))?;

    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(FapiError::KeychainAccess(e.to_string())),
    }
}

/// Load a [`ClientKey`] from the OS keychain or disk (read-only).
///
/// Checks sources in order:
/// 1. OS keychain (preferred — encrypted at rest)
/// 2. `~/.vouch/client_key.json` (legacy/fallback)
///
/// Returns `None` if no key is found. Never generates a new key — that
/// happens only in the enroll/login flows via [`load_or_create_client_key`].
/// This is intentionally non-fatal: resource requests fall back to `Bearer`
/// auth when no key is available.
pub fn load_client_key() -> Option<ClientKey> {
    // 1. Try the OS keychain first.
    match load_from_keychain() {
        Ok(Some(key_file)) => match ClientKey::from_key_file(&key_file) {
            Ok(key) => {
                tracing::debug!("Loaded FAPI key from keychain: kid={}", key.kid());
                return Some(key);
            }
            Err(e) => {
                tracing::warn!("Keychain has FAPI key but it failed to parse: {e}");
            }
        },
        Ok(None) => {
            tracing::debug!("No FAPI key in keychain");
        }
        Err(e) => {
            tracing::warn!("Cannot access keychain for FAPI key: {e}");
        }
    }

    // 2. Fall back to disk.
    let home = dirs::home_dir()?;
    let key_path = home.join(".vouch").join("client_key.json");

    if !key_path.exists() {
        tracing::debug!("No FAPI key on disk at {}", key_path.display());
        return None;
    }

    match ClientKey::load(&key_path) {
        Ok(key) => {
            tracing::debug!("Loaded FAPI key from disk: kid={}", key.kid());
            Some(key)
        }
        Err(e) => {
            tracing::warn!("FAPI key exists on disk but failed to load: {e}");
            None
        }
    }
}

/// Load the FAPI client key, checking keychain and disk, or generate a new one.
///
/// Checks sources in order:
/// 1. OS keychain (preferred — encrypted at rest)
/// 2. `~/.vouch/client_key.json` (legacy/fallback — migrated to keychain if possible)
/// 3. Generate new key → save to keychain (or file if keychain unavailable)
///
/// If the key is found on disk but not in the keychain, it is migrated to the
/// keychain and the file is removed. If the keychain is unavailable (CI, headless),
/// file storage is used as a fallback.
///
/// # Errors
///
/// Returns an error if the key cannot be loaded, generated, or saved.
pub fn load_or_create_client_key() -> anyhow::Result<ClientKey> {
    use anyhow::Context;

    let home = dirs::home_dir().context("cannot determine home directory")?;
    let key_path = home.join(".vouch").join("client_key.json");

    // 1. Try the OS keychain first.
    match load_from_keychain() {
        Ok(Some(key_file)) => {
            let key = ClientKey::from_key_file(&key_file)
                .context("failed to load client key from keychain")?;
            tracing::debug!("FAPI client key loaded from keychain: kid={}", key.kid());
            return Ok(key);
        }
        Ok(None) => {
            tracing::debug!("No client key in keychain, checking disk");
        }
        Err(e) => {
            tracing::debug!("Keychain unavailable ({e}), falling back to disk");
        }
    }

    // 2. Try loading from disk (legacy location).
    if key_path.exists() {
        let key =
            ClientKey::load(&key_path).context("failed to load FAPI client key from disk")?;
        tracing::debug!("FAPI client key loaded from disk: kid={}", key.kid());

        // Migrate to keychain if possible, then remove the file.
        // Verify the write by reading back — some platforms claim
        // success but don't actually persist the entry.
        if let Ok(key_file) = key.to_key_file()
            && save_to_keychain(&key_file).is_ok()
            && load_from_keychain().is_ok_and(|v| v.is_some())
        {
            tracing::debug!("Migrated client key to keychain");
            if let Err(e) = std::fs::remove_file(&key_path) {
                tracing::debug!("Could not remove old key file: {e}");
            }
        }

        return Ok(key);
    }

    // 3. Generate a new key.
    let key = ClientKey::generate().context("failed to generate FAPI client key")?;
    tracing::debug!("Generated new FAPI client key: kid={}", key.kid());

    // Save to keychain first, verify it persisted, fall back to disk.
    // Some platforms (notably macOS with unsigned debug builds) report
    // success on write but the entry doesn't actually persist.
    if let Ok(key_file) = key.to_key_file()
        && save_to_keychain(&key_file).is_ok()
        && load_from_keychain().is_ok_and(|v| v.is_some())
    {
        tracing::debug!("Saved new client key to keychain");
        return Ok(key);
    }

    // Keychain unavailable or unreliable — save to disk.
    tracing::debug!("Keychain unreliable, saving client key to disk");
    key.save(&key_path)
        .context("failed to save FAPI client key to disk")?;
    tracing::debug!("Saved new client key to disk");

    Ok(key)
}
