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
use super::key::ClientKeyFile;

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
