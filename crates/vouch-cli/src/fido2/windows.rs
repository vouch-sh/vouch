// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Windows FIDO2 backend using the WebAuthn API (webauthn.dll).
//!
//! Microsoft's WebAuthn API mediates FIDO2 authenticator access on Windows
//! without requiring admin privileges (since Windows 10 1903 the OS blocks
//! direct HID access to FIDO2 devices for non-elevated processes). The OS
//! handles the PIN/touch UI itself via the Windows Security modal dialog.
//!
//! # Hardware-only enforcement
//!
//! Options are hard-coded to restrict authenticators to hardware-backed
//! roaming security keys:
//! - `dwAuthenticatorAttachment = CROSS_PLATFORM` excludes Windows Hello.
//! - `bRequireResidentKey = TRUE` requires discoverable credentials.
//! - `dwUserVerificationRequirement = REQUIRED` forces PIN/UV.
//! - `dwAttestationConveyancePreference = DIRECT` requires attestation,
//!   which the server then validates against an AAGUID allowlist (server-side
//!   layer).
//!
//! The Windows API does not expose a CABLE/hybrid filter, so phone-mediated
//! synced passkeys may surface in the picker; the server's AAGUID validation
//! is the final defense.
//!
//! # Send/Sync invariant
//!
//! [`YubiKey`] holds no raw pointers across method boundaries. All
//! `WEBAUTHN_*` allocations are scoped to a single FFI call inside one method,
//! wrapped in RAII guards that drop before the method returns. Therefore
//! `YubiKey` is `Send + Sync` and can satisfy the `FidoDevice: Send` bound.
//! Future field additions MUST preserve this invariant.
//!
//! # Type name
//!
//! `YubiKey` is named for symmetry with the Unix backend; the Windows
//! WebAuthn API supports any FIDO2 authenticator. The user is constrained to
//! YubiKeys via product policy, not by the API itself.
//!
//! # Timeout semantics
//!
//! Unlike the Unix backend's `wait_for_device(timeout_secs)` which polls for
//! HID insertion, on Windows `wait_for_device` is a no-op API version probe;
//! `timeout_secs` is forwarded to `dwTimeoutMilliseconds` as the **total user
//! interaction timeout** (insertion + PIN entry + touch). Windows owns the
//! entire flow.
//!
//! # Cancellation
//!
//! Ctrl-C handling is wired up via [`cancel_current_operation`]: each
//! `register`/`authenticate` call generates a fresh cancellation ID via
//! `WebAuthNGetCancellationId`, stores it in a process-global slot, and
//! plumbs it into the WebAuthn options. [`super::spawn_fido2`] races the
//! synchronous FFI thread against `tokio::signal::ctrl_c`; on Ctrl-C it
//! invokes `WebAuthNCancelCurrentOperation`, which makes the in-flight
//! WebAuthn call return `NTE_USER_CANCELLED` so the YubiKey is left in a
//! clean state.

#![expect(
    unsafe_code,
    reason = "WebAuthn API requires raw FFI; safety documented per call site"
)]

use anyhow::{Context, Result, bail};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::sync::Mutex;
use windows::Win32::Foundation::{HWND, TRUE};
use windows::Win32::Networking::WindowsWebServices::{
    WEBAUTHN_ASSERTION, WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
    WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION, WEBAUTHN_CLIENT_DATA,
    WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
    WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256, WEBAUTHN_COSE_CREDENTIAL_PARAMETER,
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    WEBAUTHN_CREDENTIAL_ATTESTATION, WEBAUTHN_CREDENTIAL_EX,
    WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_LIST,
    WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_HASH_ALGORITHM_SHA_256,
    WEBAUTHN_RP_ENTITY_INFORMATION, WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
    WEBAUTHN_USER_ENTITY_INFORMATION, WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED, WebAuthNAuthenticatorGetAssertion,
    WebAuthNAuthenticatorMakeCredential, WebAuthNCancelCurrentOperation, WebAuthNFreeAssertion,
    WebAuthNFreeCredentialAttestation, WebAuthNGetApiVersionNumber, WebAuthNGetCancellationId,
    WebAuthNGetErrorName,
};
use windows::Win32::System::Console::GetConsoleWindow;
use windows::core::{GUID, PCWSTR};

use vouch_common::encoding::Raw;
use vouch_common::fido2_types::CredentialId;

use super::{AuthenticationResult, ClientData, FidoDevice, RegistrationResult};

/// Minimum WebAuthn API version (Windows 10 1903 = v1).
const MIN_API_VERSION: u32 = 1;

/// Cancellation ID of the in-flight WebAuthn operation, if any.
///
/// Set inside `register`/`authenticate` immediately before the FFI call and
/// cleared immediately after. [`cancel_current_operation`] reads this slot
/// from a `tokio::signal::ctrl_c` handler running on the tokio side.
static CURRENT_CANCEL_ID: Mutex<Option<GUID>> = Mutex::new(None);

/// Cancel the in-flight WebAuthn operation, if one is running.
///
/// Called by [`super::spawn_fido2`] when the user presses Ctrl-C. Idempotent:
/// if no operation is in flight, this is a no-op. The cancelled FFI call will
/// return `NTE_USER_CANCELLED` (0x80090036), which the error translator maps
/// to "Authentication cancelled."
pub(super) fn cancel_current_operation() {
    let id = match CURRENT_CANCEL_ID.lock() {
        Ok(guard) => *guard,
        Err(poisoned) => *poisoned.into_inner(),
    };
    if let Some(id) = id {
        // SAFETY: WebAuthNCancelCurrentOperation takes a pointer to a GUID
        // previously returned by WebAuthNGetCancellationId. The GUID is a
        // local-by-value copy here; the API reads it but does not retain the
        // pointer beyond the call. Cancellation is best-effort: if it fails
        // (e.g., the operation already completed), the pending FFI call will
        // simply return its own error and the process will exit normally.
        if let Err(e) = unsafe { WebAuthNCancelCurrentOperation(&id) } {
            tracing::debug!(?e, "WebAuthn cancellation request failed");
        }
    }
}

/// RAII guard that registers a cancellation ID on construction and clears it
/// on drop. Used to make sure the static `CURRENT_CANCEL_ID` is always cleared
/// after the FFI call returns, even if a panic or `?`-bail happens between.
struct CancellationSlot;

impl CancellationSlot {
    fn install(id: GUID) -> Self {
        if let Ok(mut guard) = CURRENT_CANCEL_ID.lock() {
            *guard = Some(id);
        }
        Self
    }
}

impl Drop for CancellationSlot {
    fn drop(&mut self) {
        if let Ok(mut guard) = CURRENT_CANCEL_ID.lock() {
            *guard = None;
        }
    }
}

/// Generate a fresh cancellation ID via the WebAuthn API.
fn new_cancellation_id() -> Result<GUID> {
    // SAFETY: WebAuthNGetCancellationId is a no-arg call that returns a fresh
    // GUID by value (windows-rs wraps the C out-parameter form into Result<GUID>).
    let id = unsafe { WebAuthNGetCancellationId() }
        .map_err(|e| translate_webauthn_error(e.code(), "WebAuthn cancellation init"))?;
    Ok(id)
}

/// Windows backend for FIDO2 operations via webauthn.dll.
///
/// Holds only the timeout (no FFI pointers) — see module docs for the
/// Send/Sync invariant.
pub struct YubiKey {
    timeout_ms: u32,
}

impl YubiKey {
    /// Probe the WebAuthn API version and prepare a backend instance.
    ///
    /// Unlike the Unix backend, this does not poll for hardware — Windows
    /// shows its own "Insert your security key" modal when a credential
    /// operation is invoked.
    pub fn wait_for_device(timeout_secs: u64) -> Result<Self> {
        // SAFETY: WebAuthNGetApiVersionNumber takes no parameters, returns a DWORD,
        // and has no preconditions. Available since Windows 10 1903.
        let api_version = unsafe { WebAuthNGetApiVersionNumber() };
        if api_version < MIN_API_VERSION {
            bail!(
                "Windows WebAuthn API too old (got v{api_version}, need v{MIN_API_VERSION}). \
                 Update to Windows 10 1903 or later."
            );
        }
        let timeout_ms = u32::try_from(timeout_secs.saturating_mul(1000)).unwrap_or(u32::MAX);
        Ok(Self { timeout_ms })
    }
}

impl FidoDevice for YubiKey {
    fn register(
        &self,
        rp_id: &str,
        rp_name: &str,
        challenge: &[u8],
        user_id: &[u8],
        user_name: &str,
        exclude_credentials: &[CredentialId<Raw>],
    ) -> Result<RegistrationResult> {
        let client_data_json = ClientData::new_create(challenge, rp_id).to_json()?;

        // Wide-string buffers must outlive the FFI call.
        let rp_id_w = wide(rp_id);
        let rp_name_w = wide(rp_name);
        let user_name_w = wide(user_name);
        let display_name_w = wide(user_name);

        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: PCWSTR(rp_id_w.as_ptr()),
            pwszName: PCWSTR(rp_name_w.as_ptr()),
            pwszIcon: PCWSTR::null(),
        };

        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: u32_len(user_id, "user id")?,
            pbId: user_id.as_ptr().cast_mut(),
            pwszName: PCWSTR(user_name_w.as_ptr()),
            pwszIcon: PCWSTR::null(),
            pwszDisplayName: PCWSTR(display_name_w.as_ptr()),
        };

        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: u32_len(&client_data_json, "client data")?,
            pbClientDataJSON: client_data_json.as_ptr().cast_mut(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };

        // Hardware-only credential parameters: ES256, RS256.
        // (EdDSA / -8 has no constant in Microsoft's webauthn.h and is not
        // supported by the Windows WebAuthn API. Existing EdDSA credentials
        // registered on Unix still authenticate on Windows because
        // getAssertion uses whichever key the authenticator already holds.)
        let cred_params = [
            cose_param(WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256),
            cose_param(WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256),
        ];
        let cose_params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: u32::try_from(cred_params.len())
                .context("cred params count overflow")?,
            pCredentialParameters: cred_params.as_ptr().cast_mut(),
        };

        // Exclude list: buffers must outlive the call. We hold raw pointers
        // into `exclude_credentials` byte slices; they are valid for the
        // duration of this method since `exclude_credentials` is an &[…].
        let mut exclude_ex_storage: Vec<WEBAUTHN_CREDENTIAL_EX> = exclude_credentials
            .iter()
            .map(|id| {
                Ok::<_, anyhow::Error>(WEBAUTHN_CREDENTIAL_EX {
                    dwVersion: WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
                    cbId: u32_len(id.as_bytes(), "credential id")?,
                    pbId: id.as_bytes().as_ptr().cast_mut(),
                    pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                    dwTransports: 0,
                })
            })
            .collect::<Result<_>>()?;
        let mut exclude_ex_ptrs: Vec<*mut WEBAUTHN_CREDENTIAL_EX> = exclude_ex_storage
            .iter_mut()
            .map(std::ptr::from_mut)
            .collect();
        let mut exclude_list = WEBAUTHN_CREDENTIAL_LIST {
            cCredentials: u32::try_from(exclude_ex_ptrs.len())
                .context("exclude credentials count exceeds u32")?,
            ppCredentials: exclude_ex_ptrs.as_mut_ptr(),
        };
        let exclude_list_ptr: *mut WEBAUTHN_CREDENTIAL_LIST = if exclude_credentials.is_empty() {
            ptr::null_mut()
        } else {
            &mut exclude_list
        };

        let mut cancel_id = new_cancellation_id()?;
        let _cancel_slot = CancellationSlot::install(cancel_id);

        let mut options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS::default();
        options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
        options.dwTimeoutMilliseconds = self.timeout_ms;
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
        options.bRequireResidentKey = TRUE;
        options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
        options.dwAttestationConveyancePreference =
            WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT;
        options.pExcludeCredentialList = exclude_list_ptr;
        options.pCancellationId = &mut cancel_id;

        let hwnd = parent_hwnd();

        // SAFETY: All pointer-bearing structs (rp, user, client_data, cose_params,
        // exclude_list) reference buffers held in locals declared above. They
        // remain valid throughout this FFI call. The returned pointer must be
        // freed by `WebAuthNFreeCredentialAttestation` — wrapped in
        // `CredentialAttestationGuard` immediately below.
        let attestation_ptr = unsafe {
            WebAuthNAuthenticatorMakeCredential(
                hwnd,
                &rp,
                &user,
                &cose_params,
                &client_data,
                Some(&options),
            )
        }
        .map_err(|e| translate_webauthn_error(e.code(), "FIDO2 registration"))?;

        let _guard = CredentialAttestationGuard(attestation_ptr);

        if attestation_ptr.is_null() {
            bail!("FIDO2 registration succeeded but returned no attestation");
        }

        // SAFETY: WebAuthn API guarantees that on Ok return, `attestation_ptr`
        // points to a fully-initialized struct. We immediately deep-copy fields
        // into owned Vec<u8>, so the lifetime tied to the API allocation ends
        // when the guard drops at function exit.
        let attestation_ref = unsafe { &*attestation_ptr };

        let credential_id = slice_to_vec(
            attestation_ref.pbCredentialId,
            attestation_ref.cbCredentialId,
        )?;
        let attestation_object = slice_to_vec(
            attestation_ref.pbAttestationObject,
            attestation_ref.cbAttestationObject,
        )?;

        let auth_data_len = usize::try_from(attestation_ref.cbAuthenticatorData)
            .context("authenticator data length exceeds usize")?;
        // SAFETY: WebAuthn API guarantees pbAuthenticatorData/cbAuthenticatorData
        // describe a valid initialized byte slice while the guard owns the pointer.
        let auth_data_slice = unsafe {
            std::slice::from_raw_parts(attestation_ref.pbAuthenticatorData, auth_data_len)
        };
        let public_key = vouch_common::extract_public_key_from_auth_data(auth_data_slice)
            .ok_or_else(|| {
                anyhow::anyhow!("failed to extract COSE public key from authenticator data")
            })?;

        // Drop the guard explicitly to free the WebAuthn allocation.
        drop(_guard);

        Ok(RegistrationResult {
            credential_id: credential_id.into(),
            public_key: public_key.into(),
            attestation_object: attestation_object.into(),
            client_data_json: client_data_json.into(),
        })
    }

    fn authenticate(&self, rp_id: &str, challenge: &[u8]) -> Result<AuthenticationResult> {
        let client_data_json = ClientData::new_get(challenge, rp_id).to_json()?;

        let rp_id_w = wide(rp_id);

        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: u32_len(&client_data_json, "client data")?,
            pbClientDataJSON: client_data_json.as_ptr().cast_mut(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };

        let mut cancel_id = new_cancellation_id()?;
        let _cancel_slot = CancellationSlot::install(cancel_id);

        let mut options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS::default();
        options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION;
        options.dwTimeoutMilliseconds = self.timeout_ms;
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
        options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
        options.pCancellationId = &mut cancel_id;
        // CredentialList intentionally left empty (default) — discoverable
        // credentials only.

        let hwnd = parent_hwnd();

        // SAFETY: rp_id_w and client_data_json buffers outlive this call.
        // Returned pointer is freed by WebAuthNFreeAssertion via AssertionGuard.
        let assertion_ptr = unsafe {
            WebAuthNAuthenticatorGetAssertion(
                hwnd,
                PCWSTR(rp_id_w.as_ptr()),
                &client_data,
                Some(&options),
            )
        }
        .map_err(|e| translate_webauthn_error(e.code(), "FIDO2 authentication"))?;

        let _guard = AssertionGuard(assertion_ptr);

        if assertion_ptr.is_null() {
            bail!("FIDO2 authentication succeeded but returned no assertion");
        }

        // SAFETY: WebAuthn API guarantees on Ok that assertion_ptr points to a
        // fully-initialized struct. We deep-copy fields into owned Vec<u8>.
        let assertion_ref = unsafe { &*assertion_ptr };

        let credential_id =
            slice_to_vec(assertion_ref.Credential.pbId, assertion_ref.Credential.cbId)?;
        let authenticator_data = slice_to_vec(
            assertion_ref.pbAuthenticatorData,
            assertion_ref.cbAuthenticatorData,
        )?;
        let signature = slice_to_vec(assertion_ref.pbSignature, assertion_ref.cbSignature)?;
        let user_handle = slice_to_vec(assertion_ref.pbUserId, assertion_ref.cbUserId)?;

        if user_handle.is_empty() {
            bail!(
                "Your authenticator has a credential for this service, \
                 but it was not stored as a passkey.\n\
                 Re-enroll with `vouch enroll` to create a compatible credential."
            );
        }

        drop(_guard);

        Ok(AuthenticationResult {
            credential_id: credential_id.into(),
            authenticator_data: authenticator_data.into(),
            signature: signature.into(),
            client_data_json: client_data_json.into(),
            user_handle: user_handle.into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cose_param(alg: i32) -> WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
        dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        lAlg: alg,
    }
}

/// Convert a Rust `&str` to a null-terminated UTF-16 buffer for PCWSTR.
fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Cast a slice length to `u32`, with a meaningful error context.
fn u32_len(data: &[u8], what: &str) -> Result<u32> {
    u32::try_from(data.len()).with_context(|| format!("{what} length exceeds u32::MAX"))
}

/// Copy a `*const u8 + len` pair into an owned `Vec<u8>`.
fn slice_to_vec(ptr: *const u8, len: u32) -> Result<Vec<u8>> {
    if ptr.is_null() || len == 0 {
        return Ok(Vec::new());
    }
    let len_usize = usize::try_from(len).context("WebAuthn buffer length exceeds usize")?;
    // SAFETY: caller (WebAuthn API) guarantees `ptr` is a valid pointer to at
    // least `len` initialized bytes. We immediately copy into an owned Vec, so
    // no aliasing concerns.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len_usize) }.to_vec())
}

/// Determine the parent HWND for the Windows Security modal.
///
/// Returns the calling process's console window if one is attached. Otherwise
/// returns null, which makes Windows parent the modal to the desktop.
///
/// Note: we deliberately do **not** fall back to `GetForegroundWindow()` —
/// that returns the system-wide foreground window, which may belong to an
/// unrelated (potentially attacker-controlled) application. Parenting our
/// modal to such a window could let it be obscured or visually misrepresented.
/// The Security modal itself runs in a separate process and is tamper-proof,
/// but we don't hand it a parent we don't control.
fn parent_hwnd() -> HWND {
    // SAFETY: GetConsoleWindow returns NULL if no console attached; never panics.
    let hwnd = unsafe { GetConsoleWindow() };
    if !hwnd.is_invalid() {
        return hwnd;
    }
    HWND(ptr::null_mut())
}

// Microsoft documented HRESULTs for WebAuthn (signed i32 representation;
// stored as u32 bit pattern in the Win32 SDK).
const NTE_TOKEN_KEYSET_STORAGE_FULL: u32 = 0x8009_0023;
const NTE_INVALID_PARAMETER: u32 = 0x8009_0027;
const NTE_NOT_SUPPORTED: u32 = 0x8009_0029;
const NTE_DEVICE_NOT_FOUND: u32 = 0x8009_0035;
const NTE_USER_CANCELLED: u32 = 0x8009_0036;
const ERROR_TIMEOUT_HRESULT: u32 = 0x8007_05B4;

/// Translate a WebAuthn HRESULT into a user-friendly error.
fn translate_webauthn_error(hr: windows::core::HRESULT, op: &str) -> anyhow::Error {
    // Bit-pattern-preserving conversion i32 → u32 (HRESULT is wrapped i32).
    let code = u32::from_ne_bytes(hr.0.to_ne_bytes());
    let detail = webauthn_error_message(hr);

    match code {
        NTE_USER_CANCELLED => anyhow::anyhow!("Authentication cancelled."),
        NTE_DEVICE_NOT_FOUND => anyhow::anyhow!(
            "No security key found.\n\
             Insert your YubiKey and try again."
        ),
        NTE_TOKEN_KEYSET_STORAGE_FULL => anyhow::anyhow!(
            "Your YubiKey has no free passkey slots.\n\
             Delete an existing credential with `ykman fido credentials delete` and try again."
        ),
        ERROR_TIMEOUT_HRESULT => anyhow::anyhow!(
            "Timed out waiting for YubiKey.\n\
             Insert your key and try again."
        ),
        NTE_NOT_SUPPORTED => anyhow::anyhow!(
            "Your authenticator does not support resident keys or user verification.\n\
             vouch requires a YubiKey 5 or later with PIN configured."
        ),
        NTE_INVALID_PARAMETER => anyhow::anyhow!(
            "Internal error: invalid WebAuthn parameter (HRESULT 0x{code:08x}). \
             Please file a bug at https://github.com/vouch-sh/vouch/issues."
        ),
        _ => anyhow::anyhow!("{op} failed: 0x{code:08x} {detail}"),
    }
}

/// Resolve a WebAuthn HRESULT to a human-readable name via the API.
fn webauthn_error_message(hr: windows::core::HRESULT) -> String {
    // SAFETY: WebAuthNGetErrorName takes an HRESULT by value, returns PCWSTR
    // pointing to a static string in webauthn.dll; no allocation, no preconditions.
    let pcwstr = unsafe { WebAuthNGetErrorName(hr) };
    if pcwstr.is_null() {
        return String::new();
    }
    // SAFETY: PCWSTR points to a null-terminated UTF-16 string in webauthn.dll's
    // static data; pcwstr.to_string() walks until null and decodes UTF-16.
    unsafe { pcwstr.to_string() }.unwrap_or_default()
}

// ---------------------------------------------------------------------------
// RAII guards for WebAuthn output structs
// ---------------------------------------------------------------------------

struct CredentialAttestationGuard(*mut WEBAUTHN_CREDENTIAL_ATTESTATION);
impl Drop for CredentialAttestationGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: pointer was returned by WebAuthNAuthenticatorMakeCredential
            // and not yet freed. WebAuthNFreeCredentialAttestation is the only
            // valid deallocator per the Windows API contract. windows-rs wraps
            // the deallocator's nullable parameter as Option<*const _>.
            unsafe { WebAuthNFreeCredentialAttestation(Some(self.0.cast_const())) };
        }
    }
}

struct AssertionGuard(*mut WEBAUTHN_ASSERTION);
impl Drop for AssertionGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: pointer was returned by WebAuthNAuthenticatorGetAssertion
            // and not yet freed. WebAuthNFreeAssertion is the only valid
            // deallocator per the Windows API contract. Unlike its sibling
            // WebAuthNFreeCredentialAttestation, this one takes the pointer
            // directly without an Option wrapper.
            unsafe { WebAuthNFreeAssertion(self.0.cast_const()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webauthn_api_available() {
        // SAFETY: WebAuthNGetApiVersionNumber takes no parameters and is
        // available since Windows 10 1903 (which all supported targets are).
        let version = unsafe { WebAuthNGetApiVersionNumber() };
        assert!(
            version >= MIN_API_VERSION,
            "WebAuthn API version {version} is below minimum {MIN_API_VERSION}"
        );
    }

    #[test]
    fn translate_known_errors() {
        let cancelled_hr =
            windows::core::HRESULT(i32::from_ne_bytes(NTE_USER_CANCELLED.to_ne_bytes()));
        let cancelled = translate_webauthn_error(cancelled_hr, "test");
        assert!(cancelled.to_string().contains("cancelled"));

        let not_found_hr =
            windows::core::HRESULT(i32::from_ne_bytes(NTE_DEVICE_NOT_FOUND.to_ne_bytes()));
        let not_found = translate_webauthn_error(not_found_hr, "test");
        assert!(not_found.to_string().contains("No security key found"));
    }

    #[test]
    fn wide_terminates_with_null() {
        let w = wide("hello");
        assert_eq!(w.last(), Some(&0u16));
        assert_eq!(w.len(), "hello".len() + 1);
    }
}
