// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SSH certificate status checking.

use ssh_key::certificate::Certificate;

use super::{ConfiguredDetails, IntegrationCheck, IntegrationState};
use crate::commands::credential::ssh::default_key_path;

/// SSH certificate integration checker.
pub(crate) struct SshIntegration;

impl SshIntegration {
    /// Create a new SSH integration checker.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self
    }
}

impl Default for SshIntegration {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegrationCheck for SshIntegration {
    fn name(&self) -> &'static str {
        "SSH"
    }

    fn check(&self) -> IntegrationState {
        let key_path = match default_key_path() {
            Ok(p) => p,
            Err(_) => {
                return IntegrationState::NotConfigured {
                    setup_hint: "vouch credential ssh".to_string(),
                };
            }
        };

        let cert_path_str = format!("{}-cert.pub", key_path.display());
        let cert_path = std::path::Path::new(&cert_path_str);

        if !key_path.exists() {
            return IntegrationState::Partial {
                message: "no keypair".to_string(),
                setup_hint: Some("vouch credential ssh".to_string()),
            };
        }

        if !cert_path.exists() {
            return IntegrationState::Partial {
                message: "keypair exists, no certificate".to_string(),
                setup_hint: Some("vouch credential ssh".to_string()),
            };
        }

        // Parse the certificate for details
        let cert_data = match std::fs::read_to_string(cert_path) {
            Ok(d) => d,
            Err(_) => {
                return IntegrationState::Partial {
                    message: "certificate unreadable".to_string(),
                    setup_hint: None,
                };
            }
        };

        let cert = match Certificate::from_openssh(&cert_data) {
            Ok(c) => c,
            Err(_) => {
                return IntegrationState::Partial {
                    message: "certificate invalid".to_string(),
                    setup_hint: None,
                };
            }
        };

        let valid_before = cert.valid_before();
        let now_unix = jiff::Timestamp::now().as_second();
        let valid_before_i64 = i64::try_from(valid_before).unwrap_or(i64::MAX);

        if valid_before_i64 <= now_unix {
            return IntegrationState::Partial {
                message: "certificate expired".to_string(),
                setup_hint: Some("vouch credential ssh".to_string()),
            };
        }

        let remaining_secs = valid_before_i64.saturating_sub(now_unix);
        // 60 is non-zero; unwrap_or arm is unreachable.
        let remaining =
            jiff::SignedDuration::from_mins(remaining_secs.checked_div(60).unwrap_or(0));

        let principals: Vec<String> = cert
            .valid_principals()
            .iter()
            .map(|s| s.to_string())
            .collect();

        let mut details = vec![("Certificate".to_string(), cert_path_str)];

        if !principals.is_empty() {
            details.push(("Principals".to_string(), principals.join(", ")));
        }

        details.push(("Serial".to_string(), cert.serial().to_string()));

        // Show SSH agent socket if configured (Unix only)
        #[cfg(unix)]
        if let Ok(socket_path) = vouch_agent::ssh_agent_socket_path()
            && socket_path.exists()
        {
            details.push((
                "Agent socket".to_string(),
                socket_path.display().to_string(),
            ));
        }

        IntegrationState::Configured(ConfiguredDetails {
            summary: format!("certificate valid ({remaining:#} remaining)"),
            details,
        })
    }
}
