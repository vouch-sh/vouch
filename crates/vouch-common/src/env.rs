// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Environment and configuration value helpers.

/// Treat an empty string as absent.
///
/// Fallback chains must progress past values that are set but empty
/// (`AWS_REGION=""`), otherwise the empty string overrides every later source
/// and surfaces far away as malformed output (e.g. an STS endpoint of
/// `https://sts..amazonaws.com`).
#[must_use]
pub fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|s| !s.is_empty())
}

/// Read an environment variable, treating unset and empty as equivalent.
#[must_use]
pub fn non_empty_env(name: &str) -> Option<String> {
    non_empty(std::env::var(name).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_empty_passes_values_through() {
        assert_eq!(
            non_empty(Some("us-east-1".to_string())),
            Some("us-east-1".to_string())
        );
    }

    #[test]
    fn non_empty_treats_empty_as_absent() {
        assert_eq!(non_empty(Some(String::new())), None);
    }

    #[test]
    fn non_empty_passes_none_through() {
        assert_eq!(non_empty(None), None);
    }

    #[test]
    fn non_empty_env_unset_is_none() {
        assert_eq!(non_empty_env("VOUCH_TEST_ENV_VAR_THAT_IS_NEVER_SET"), None);
    }
}
