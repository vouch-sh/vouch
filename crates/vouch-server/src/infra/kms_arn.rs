// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cross-account KMS key ARN resolution.
//!
//! When KMS keys live in a different AWS account than the server, the AWS SDK
//! must be given the full ARN rather than a bare key ID. This module reads
//! `AWS_PARTITION`, `AWS_REGION`/`AWS_DEFAULT_REGION`, and `AWS_ACCOUNT_ID`
//! from the environment, combines them with a configured `kms_account_id`,
//! and wraps raw key IDs into full ARNs.
//!
//! Pass-through cases (return the raw value unchanged):
//! - The configured value already starts with `arn:`.
//! - `kms_account_id` is unset (no cross-account access configured).
//! - Required env vars are missing (logged once at construction).

use std::env;

/// Resolves bare KMS key IDs into full ARNs for cross-account access.
#[derive(Debug, Clone)]
pub struct KmsArnResolver {
    partition: Option<String>,
    region: Option<String>,
    account_id: Option<String>,
}

impl KmsArnResolver {
    /// Build a resolver from process environment plus the configured
    /// `kms_account_id`.
    ///
    /// When `kms_account_id` is `None`, the resolver becomes a no-op:
    /// every call to [`resolve`](Self::resolve) returns the input unchanged.
    pub fn from_env(kms_account_id: Option<&str>) -> Self {
        let account_id = kms_account_id.map(str::to_owned);
        let partition = env::var("AWS_PARTITION").ok();
        let region = env::var("AWS_REGION")
            .ok()
            .or_else(|| env::var("AWS_DEFAULT_REGION").ok());

        if account_id.is_some() {
            if partition.is_none() {
                tracing::warn!(
                    "kms_account_id is set but AWS_PARTITION is unset; \
                     KMS key IDs will be passed through unchanged"
                );
            }
            if region.is_none() {
                tracing::warn!(
                    "kms_account_id is set but neither AWS_REGION nor \
                     AWS_DEFAULT_REGION is set; KMS key IDs will be passed \
                     through unchanged"
                );
            }
        }

        Self {
            partition,
            region,
            account_id,
        }
    }

    /// Wrap a raw KMS key ID into a full ARN, or pass it through if the
    /// resolver has no target account configured, env vars are missing, or
    /// the input is already an ARN.
    pub fn resolve(&self, raw: &str) -> String {
        if raw.starts_with("arn:") {
            return raw.to_owned();
        }
        let (Some(account), Some(partition), Some(region)) =
            (&self.account_id, &self.partition, &self.region)
        else {
            return raw.to_owned();
        };
        if raw.starts_with("alias/") {
            format!("arn:{partition}:kms:{region}:{account}:{raw}")
        } else {
            format!("arn:{partition}:kms:{region}:{account}:key/{raw}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver(
        account: Option<&str>,
        partition: Option<&str>,
        region: Option<&str>,
    ) -> KmsArnResolver {
        KmsArnResolver {
            partition: partition.map(str::to_owned),
            region: region.map(str::to_owned),
            account_id: account.map(str::to_owned),
        }
    }

    #[test]
    fn pass_through_when_no_account() {
        let r = resolver(None, Some("aws"), Some("us-east-1"));
        assert_eq!(r.resolve("mrk-abc"), "mrk-abc");
        assert_eq!(
            r.resolve("12345678-1234-1234-1234-123456789012"),
            "12345678-1234-1234-1234-123456789012",
        );
        assert_eq!(r.resolve("alias/foo"), "alias/foo");
    }

    #[test]
    fn pass_through_arn_input() {
        let r = resolver(Some("999988887777"), Some("aws"), Some("us-east-1"));
        let arn = "arn:aws:kms:us-west-2:111122223333:key/abc";
        assert_eq!(r.resolve(arn), arn);
    }

    #[test]
    fn build_arn_from_mrk_id() {
        let r = resolver(Some("111122223333"), Some("aws"), Some("us-east-1"));
        assert_eq!(
            r.resolve("mrk-12345678901234567890123456789012"),
            "arn:aws:kms:us-east-1:111122223333:key/mrk-12345678901234567890123456789012",
        );
    }

    #[test]
    fn build_arn_from_uuid() {
        let r = resolver(Some("111122223333"), Some("aws"), Some("us-east-1"));
        assert_eq!(
            r.resolve("12345678-1234-1234-1234-123456789012"),
            "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012",
        );
    }

    #[test]
    fn build_arn_from_alias() {
        let r = resolver(Some("111122223333"), Some("aws"), Some("us-east-1"));
        assert_eq!(
            r.resolve("alias/vouch-oidc"),
            "arn:aws:kms:us-east-1:111122223333:alias/vouch-oidc",
        );
    }

    #[test]
    fn govcloud_partition() {
        let r = resolver(
            Some("111122223333"),
            Some("aws-us-gov"),
            Some("us-gov-west-1"),
        );
        assert_eq!(
            r.resolve("mrk-abc"),
            "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/mrk-abc",
        );
    }

    #[test]
    fn pass_through_when_region_missing() {
        let r = resolver(Some("111122223333"), Some("aws"), None);
        assert_eq!(r.resolve("mrk-abc"), "mrk-abc");
    }

    #[test]
    fn pass_through_when_partition_missing() {
        let r = resolver(Some("111122223333"), None, Some("us-east-1"));
        assert_eq!(r.resolve("mrk-abc"), "mrk-abc");
    }
}
