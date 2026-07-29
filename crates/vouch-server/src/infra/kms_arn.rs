// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cross-account KMS key ARN resolution.
//!
//! When KMS keys live in a different AWS account than the server, the AWS SDK
//! must be given the full ARN rather than a bare key ID. This module combines
//! a resolved partition and region (from `ServerConfig`'s `aws_partition` /
//! `aws_region` fields — env or, on EC2, IMDS; see `infra::bootstrap`) with
//! the `kms_account_id` field from config, and wraps raw key IDs into full
//! ARNs.
//!
//! Pass-through cases (return the raw value unchanged):
//! - The configured value already starts with `arn:`.
//! - `kms_account_id` is unset (no cross-account access configured).
//! - Partition or region is missing (logged once at construction).

/// Resolves bare KMS key IDs into full ARNs for cross-account access.
#[derive(Debug, Clone)]
pub struct KmsArnResolver {
    partition: Option<String>,
    region: Option<String>,
    account_id: Option<String>,
}

impl KmsArnResolver {
    /// Build a resolver from an already-resolved partition, region, and the
    /// configured `kms_account_id`.
    ///
    /// When `kms_account_id` is `None`, the resolver becomes a no-op:
    /// every call to [`resolve`](Self::resolve) returns the input unchanged.
    pub fn new(
        kms_account_id: Option<&str>,
        partition: Option<&str>,
        region: Option<&str>,
    ) -> Self {
        let account_id = kms_account_id.map(str::to_owned);
        let partition = partition.map(str::to_owned);
        let region = region.map(str::to_owned);

        if account_id.is_some() {
            if partition.is_none() {
                tracing::warn!(
                    "kms_account_id is set but the AWS partition is unresolved; \
                     KMS key IDs will be passed through unchanged"
                );
            }
            if region.is_none() {
                tracing::warn!(
                    "kms_account_id is set but the AWS region is unresolved; \
                     KMS key IDs will be passed through unchanged"
                );
            }
        }

        Self {
            partition,
            region,
            account_id,
        }
    }

    /// Derive a resolver sharing this one's partition and region, but
    /// resolving keys under a different account.
    ///
    /// Used when an account ID becomes known after this resolver was
    /// constructed — e.g. an S3 config document's own `kms_account_id`,
    /// read only once the document has been fetched and parsed.
    #[must_use]
    pub fn with_account_id(&self, kms_account_id: Option<&str>) -> Self {
        Self {
            partition: self.partition.clone(),
            region: self.region.clone(),
            account_id: kms_account_id.map(str::to_owned),
        }
    }

    /// Wrap a raw KMS key ID into a full ARN, or pass it through if the
    /// resolver has no target account configured, partition/region are
    /// missing, or the input is already an ARN.
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

    #[test]
    fn empty_input_wraps_into_malformed_arn() {
        // Empty string falls through to the `key/` branch. KMS will reject
        // the resulting ARN, so the failure is loud — but the behavior is
        // pinned here so a future refactor doesn't silently change it.
        let r = resolver(Some("111122223333"), Some("aws"), Some("us-east-1"));
        assert_eq!(r.resolve(""), "arn:aws:kms:us-east-1:111122223333:key/");
    }

    #[test]
    fn bare_alias_prefix_wraps_into_malformed_arn() {
        // `alias/` with no name falls through the `alias/` branch and
        // produces an ARN with an empty alias name. KMS will reject it,
        // but document the behavior.
        let r = resolver(Some("111122223333"), Some("aws"), Some("us-east-1"));
        assert_eq!(
            r.resolve("alias/"),
            "arn:aws:kms:us-east-1:111122223333:alias/",
        );
    }
}
