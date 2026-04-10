// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AWS partition definitions shared across CLI and server.

/// AWS partition identifier.
///
/// Each partition is a fully isolated instance of the AWS infrastructure
/// with its own DNS suffix, IAM system, and billing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Partition {
    /// Commercial (amazonaws.com)
    Aws,
    /// China (amazonaws.com.cn)
    AwsCn,
    /// GovCloud US (amazonaws.com)
    AwsUsGov,
    /// European Sovereign Cloud (amazonaws.eu)
    AwsEusc,
    /// US ISO - C2S (c2s.ic.gov)
    AwsIso,
    /// US ISO-B - SC2S (sc2s.sgov.gov)
    AwsIsoB,
    /// UK ISO-E - ADC (cloud.adc-e.uk)
    AwsIsoE,
    /// US ISO-F - CSP (csp.hci.ic.gov)
    AwsIsoF,
}

impl Partition {
    /// Parse a partition string from an ARN segment.
    ///
    /// # Errors
    ///
    /// Returns an error if the partition string is not recognized.
    pub fn parse(s: &str) -> Result<Self, PartitionError> {
        match s {
            "aws" => Ok(Self::Aws),
            "aws-cn" => Ok(Self::AwsCn),
            "aws-us-gov" => Ok(Self::AwsUsGov),
            "aws-eusc" => Ok(Self::AwsEusc),
            "aws-iso" => Ok(Self::AwsIso),
            "aws-iso-b" => Ok(Self::AwsIsoB),
            "aws-iso-e" => Ok(Self::AwsIsoE),
            "aws-iso-f" => Ok(Self::AwsIsoF),
            _ => Err(PartitionError(s.to_string())),
        }
    }

    /// Extract the partition from an ARN string.
    ///
    /// Prefer [`Arn::parse`] when you need more than just the partition.
    ///
    /// # Errors
    ///
    /// Returns an error if the ARN is malformed or the partition
    /// is not recognized.
    pub fn from_arn(arn: &str) -> Result<Self, PartitionError> {
        let parsed = Arn::parse(arn).map_err(|_| PartitionError(arn.to_string()))?;
        Ok(parsed.partition)
    }

    /// Default region for STS API calls in this partition.
    ///
    /// STS `AssumeRoleWithWebIdentity` is region-agnostic — the call
    /// succeeds against any regional endpoint regardless of where the
    /// IAM role lives. We pick a well-known region per partition as a
    /// fallback when no region is configured.
    #[must_use]
    pub fn default_sts_region(self) -> &'static str {
        match self {
            Self::Aws => "us-east-1",
            Self::AwsCn => "cn-north-1",
            Self::AwsUsGov => "us-gov-west-1",
            Self::AwsEusc => "eusc-de-east-1",
            Self::AwsIso => "us-iso-east-1",
            Self::AwsIsoB => "us-isob-east-1",
            Self::AwsIsoE => "eu-isoe-west-1",
            Self::AwsIsoF => "us-isof-south-1",
        }
    }

    /// String representation of the partition name as used in ARNs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::AwsCn => "aws-cn",
            Self::AwsUsGov => "aws-us-gov",
            Self::AwsEusc => "aws-eusc",
            Self::AwsIso => "aws-iso",
            Self::AwsIsoB => "aws-iso-b",
            Self::AwsIsoE => "aws-iso-e",
            Self::AwsIsoF => "aws-iso-f",
        }
    }

    /// Infer the AWS partition from a region string.
    ///
    /// Checks longer prefixes before shorter ones to avoid false matches
    /// (e.g., `us-isob-` before `us-iso-`).
    #[must_use]
    pub fn from_region(region: &str) -> Self {
        if region.starts_with("cn-") {
            Self::AwsCn
        } else if region.starts_with("us-gov-") {
            Self::AwsUsGov
        } else if region.starts_with("us-isob-") {
            Self::AwsIsoB
        } else if region.starts_with("us-isof-") {
            Self::AwsIsoF
        } else if region.starts_with("us-iso-") {
            Self::AwsIso
        } else if region.starts_with("eu-isoe-") {
            Self::AwsIsoE
        } else if region.starts_with("eusc-") {
            Self::AwsEusc
        } else {
            Self::Aws
        }
    }

    /// SSO OIDC endpoint for this partition.
    #[must_use]
    pub fn sso_oidc_endpoint(self, region: &str) -> String {
        format!("https://oidc.{}.{}", region, self.dns_suffix())
    }

    /// SSO Portal endpoint for this partition.
    #[must_use]
    pub fn sso_portal_endpoint(self, region: &str) -> String {
        format!("https://portal.sso.{}.{}", region, self.dns_suffix())
    }

    /// AWS Console sign-in federation endpoint for this partition.
    ///
    /// Used to obtain a sign-in token and construct a console login URL.
    /// See: <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html>
    ///
    /// Note: China uses `amazonaws.cn` for console/signin portals, NOT
    /// `amazonaws.com.cn` (which is the API endpoint DNS suffix from
    /// [`dns_suffix`](Self::dns_suffix)).
    ///
    /// # Errors
    ///
    /// Returns an error for ISO partitions which do not support console
    /// federation.
    pub fn federation_endpoint(self) -> Result<&'static str, FederationError> {
        match self {
            Self::Aws => Ok("https://signin.aws.amazon.com/federation"),
            // amazonaws.cn, not amazonaws.com.cn — see doc comment
            Self::AwsCn => Ok("https://signin.amazonaws.cn/federation"),
            Self::AwsUsGov => Ok("https://signin.amazonaws-us-gov.com/federation"),
            Self::AwsEusc => Ok("https://signin.amazonaws-eusc.eu/federation"),
            Self::AwsIso | Self::AwsIsoB | Self::AwsIsoE | Self::AwsIsoF => {
                Err(FederationError(self))
            }
        }
    }

    /// AWS Management Console URL for this partition.
    ///
    /// # Errors
    ///
    /// Returns an error for ISO partitions which do not have a public
    /// console URL.
    pub fn console_url(self) -> Result<&'static str, FederationError> {
        match self {
            Self::Aws => Ok("https://console.aws.amazon.com/"),
            // amazonaws.cn, not amazonaws.com.cn — see federation_endpoint doc
            Self::AwsCn => Ok("https://console.amazonaws.cn/"),
            Self::AwsUsGov => Ok("https://console.amazonaws-us-gov.com/"),
            Self::AwsEusc => Ok("https://console.amazonaws-eusc.eu/"),
            Self::AwsIso | Self::AwsIsoB | Self::AwsIsoE | Self::AwsIsoF => {
                Err(FederationError(self))
            }
        }
    }

    /// DNS suffix for this partition's AWS endpoints.
    #[must_use]
    pub fn dns_suffix(self) -> &'static str {
        match self {
            Self::Aws | Self::AwsUsGov => "amazonaws.com",
            Self::AwsCn => "amazonaws.com.cn",
            Self::AwsEusc => "amazonaws.eu",
            Self::AwsIso => "c2s.ic.gov",
            Self::AwsIsoB => "sc2s.sgov.gov",
            Self::AwsIsoE => "cloud.adc-e.uk",
            Self::AwsIsoF => "csp.hci.ic.gov",
        }
    }
}

impl std::fmt::Display for Partition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when a partition string is not recognized.
#[derive(Debug, thiserror::Error)]
#[error(
    "Unknown AWS partition: '{0}'\n\
     Expected one of: aws, aws-cn, aws-us-gov, aws-eusc, \
     aws-iso, aws-iso-b, aws-iso-e, aws-iso-f"
)]
pub struct PartitionError(String);

/// Error returned when console federation is not supported for a
/// partition.
#[derive(Debug, thiserror::Error)]
#[error("AWS Console federation is not supported for the '{0}' partition")]
pub struct FederationError(Partition);

/// Parsed AWS ARN (Amazon Resource Name).
///
/// Follows the [ARN format specification][arn-ref]:
/// ```text
/// arn:partition:service:region:account-id:resource
/// ```
///
/// Region and account may be absent depending on the resource type
/// (e.g., IAM resources have no region, S3 buckets have no account).
///
/// [arn-ref]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arn {
    /// The AWS partition.
    pub partition: Partition,
    /// The service namespace (e.g., `"iam"`, `"sso"`, `"s3"`).
    pub service: String,
    /// The region, if present (e.g., `"us-east-1"`).
    pub region: Option<String>,
    /// The account ID, if present (e.g., `"123456789012"`).
    pub account: Option<String>,
    /// The resource portion (everything after the 5th colon).
    pub resource: String,
}

/// Error returned when an ARN string cannot be parsed.
#[derive(Debug, thiserror::Error)]
#[error(
    "Invalid ARN: '{0}'\n\
     Expected format: arn:<partition>:<service>:<region>:<account>:<resource>"
)]
pub struct ArnError(String);

impl Arn {
    /// Parse an ARN string into its components.
    ///
    /// Empty region/account fields become `None`.
    ///
    /// # Errors
    ///
    /// Returns [`ArnError`] if the string does not start with `arn:`,
    /// does not contain at least 6 colon-separated segments, or the
    /// partition is not recognized.
    pub fn parse(arn: &str) -> Result<Self, ArnError> {
        let rest = arn
            .strip_prefix("arn:")
            .ok_or_else(|| ArnError(arn.to_string()))?;

        // Split into at most 6 parts (resource may contain colons)
        let mut parts = rest.splitn(5, ':');

        let partition_str = parts.next().ok_or_else(|| ArnError(arn.to_string()))?;
        let service = parts.next().ok_or_else(|| ArnError(arn.to_string()))?;
        let region = parts.next().ok_or_else(|| ArnError(arn.to_string()))?;
        let account = parts.next().ok_or_else(|| ArnError(arn.to_string()))?;
        let resource = parts.next().ok_or_else(|| ArnError(arn.to_string()))?;

        if service.is_empty() || resource.is_empty() {
            return Err(ArnError(arn.to_string()));
        }

        let partition = Partition::parse(partition_str).map_err(|_| ArnError(arn.to_string()))?;

        Ok(Self {
            partition,
            service: service.to_string(),
            region: (!region.is_empty()).then(|| region.to_string()),
            account: (!account.is_empty()).then(|| account.to_string()),
            resource: resource.to_string(),
        })
    }

    /// Check whether this ARN refers to an IAM role.
    #[must_use]
    pub fn is_iam_role(&self) -> bool {
        self.service == "iam" && self.resource.starts_with("role/") && self.resource.len() > 5
    }
}

impl std::fmt::Display for Arn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "arn:{}:{}:{}:{}:{}",
            self.partition.as_str(),
            self.service,
            self.region.as_deref().unwrap_or(""),
            self.account.as_deref().unwrap_or(""),
            self.resource,
        )
    }
}

/// Compute an expiration timestamp from a duration in seconds.
///
/// # Errors
///
/// Returns an error if the resulting timestamp overflows.
pub fn expiration_from_secs(expires_in: u64) -> Result<jiff::Timestamp, jiff::Error> {
    jiff::Timestamp::now().checked_add(jiff::SignedDuration::from_secs(
        i64::try_from(expires_in).unwrap_or(i64::MAX),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_all_valid() {
        assert_eq!(Partition::parse("aws").unwrap(), Partition::Aws);
        assert_eq!(Partition::parse("aws-cn").unwrap(), Partition::AwsCn);
        assert_eq!(Partition::parse("aws-us-gov").unwrap(), Partition::AwsUsGov);
        assert_eq!(Partition::parse("aws-eusc").unwrap(), Partition::AwsEusc);
        assert_eq!(Partition::parse("aws-iso").unwrap(), Partition::AwsIso);
        assert_eq!(Partition::parse("aws-iso-b").unwrap(), Partition::AwsIsoB);
        assert_eq!(Partition::parse("aws-iso-e").unwrap(), Partition::AwsIsoE);
        assert_eq!(Partition::parse("aws-iso-f").unwrap(), Partition::AwsIsoF);
    }

    #[test]
    fn test_parse_unknown() {
        assert!(Partition::parse("unknown").is_err());
        assert!(Partition::parse("").is_err());
    }

    #[test]
    fn test_from_arn_commercial() {
        let p = Partition::from_arn("arn:aws:iam::123456789012:role/MyRole").unwrap();
        assert_eq!(p, Partition::Aws);
    }

    #[test]
    fn test_from_arn_china() {
        let p = Partition::from_arn("arn:aws-cn:iam::123456789012:role/MyRole").unwrap();
        assert_eq!(p, Partition::AwsCn);
    }

    #[test]
    fn test_from_arn_govcloud() {
        let p = Partition::from_arn("arn:aws-us-gov:iam::123456789012:role/MyRole").unwrap();
        assert_eq!(p, Partition::AwsUsGov);
    }

    #[test]
    fn test_from_arn_eusc() {
        let p = Partition::from_arn("arn:aws-eusc:iam::123456789012:role/MyRole").unwrap();
        assert_eq!(p, Partition::AwsEusc);
    }

    #[test]
    fn test_from_arn_invalid() {
        assert!(Partition::from_arn("not-an-arn").is_err());
        assert!(Partition::from_arn("arn:unknown:iam::123:role/R").is_err());
    }

    #[test]
    fn test_default_sts_region() {
        assert_eq!(Partition::Aws.default_sts_region(), "us-east-1");
        assert_eq!(Partition::AwsCn.default_sts_region(), "cn-north-1");
        assert_eq!(Partition::AwsUsGov.default_sts_region(), "us-gov-west-1");
        assert_eq!(Partition::AwsEusc.default_sts_region(), "eusc-de-east-1");
        assert_eq!(Partition::AwsIso.default_sts_region(), "us-iso-east-1");
        assert_eq!(Partition::AwsIsoB.default_sts_region(), "us-isob-east-1");
        assert_eq!(Partition::AwsIsoE.default_sts_region(), "eu-isoe-west-1");
        assert_eq!(Partition::AwsIsoF.default_sts_region(), "us-isof-south-1");
    }

    // =========================================================================
    // Arn tests
    // =========================================================================

    #[test]
    fn test_arn_parse_iam_role() {
        let arn = Arn::parse("arn:aws:iam::123456789012:role/MyRole").unwrap();
        assert_eq!(arn.partition, Partition::Aws);
        assert_eq!(arn.service, "iam");
        assert_eq!(arn.region, None);
        assert_eq!(arn.account.as_deref(), Some("123456789012"));
        assert_eq!(arn.resource, "role/MyRole");
        assert!(arn.is_iam_role());
    }

    #[test]
    fn test_arn_parse_sso_application() {
        let arn = Arn::parse("arn:aws:sso::123456789012:application/ssoins-abc/apl-xyz").unwrap();
        assert_eq!(arn.partition, Partition::Aws);
        assert_eq!(arn.service, "sso");
        assert_eq!(arn.account.as_deref(), Some("123456789012"));
        assert_eq!(arn.resource, "application/ssoins-abc/apl-xyz");
        assert!(!arn.is_iam_role());
    }

    #[test]
    fn test_arn_parse_with_region() {
        let arn = Arn::parse("arn:aws:sns:us-east-1:123456789012:my-topic").unwrap();
        assert_eq!(arn.service, "sns");
        assert_eq!(arn.region.as_deref(), Some("us-east-1"));
        assert_eq!(arn.account.as_deref(), Some("123456789012"));
        assert_eq!(arn.resource, "my-topic");
    }

    #[test]
    fn test_arn_parse_no_region_no_account() {
        let arn = Arn::parse("arn:aws:s3:::my-bucket").unwrap();
        assert_eq!(arn.service, "s3");
        assert_eq!(arn.region, None);
        assert_eq!(arn.account, None);
        assert_eq!(arn.resource, "my-bucket");
    }

    #[test]
    fn test_arn_parse_china_partition() {
        let arn = Arn::parse("arn:aws-cn:iam::123456789012:role/MyRole").unwrap();
        assert_eq!(arn.partition, Partition::AwsCn);
    }

    #[test]
    fn test_arn_parse_govcloud_partition() {
        let arn = Arn::parse("arn:aws-us-gov:iam::123456789012:role/MyRole").unwrap();
        assert_eq!(arn.partition, Partition::AwsUsGov);
    }

    #[test]
    fn test_arn_parse_unknown_partition_rejected() {
        assert!(Arn::parse("arn:aws-future:iam::123456789012:role/MyRole").is_err());
    }

    #[test]
    fn test_arn_parse_with_colons_in_resource() {
        let arn = Arn::parse("arn:aws:iam::123456789012:role/path:to:thing").unwrap();
        assert_eq!(arn.resource, "role/path:to:thing");
    }

    #[test]
    fn test_arn_parse_invalid() {
        assert!(Arn::parse("not-an-arn").is_err());
        assert!(Arn::parse("").is_err());
        assert!(Arn::parse("arn:aws:iam::123:").is_err());
        assert!(Arn::parse("arn:aws:iam").is_err());
        assert!(Arn::parse("arn::iam::123:role/R").is_err());
        assert!(Arn::parse("arn:aws:::123:role/R").is_err());
    }

    #[test]
    fn test_arn_is_not_iam_role() {
        let arn = Arn::parse("arn:aws:iam::123456789012:user/MyUser").unwrap();
        assert!(!arn.is_iam_role());
    }

    #[test]
    fn test_arn_display_roundtrip() {
        let inputs = [
            "arn:aws:iam::123456789012:role/MyRole",
            "arn:aws:s3:::my-bucket",
            "arn:aws:sns:us-east-1:123456789012:my-topic",
            "arn:aws-cn:iam::123456789012:role/MyRole",
        ];
        for input in &inputs {
            let arn = Arn::parse(input).unwrap();
            assert_eq!(arn.to_string(), *input);
        }
    }

    #[test]
    fn test_partition_as_str_roundtrip() {
        let partitions = [
            Partition::Aws,
            Partition::AwsCn,
            Partition::AwsUsGov,
            Partition::AwsEusc,
            Partition::AwsIso,
            Partition::AwsIsoB,
            Partition::AwsIsoE,
            Partition::AwsIsoF,
        ];
        for p in &partitions {
            assert_eq!(Partition::parse(p.as_str()).unwrap(), *p);
        }
    }

    // =========================================================================
    // from_region tests
    // =========================================================================

    #[test]
    fn test_from_region_commercial() {
        assert_eq!(Partition::from_region("us-east-1"), Partition::Aws);
        assert_eq!(Partition::from_region("eu-west-1"), Partition::Aws);
        assert_eq!(Partition::from_region("ap-southeast-2"), Partition::Aws);
    }

    #[test]
    fn test_from_region_china() {
        assert_eq!(Partition::from_region("cn-north-1"), Partition::AwsCn);
        assert_eq!(Partition::from_region("cn-northwest-1"), Partition::AwsCn);
    }

    #[test]
    fn test_from_region_govcloud() {
        assert_eq!(Partition::from_region("us-gov-west-1"), Partition::AwsUsGov);
        assert_eq!(Partition::from_region("us-gov-east-1"), Partition::AwsUsGov);
    }

    #[test]
    fn test_from_region_iso_prefix_ordering() {
        // us-isob- must be checked before us-iso- to avoid false match
        assert_eq!(Partition::from_region("us-isob-east-1"), Partition::AwsIsoB);
        assert_eq!(
            Partition::from_region("us-isof-south-1"),
            Partition::AwsIsoF
        );
        assert_eq!(Partition::from_region("us-iso-east-1"), Partition::AwsIso);
        assert_eq!(Partition::from_region("us-iso-west-1"), Partition::AwsIso);
        assert_eq!(Partition::from_region("eu-isoe-west-1"), Partition::AwsIsoE);
    }

    #[test]
    fn test_from_region_eusc() {
        assert_eq!(Partition::from_region("eusc-de-east-1"), Partition::AwsEusc);
    }

    #[test]
    fn test_from_region_unknown_defaults_commercial() {
        assert_eq!(Partition::from_region("unknown-region-1"), Partition::Aws);
        assert_eq!(Partition::from_region(""), Partition::Aws);
    }

    // =========================================================================

    #[test]
    fn test_sso_oidc_endpoint_commercial() {
        assert_eq!(
            Partition::Aws.sso_oidc_endpoint("us-east-1"),
            "https://oidc.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn test_sso_oidc_endpoint_china() {
        assert_eq!(
            Partition::AwsCn.sso_oidc_endpoint("cn-north-1"),
            "https://oidc.cn-north-1.amazonaws.com.cn"
        );
    }

    #[test]
    fn test_sso_portal_endpoint_commercial() {
        assert_eq!(
            Partition::Aws.sso_portal_endpoint("us-east-1"),
            "https://portal.sso.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn test_sso_portal_endpoint_govcloud() {
        assert_eq!(
            Partition::AwsUsGov.sso_portal_endpoint("us-gov-west-1"),
            "https://portal.sso.us-gov-west-1.amazonaws.com"
        );
    }

    #[test]
    fn test_dns_suffix() {
        assert_eq!(Partition::Aws.dns_suffix(), "amazonaws.com");
        assert_eq!(Partition::AwsCn.dns_suffix(), "amazonaws.com.cn");
        assert_eq!(Partition::AwsUsGov.dns_suffix(), "amazonaws.com");
        assert_eq!(Partition::AwsEusc.dns_suffix(), "amazonaws.eu");
        assert_eq!(Partition::AwsIso.dns_suffix(), "c2s.ic.gov");
        assert_eq!(Partition::AwsIsoB.dns_suffix(), "sc2s.sgov.gov");
        assert_eq!(Partition::AwsIsoE.dns_suffix(), "cloud.adc-e.uk");
        assert_eq!(Partition::AwsIsoF.dns_suffix(), "csp.hci.ic.gov");
    }

    // =========================================================================
    // Federation endpoint tests
    // =========================================================================

    #[test]
    fn test_federation_endpoint_commercial() {
        assert_eq!(
            Partition::Aws.federation_endpoint().unwrap(),
            "https://signin.aws.amazon.com/federation"
        );
    }

    #[test]
    fn test_federation_endpoint_china() {
        assert_eq!(
            Partition::AwsCn.federation_endpoint().unwrap(),
            "https://signin.amazonaws.cn/federation"
        );
    }

    #[test]
    fn test_federation_endpoint_govcloud() {
        assert_eq!(
            Partition::AwsUsGov.federation_endpoint().unwrap(),
            "https://signin.amazonaws-us-gov.com/federation"
        );
    }

    #[test]
    fn test_federation_endpoint_eusc() {
        assert_eq!(
            Partition::AwsEusc.federation_endpoint().unwrap(),
            "https://signin.amazonaws-eusc.eu/federation"
        );
    }

    #[test]
    fn test_federation_endpoint_iso_unsupported() {
        assert!(Partition::AwsIso.federation_endpoint().is_err());
        assert!(Partition::AwsIsoB.federation_endpoint().is_err());
        assert!(Partition::AwsIsoE.federation_endpoint().is_err());
        assert!(Partition::AwsIsoF.federation_endpoint().is_err());
    }

    // =========================================================================
    // Console URL tests
    // =========================================================================

    #[test]
    fn test_console_url_commercial() {
        assert_eq!(
            Partition::Aws.console_url().unwrap(),
            "https://console.aws.amazon.com/"
        );
    }

    #[test]
    fn test_console_url_china() {
        assert_eq!(
            Partition::AwsCn.console_url().unwrap(),
            "https://console.amazonaws.cn/"
        );
    }

    #[test]
    fn test_console_url_govcloud() {
        assert_eq!(
            Partition::AwsUsGov.console_url().unwrap(),
            "https://console.amazonaws-us-gov.com/"
        );
    }

    #[test]
    fn test_console_url_eusc() {
        assert_eq!(
            Partition::AwsEusc.console_url().unwrap(),
            "https://console.amazonaws-eusc.eu/"
        );
    }

    #[test]
    fn test_console_url_iso_unsupported() {
        assert!(Partition::AwsIso.console_url().is_err());
        assert!(Partition::AwsIsoB.console_url().is_err());
        assert!(Partition::AwsIsoE.console_url().is_err());
        assert!(Partition::AwsIsoF.console_url().is_err());
    }

    #[test]
    fn test_partition_display() {
        assert_eq!(Partition::Aws.to_string(), "aws");
        assert_eq!(Partition::AwsCn.to_string(), "aws-cn");
        assert_eq!(Partition::AwsUsGov.to_string(), "aws-us-gov");
    }
}
