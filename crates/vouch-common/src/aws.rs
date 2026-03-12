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
    /// ARN format: `arn:{partition}:...`
    ///
    /// # Errors
    ///
    /// Returns an error if the ARN is malformed or the partition
    /// is not recognized.
    pub fn from_arn(arn: &str) -> Result<Self, PartitionError> {
        let partition_str = arn
            .strip_prefix("arn:")
            .and_then(|rest| rest.split(':').next())
            .ok_or_else(|| PartitionError(arn.to_string()))?;
        Self::parse(partition_str)
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

/// Error returned when a partition string is not recognized.
#[derive(Debug, thiserror::Error)]
#[error(
    "Unknown AWS partition: '{0}'\n\
     Expected one of: aws, aws-cn, aws-us-gov, aws-eusc, \
     aws-iso, aws-iso-b, aws-iso-e, aws-iso-f"
)]
pub struct PartitionError(String);

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
}
