# AWS Cross-Partition Region/Role Mismatch

Detect AWS flows that resolve a region and a role ARN independently and then use them together in a service call (STS `AssumeRoleWithWebIdentity`, CodeCommit SigV4 signing, SSM/EKS setup) without first validating that both belong to the same AWS partition, resulting in opaque 403 errors from the service endpoint.

## What to look for

A violation occurs when code:

1. **Resolves a region** via any of `resolve_region(...)`, `resolve_region_with_fallback(...)`, `resolve_role_and_region(...)`, `find_region(...)`, `extract_region_from_hostname(...)`, or an explicit `--region` CLI argument — AND
2. **Resolves a role ARN** separately via `resolve_vouch_profile(...)`, `select_vouch_profile(...)`, a `--role` argument, or a URL profile — AND
3. **Uses both together** in a downstream service call (STS endpoint URL construction, `sign_request(...)`, `exchange_for_sts_credentials(...)`, `get_aws_credentials(...)`, EKS `describe_cluster`, or SSM session setup) — WITHOUT calling **`validate_region_for_role(region, role_arn)`** or **`validate_region_partition(region, arn_partition)`** before the service call.

The STS endpoint DNS suffix is derived from the role ARN's partition (e.g., `sts.amazonaws.com` for `aws`, `sts.cn-north-1.amazonaws.com.cn` for `aws-cn`). A China region paired with a commercial ARN — or a GovCloud role with a fallback `us-east-1` — produces a request the endpoint's partition rejects with a generic 403.

**Key invariant**: every path that pairs a resolved region with a role ARN for a Vouch-built endpoint must call `validate_region_for_role` or `validate_region_partition` before any network call.

**When `None` is correct**: `resolve_region(..., None)` (no role ARN) is acceptable only when the region exclusively feeds the native AWS CLI's own `--region` flag and `credential_process` is not involved, or when the caller is using an explicitly user-named non-Vouch profile (e.g., `SsmProfile::Explicit`).

## Violation examples

**Missing partition guard in `resolve_region` call (setup eks before fix)**
```rust
// resolve_region called without role ARN — EKS later uses region + role_arn together
let role_arn = vouch_profile.role_arn;
let region_name = aws::resolve_region(region, &profile_name)?;
// ... then region_name and role_arn used in describe_cluster and STS calls
```

**Missing partition guard in `resolve_region_with_fallback` (before fix)**
```rust
// No partition validation; mismatched profile region silently accepted
pub(crate) fn resolve_region_with_fallback(role_arn: &str) -> anyhow::Result<String> {
    // ...
    if let Some(r) = find_region(None, profile_name.as_deref())? {
        return Ok(r);  // returned without validate_region_partition
    }
    let arn = sts::parse_role_arn(role_arn)?;
    let default = arn.partition.default_sts_region();
    Ok(default.to_string())
}
```

**Missing partition guard in `resolve_role_and_region` (before fix)**
```rust
pub(crate) fn resolve_role_and_region(...) -> anyhow::Result<(String, String)> {
    // ...
    let region_name = find_region(region, profile_name.as_deref())?.ok_or_else(no_region_error)?;
    // region_name returned and used with role_arn, but no validate_region_partition call
    Ok((role_arn, region_name))
}
```

**CodeCommit credential helper signs before validating (before fix)**
```rust
// get_sts_credentials called before the region/role partition is checked
let creds = get_sts_credentials(profile).await?;
let signed = sign_request(&creds, host, &canonical_path, region);
```

**CodeCommit remote helper signs before validating (before fix)**
```rust
let creds = get_sts_credentials(parsed.profile.as_deref()).await?;
let signed = sign_request(&creds, &hostname, &path, &region);
// region derived from URL, creds from a role that may be in another partition
```

**SSM setup passing `None` role ARN when auto-detected Vouch profile is available (before fix)**
```rust
let profile_name = resolve_ssm_profile(profile)?;
// Vouch auto-detected profile has a role_arn, but None is passed — skips validation
let region_name = aws::resolve_region(region, &profile_name, None)?;
```

## Correct patterns

**`resolve_region` with role ARN for EKS (correct)**
```rust
let role_arn = vouch_profile.role_arn;
let region_name = aws::resolve_region(region, &profile_name, Some(&role_arn))?;
```

**`resolve_region_with_fallback` with partition guard (correct)**
```rust
if let Some(r) = find_region(None, profile_name.as_deref())? {
    validate_region_partition(&r, arn_partition)?;  // guard before returning
    return Ok(r);
}
```

**`resolve_role_and_region` with partition guard (correct)**
```rust
let arn_partition = vouch_common::aws::Partition::from_arn(&role_arn).map_err(|_| { ... })?;
let region_name = find_region(region, profile_name.as_deref())?.ok_or_else(no_region_error)?;
validate_region_partition(&region_name, arn_partition)?;
Ok((role_arn, region_name))
```

**CodeCommit helpers resolve role first, validate, then sign (correct)**
```rust
let vouch_profile = resolve_vouch_profile(profile, ProfileOverride::Profile)?;
crate::integrations::aws::validate_region_for_role(region, &vouch_profile.role_arn)?;
let creds = get_sts_credentials(&vouch_profile.role_arn).await?;
let signed = sign_request(&creds, host, &canonical_path, region);
```

**SSM uses `SsmProfile` enum to carry role ARN when auto-detected (correct)**
```rust
// SsmProfile::Vouch carries the role_arn; SsmProfile::Explicit yields None (no ARN to validate)
let ssm_profile = SsmProfile::resolve(profile)?;
let region_name = aws::resolve_region(region, ssm_profile.name(), ssm_profile.validation_arn())?;
```

**`validate_region_for_role` wrapper (correct for callers holding an ARN string)**
```rust
pub(crate) fn validate_region_for_role(region: &str, role_arn: &str) -> Result<(), CliError> {
    let arn_partition = vouch_common::aws::Partition::from_arn(role_arn)
        .map_err(|_| CliError::ConfigError(tr!("aws-console-err-invalid-role-arn")))?;
    validate_region_partition(region, arn_partition)
}
```

## Scope

Check all files under:
- `crates/vouch-cli/src/integrations/aws/` — especially `mod.rs`, `sts.rs`, `codecommit.rs`
- `crates/vouch-cli/src/commands/credential/` — especially `aws.rs`, `codecommit.rs`
- `crates/vouch-cli/src/commands/setup/` — especially `eks.rs`, `ssm.rs`, `aws.rs`
- `crates/vouch-cli/src/commands/aws/` — especially `console.rs`

Any new command or helper that: (a) calls `resolve_region`, `resolve_region_with_fallback`, `resolve_role_and_region`, `find_region`, or extracts a region from a URL/hostname, **and** (b) pairs that region with a Vouch-managed role ARN for a Vouch-built AWS endpoint, must validate the partition pair before the service call.
