# Empty String Config Overrides Fallback Chain

Detect configuration fields sourced from environment variables or CLI args that are used as-is when their value is an empty string, rather than being filtered out so the next provider in the fallback chain (IMDS, AWS SDK defaults, etc.) takes over.

## What to look for

Config fields backed by `#[arg(env = "...")]` clap attributes (in `crates/vouch-server/src/config.rs` and `crates/vouch-cli/src/commands/credential/aws.rs`) arrive as `Some("")` when the env var is set but empty, or when the CLI flag is passed with no value (e.g. `--aws-region=`). This `Some("")` is indistinguishable from a real value unless explicitly filtered.

Look for these patterns:

1. **`Option<String>` fields passed directly without a `.filter(|s| !s.is_empty())` guard** when the field feeds a downstream fallback chain (IMDS, AWS SDK default region provider, vendor-specific env-var detection).

2. **`env::var("...").ok()` calls without an empty-string filter** when the result is used as an override that bypasses a fallback (e.g. region resolution, FIPS endpoint, agent detection).

3. **`bootstrap_overlay_args`**: Any change to the bootstrap blob handling that re-introduces accepting empty blob values without `.filter(|v| !v.is_empty())`.

4. **Boolean-valued string fields parsed with `.map(|v| v.eq_ignore_ascii_case("true"))`** (e.g. `aws_use_fips_endpoint`): an empty string maps to `Some(false)`, explicitly disabling the feature and suppressing the SDK's own `AWS_USE_FIPS_ENDPOINT` provider chain.

5. **Agent-detection env vars** (`AGENT`, `AI_AGENT`) used without an `!val.is_empty()` guard: an empty value would match the `if let Some(val) = get(...)` branch and suppress downstream vendor-specific signals (`CLAUDECODE`, `CURSOR_AGENT`, etc.).

The affected fields and their correct guard are:

| Field / variable | Empty-means-unset guard required |
|---|---|
| `args.aws_region` | `.filter(|s| !s.is_empty())` before `.or_else(IMDS)` |
| `args.aws_az` | `.filter(|s| !s.is_empty())` before `.or_else(IMDS)` |
| `args.aws_partition` | `.filter(|s| !s.is_empty())` before `.or_else(IMDS)` |
| `args.aws_use_fips_endpoint` | `.as_deref().filter(|s| !s.is_empty()).map(parse_bool)` |
| `args.s3_config_region` | `.filter(|s| !s.is_empty())` |
| `env::var("AWS_DEFAULT_REGION").ok()` | `.filter(|s| !s.is_empty())` |
| `get("AGENT")` / `get("AI_AGENT")` | `&& !val.is_empty()` in the `if let` guard |
| bootstrap blob values in `bootstrap_overlay_args` | `.filter(|v| !v.is_empty())` on the `blob.get(env_name)` result |

Any new `Option<String>` field with `#[arg(env = "...")]` that participates in an `.or_else(...)` fallback chain must apply the same guard before being returned.

## Violation examples

**Missing filter on CLI arg before IMDS fallback** (pre-fix pattern for `aws_region`, `aws_az`, `aws_partition`):
```rust
// VIOLATION: Some("") passed to fallback chain; IMDS never reached
let aws_region = args
    .aws_region
    .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
    .or_else(|| instance.map(|b| b.region.clone()));
```

**Boolean parse without empty-string guard** (pre-fix pattern for `aws_use_fips_endpoint`):
```rust
// VIOLATION: empty string yields Some(false), disabling FIPS and
// overriding the AWS SDK's AWS_USE_FIPS_ENDPOINT provider chain
let aws_use_fips_endpoint = args
    .aws_use_fips_endpoint
    .as_deref()
    .map(|v| v.eq_ignore_ascii_case("true"));
```

**Direct assignment of Option field without filter** (pre-fix pattern for `s3_config_region`):
```rust
// VIOLATION: Some("") reaches aws_config_loader → Region::new("") overrides
// the SDK's default region provider chain
s3_config_region: args.s3_config_region,
```

**Bootstrap blob value accepted when empty** (pre-fix pattern in `bootstrap_overlay_args`):
```rust
// VIOLATION: empty blob value emits --aws-region= which clap parses as
// Some(""), blocking the IMDS fallback in ServerConfig::from_args
let Some(value) = blob.get(env_name) else {
    continue;
};
```

**Agent env var consumed when empty** (pre-fix pattern for `AGENT` in `detect_agent_source_from`):
```rust
// VIOLATION: empty AGENT suppresses CLAUDECODE=1 and all other real signals
if let Some(val) = get("AGENT") {
    return Some(match val.as_str() { ... });
}
```

## Correct patterns

**Filter before fallback chain**:
```rust
let aws_region = args
    .aws_region
    .filter(|s| !s.is_empty())
    .or_else(|| {
        std::env::var("AWS_DEFAULT_REGION")
            .ok()
            .filter(|s| !s.is_empty())
    })
    .or_else(|| instance.map(|b| b.region.clone()));
```

**Filter boolean-valued string before parse**:
```rust
let aws_use_fips_endpoint = args
    .aws_use_fips_endpoint
    .as_deref()
    .filter(|s| !s.is_empty())
    .map(|v| v.eq_ignore_ascii_case("true"));
```

**Filter at assignment site**:
```rust
s3_config_region: args.s3_config_region.filter(|s| !s.is_empty()),
```

**Filter bootstrap blob values**:
```rust
let Some(value) = blob.get(env_name).filter(|v| !v.is_empty()) else {
    continue;
};
```

**Guard agent detection**:
```rust
if let Some(val) = get("AGENT")
    && !val.is_empty()
{
    return Some(match val.as_str() { ... });
}
```

## Scope

- `crates/vouch-server/src/config.rs` — `ServerConfig::from_args`, `bootstrap_overlay_args`, and any new `Args` field with `#[arg(env = "...")]` that feeds a fallback chain
- `crates/vouch-cli/src/commands/credential/aws.rs` — `detect_agent_source_from` and any new agent env var detection
- `crates/vouch-cli/src/integrations/aws/mod.rs` — `resolve_region` and similar env-var-driven region/profile resolution
- `crates/vouch-cli/src/commands/credential/codecommit.rs` — `resolve_region` and similar env-var fallback chains

Any file in these crates that reads an `Option<String>` from a clap `#[arg(env)]` field or calls `std::env::var(...).ok()` and uses the result as an override ahead of a documented fallback (IMDS, AWS SDK provider chain, vendor-specific env var) is in scope.
