# Posture Policies

Posture policies let you require that a user's device meets a security standard before Vouch will
issue them credentials. A laptop without full-disk encryption, or running an unsupported OS
version, can be refused a token even though the user holds a valid hardware key.

Policies also cover *timing*: a policy can require a recent hardware login before workload
credentials are issued, cap how many tokens a user obtains per hour, or refuse credentials after a
logout. These read the user's recent authentication history rather than their device.

> **Migrating from CEL.** Policies are written in
> [Dogwood](https://dogwood-policy.github.io/dogwood/) (Cedar plus temporal conditions). Custom
> policies written for the previous CEL engine are rejected when you edit them and fail closed at
> login until re-authored — see [Rewriting a CEL policy](#rewriting-a-cel-policy).

Manage them at `/admin/policies`.

## How enforcement works

The `vouch` CLI collects device posture attributes locally and sends them with the FIDO2 token
request. The server evaluates your active policies against those attributes **after** verifying the
FIDO2 assertion and **before** issuing the access token.

Policies are enforced at two points:

| Decision | When | Policies that apply |
|----------|------|---------------------|
| Token issuance | `vouch login` (FIDO2 assertion grant) | Device posture, plus history policies that count prior activity |
| Token exchange | Workload identity and agent credentials (RFC 8693) | History policies only — an exchange carries no device posture |

Recency policies ("logged in within 15 minutes") deliberately gate *exchange*, not login: the login
itself is a hardware authentication, so requiring a recent login there would always be satisfied.

If any active policy fails, the token request is rejected with OAuth `access_denied` and a message
naming the failed policy plus remediation guidance for the user's operating system:

```
Device posture policy 'Disk Encryption' not satisfied. Enable FileVault in
System Settings > Privacy & Security > FileVault.
```

The user cannot obtain credentials until they fix the device and retry. There is no override and no
grace period.

Three properties are worth understanding before you enable anything:

- **No active policies means no enforcement and no posture requirement.** The check short-circuits
  entirely.
- **Once any policy is active, a client that sends no posture data is denied.** Enabling your first
  policy therefore also requires every user to be on a CLI version that reports posture.
- **Evaluation is fail-closed.** An expression that errors at runtime, or returns a non-boolean,
  counts as a failure, not a pass.

> **Roll out carefully.** Turning on a policy takes effect at the next login for every user in the
> organization. Announce it, and check what your fleet actually reports first — a policy that
> looks obviously satisfiable can lock out a whole class of devices.

## Preconfigured policies

Six policies ship built in. Toggle each on or off from `/admin/policies`.

| Slug | Name | Requires |
|------|------|----------|
| `disk_encryption` | Disk Encryption | Full-disk encryption enabled (FileVault, BitLocker, LUKS) |
| `firewall` | Firewall | An active firewall |
| `screen_lock` | Screen Lock | Screen lock on idle enabled |
| `endpoint_protection` | Endpoint Protection | At least one EDR agent installed |
| `platform_integrity` | Platform Integrity | Secure Boot enabled |
| `os_recency` | OS Recency | macOS 14.0.0+ or Windows 24H2+. **Denies all Linux devices** — see below |

Five more policies read the user's recent authentication history instead of their device:

| Slug | Name | Denies when |
|------|------|-------------|
| `issuance_rate_limit` | Issuance Rate Limit | The user obtained 10 or more tokens in the past hour |
| `failed_login_burst` | Failed Login Burst | The user had 5 or more failed logins in the past ten minutes |
| `token_exchange_step_up` | Token Exchange Step-Up | No successful hardware login in the past 15 minutes (exchange only) |
| `exchange_ip_consistency` | Exchange IP Consistency | No successful login from this IP address in the past 8 hours (exchange only) |
| `logout_invalidates_exchange` | Logout Invalidates Exchange | The user logged out and has not logged in again (exchange only) |

History comes from the audit log, scoped to the requesting user and the past 24 hours. Two
consequences worth knowing: audit retention shorter than two days truncates the window a policy can
see (the server warns at startup), and audit writes on the login path are best-effort, so a dropped
write can under-count a rate limit by one event.

`os_recency` is the one with moving parts, and the one to be careful with. It passes a device only
if it is macOS 14.0.0 or later, **or** Windows 10.0.26100 (24H2) or later.

> **`os_recency` denies every Linux device.** The check has no Linux branch, so a Linux client
> matches neither condition and the policy fails closed. Distributions version independently, so
> there is no sensible built-in threshold — but the effect is a denial, not an exemption. The user
> sees: *"Linux is not covered by the built-in OS recency check. Your organization may have a
> custom policy for your distribution."*
>
> If any part of your fleet runs Linux, do not enable `os_recency`. Write a custom policy that
> covers all three platforms instead:
>
> ```cedar
> forbid (principal, action == Vouch::Action::"IssueToken", resource)
> unless {
>     (context.device.os == "macos" && context.device.os_version_num >= 14000000) ||
>     (context.device.os == "windows" && context.device.os_build_num >= 26100) ||
>     (context.device.os == "linux" && context.device.os_distribution == "ubuntu"
>         && context.device.os_version_num >= 22004000)
> };
> ```

Those thresholds are compiled into the server, so they advance when you upgrade Vouch. Read the
release notes before upgrading if `os_recency` is active: a raised floor can lock out devices that
were passing yesterday.

## Custom policies

For anything the built-ins do not cover, write a
[Dogwood/Cedar](https://dogwood-policy.github.io/dogwood/) `forbid` rule. The rule fires — and the
token request is denied — when its `unless` requirement is **not** met. Posture attributes live at
`context.posture`.

```cedar
// Require BitLocker specifically, not just any disk encryption
forbid (principal, action == Vouch::Action::"IssueToken", resource)
unless { context.device.disk_encryption_technology == "bitlocker" };

// Require a recent Ubuntu
forbid (principal, action == Vouch::Action::"IssueToken", resource)
unless { context.device.os_distribution == "ubuntu"
         && context.device.os_version_num >= 22004000 };

// Screen lock must engage within five minutes
forbid (principal, action == Vouch::Action::"IssueToken", resource)
unless { context.device.screen_lock_enabled
         && context.device.screen_lock_idle_timeout_secs <= 300 };

// Require both an EDR agent and MDM enrollment
forbid (principal, action == Vouch::Action::"IssueToken", resource)
unless { context.device.edr_count > 0 && context.device.mdm_count > 0 };

// Apply a rule only on macOS, passing every other platform
forbid (principal, action == Vouch::Action::"IssueToken", resource)
unless { context.device.os != "macos" || context.device.sip_enabled };
```

That last pattern matters: attributes are populated per platform, so an unqualified rule applies
everywhere. Guard on `context.device.os` when a requirement is platform-specific.

### Writing a history policy

A `when temporal { … }` clause reads the user's recent events. Windows are required, capped at 24
hours, and only `&&` and `!` are available inside the block (write separate policies for "or"):

```cedar
// Require a successful login within the last 30 minutes before exchanging tokens
forbid (principal, action == Vouch::Action::"ExchangeToken", resource)
when temporal {
    !(formerly within 30m Vouch::Action::"Login"::response{ output.result: true })
};

// Cap SSH certificate issuance at 5 per hour
forbid (principal, action == Vouch::Action::"IssueToken", resource)
when temporal {
    exists (n: Long). (
        (count_within(1h, Vouch::Action::"IssueCredential"::response{ input.kind: "ssh" })) == n
        && n >= 5
    )
};
```

Aggregations must be compared inside an `exists (n: Long). ((count_within(…)) == n && n >= K)`
binding — that shape is what lets the count be thresholded.

The policy editor validates history policies but cannot evaluate them: the test device has no
history, so a temporal result is labelled rather than reported as a plain pass or fail. Verify
these against a real account in a staging organization.

### Rewriting a CEL policy

CEL expressions were bare booleans; Dogwood policies are `forbid` rules, and posture attributes
moved from `posture.*` to `context.device.*`. A CEL rule that read:

```
posture.disk_encryption_technology == "bitlocker"
```

becomes:

```cedar
forbid (principal, action == Vouch::Action::"IssueToken", resource)
unless { context.device.disk_encryption_technology == "bitlocker" };
```

Note the inversion: CEL expressions stated what must be **true** to pass; a `forbid … unless` rule
states the same requirement, and denies when it is not met. Version comparisons that used
`semver(posture.os_version)` use the precomputed `context.device.os_version_num` field.

### Available attributes

Every attribute is always present in the evaluation context. When a client does not report one, it
takes a type-appropriate default — `false`, `""`, `0`, or `[]` — so an expression never errors on a
missing field. The corollary: **a missing attribute looks identical to a negative one.** Requiring
`posture.tpm_present == true` also fails every client too old to report it.

**Booleans** (default `false`)

`disk_encryption_enabled`, `screen_lock_enabled`, `firewall_enabled`, `secure_boot_enabled`,
`sip_enabled`, `tpm_present`, `auto_update_enabled`, `access_control_enforcing`, `elevated`, `tty`

**Strings** (default `""`)

`os`, `os_version`, `os_distribution`, `os_build`, `arch`, `disk_encryption_technology`,
`firewall_technology`, `tpm_version`, `auto_update_technology`, `access_control_technology`,
`parent_process`, `cli_version`, `collected_at`

**Numbers** (default `0`)

`screen_lock_idle_timeout_secs`, `uptime_secs`, `edr_count`, `mdm_count`

**Derived version numbers** (`-1` when unparseable)

`os_version_num` — `os_version` encoded as `major*1000000 + minor*1000 + patch`
(`"15.3.1"` → `15003001`; 4-component Windows versions encode as `-1`).
`os_build_num` — `os_build` parsed as an integer (`"26100"` → `26100`).

**Sets** (default empty)

`edr`, `mdm` — test membership with `context.device.edr.contains("crowdstrike")`

### Version comparison

Compare `os_version_num` (never the `os_version` string) — lexical comparison puts `"10.0.0"`
before `"9.0.0"`, the numeric encoding does not.

```cedar
context.device.os_version_num >= 14000000
```

## Testing an expression before you enable it

The policy editor validates expressions against sample posture data before you save, using
`POST /api/v1/org/policies/validate`. Use it — a syntactically valid expression that is
semantically wrong fails closed and locks users out.

Test at minimum: a device that should pass, a device that should fail, and a device reporting
nothing at all (the "old CLI" case).

## Enabling and disabling

Policies have an active flag independent of their existence, so you can stage one and turn it on
later, or disable one during an incident without losing it. Toggling takes effect on the next token
request; existing sessions are unaffected until they expire.

To roll back an over-strict policy, toggle it off — no restart required.

## Audit events

| Event | Trigger |
|-------|---------|
| `policy_denied` | A policy denied token issuance or exchange |
| `admin_policy_create` | Custom policy created |
| `admin_policy_update` | Custom policy edited |
| `admin_policy_delete` | Custom policy deleted |
| `admin_policy_toggle` | Any policy enabled or disabled |

These are in the never-purged retention class, so the record of when a policy was relaxed is
permanent. See [Audit Events](audit.md).

## Troubleshooting

**Everyone is denied right after enabling the first policy.**
Most likely the fleet is on a CLI too old to report posture. Once any policy is active, a request
carrying no posture data is rejected. Disable the policy, confirm CLI versions, then re-enable.

**A policy fails on devices that visibly satisfy it.**
The attribute probably is not reported on that platform and is defaulting to `false` or `""`. Check
the server log at `RUST_LOG=vouch_server=debug`, which logs each policy evaluation and its result,
then guard the expression on `posture.os`.

**A custom policy never passes.**
Runtime evaluation errors count as failures (fail-closed), and policies written in CEL syntax for
the pre-Dogwood engine always fail. Test the rule in the policy editor against known-good sample
posture.
