# Posture Policies

Posture policies let you require that a user's device meets a security standard before Vouch will
issue them credentials. A laptop without full-disk encryption, or running an unsupported OS
version, can be refused a token even though the user holds a valid hardware key.

Manage them at `/admin/policies`.

## How enforcement works

The `vouch` CLI collects device posture attributes locally and sends them with the FIDO2 token
request. The server evaluates your active policies against those attributes **after** verifying the
FIDO2 assertion and **before** issuing the access token.

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
> ```javascript
> (posture.os == "macos" && semver(posture.os_version) >= semver("14.0.0"))
>   || (posture.os == "windows" && semver(posture.os_version) >= semver("10.0.26100"))
>   || (posture.os == "linux" && posture.os_distribution == "ubuntu"
>       && semver(posture.os_version) >= semver("22.04.0"))
> ```

Those thresholds are compiled into the server, so they advance when you upgrade Vouch. Read the
release notes before upgrading if `os_recency` is active: a raised floor can lock out devices that
were passing yesterday.

## Custom policies

For anything the built-ins do not cover, write a CEL
([Common Expression Language](https://github.com/google/cel-spec)) expression. It must evaluate to
a boolean, where `true` means the device passes.

```javascript
// Require BitLocker specifically, not just any disk encryption
posture.disk_encryption_technology == "BitLocker"

// Require a recent Ubuntu
posture.os_distribution == "ubuntu" && semver(posture.os_version) >= semver("22.04.0")

// Screen lock must engage within five minutes
posture.screen_lock_enabled == true && posture.screen_lock_idle_timeout_secs <= 300

// Require both an EDR agent and MDM enrollment
size(posture.edr) > 0 && size(posture.mdm) > 0

// Apply a rule only on macOS, passing every other platform
posture.os != "macos" || posture.sip_enabled == true
```

That last pattern matters: attributes are populated per platform, so an unqualified rule applies
everywhere. Guard on `posture.os` when a requirement is platform-specific.

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

`screen_lock_idle_timeout_secs`, `uptime_secs`

**Lists** (default `[]`)

`edr`, `mdm`

### The `semver` function

Beyond standard CEL, Vouch provides `semver(string)` for version comparison. Use it rather than
comparing version strings directly — lexical comparison puts `"10.0.0"` before `"9.0.0"`.

```javascript
semver(posture.os_version) >= semver("14.0.0")
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

**A custom expression never passes.**
Runtime errors and non-boolean results both count as failures. Test it in the policy editor against
known-good sample posture.
