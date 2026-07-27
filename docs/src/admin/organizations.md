# Organizations and Administrators

Vouch groups users into organizations, and administration happens per organization. This chapter
covers where organizations come from, how the first administrator is created, and what an
administrator can do.

## Organizations are created automatically

There is no "create organization" step, no command, and no admin screen for it. An organization is
created the first time somebody enrolls from a given email domain: the server derives the domain
from the verified email its identity provider returned, looks for an organization owning that
domain, and creates one if none exists.

The consequence worth internalizing: **your organization comes into existence when your first user
enrolls, not when you install the server.** A freshly started server has no organizations, no
users, and no administrators, and there is nothing you can usefully click until somebody enrolls.

Users whose identity provider returns no hosted-domain information enroll without an organization.
They can log in and receive credentials normally, but they are not part of any organization and
cannot be managed through SCIM.

## The first enrollee becomes the administrator

The first user to enroll from a domain is made that organization's administrator automatically, as
part of the same transaction that creates their account. If several people enroll simultaneously,
they race on a compare-and-swap against the organization record — exactly one wins and becomes
administrator; the others enroll as ordinary members.

There is no bootstrap token, no `VOUCH_ADMIN_EMAILS` setting, and no way to designate the first
administrator ahead of time.

> **Plan the first enrollment.** Whoever enrolls first from your domain holds the only
> administrator account, and every subsequent administrator is promoted by an existing one. Enroll
> deliberately — ideally the person who will own the deployment — rather than letting an
> arbitrary early user claim it.

Restrict who can enroll at all with `VOUCH_ALLOWED_DOMAINS`. When it is unset, enrollment is open
to any email domain your identity provider will authenticate, which the server records in its
startup log as open enrollment.

## Administration is per-organization

An administrator administers **their own organization and nothing else**. There is no global
administrator, no super-user, and no cross-organization console anywhere in the product. An
administrator attempting to act on a user in another organization is rejected.

Administrators also cannot act on themselves: promote, demote, deactivate, and remove all refuse
when the target is the acting administrator. This prevents an organization from locking itself out
by demoting or deleting its only administrator.

## Accessing the admin UI

The admin pages live under `/admin` and require a signed-in session belonging to a user who is
both active and an administrator. Sign in at your server's login page and go to `/admin`.

The same actions are available programmatically under `/api/v1/org/*` using a Bearer access token
from a regular FIDO2 session — this is what the [SCIM](scim.md) chapter uses.

| Page | Path | Covered in |
|------|------|-----------|
| Members | `/admin` | This page |
| Audit log | `/admin/audit` | [Audit Events](audit.md) |
| Posture policies | `/admin/policies` | [Posture Policies](policies.md) |
| SCIM tokens | `/admin/scim-tokens` | [SCIM Provisioning](scim.md) |
| Email domains | `/admin/domains` | [Email Domains](domains.md) |

## Member actions

All of these are on the Members page, and every one writes an audit event.

| Action | Effect |
|--------|--------|
| **Promote** | Grants administrator rights. Audited as `admin_promote`. |
| **Demote** | Removes administrator rights; the account otherwise keeps working. Audited as `admin_demote`. |
| **Deactivate** | Marks the account inactive, deletes all of its sessions, revokes all of its SSH certificates, and clears any stored GitHub refresh token. Enrolled authenticators are kept, so reactivating restores access without re-enrollment. Audited as `admin_deactivate`. |
| **Activate** | Reverses a deactivation. The user must sign in again — deactivation already destroyed their sessions. Audited as `admin_activate`. |
| **Revoke credentials** | Deletes every enrolled authenticator, deletes all sessions, revokes all SSH certificates, and clears the GitHub refresh token — but keeps the account. The user must enroll a hardware key again before they can log in. Audited as `admin_revoke_credentials`. |
| **Remove** | Revokes the user's SSH certificates and then deletes the user record, cascading to their authenticators. Audited as `admin_remove_user`. |

### Choosing between them

- **Someone lost their YubiKey** → *Revoke credentials*. It clears the enrolled authenticators so
  they can enroll a replacement, without deleting the account or its history.
- **Someone is on leave, or you are responding to a suspected compromise** → *Deactivate*. It cuts
  off access immediately and is reversible, because their authenticators survive.
- **Someone has left the organization** → *Remove*, or let SCIM de-provisioning do it for you. See
  [SCIM Provisioning](scim.md), which performs the equivalent automatically when your IdP deletes
  the user.

All three revoke live sessions immediately. None of them wait for token expiry.

## What administrators cannot do

- Create organizations, or move a user between organizations
- Create users — enrollment is always initiated by the user with their hardware key present
- Recover or export any private key material
- Administer another organization
- Change server configuration — that is environment variables or the S3 document, and requires a
  restart. See [Configuration Sources](../configuration/sources.md).
