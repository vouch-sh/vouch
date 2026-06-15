# Vouch server UI — English (en-US) source strings.
#
# Message ids use kebab-case `area-element`. Fluent ids disallow dots
# (dots denote attributes). Placeables `{ $name }` are filled from Rust via
# I18nContext::ta / t1 / t2.
#
# This is the source-of-truth catalog for BOTH server-rendered templates and
# the strings injected into static JS (see templates' `js_i18n` blocks).

## Common / layout
common-app-name = vouch
common-copy = Copy
common-save = Save
common-cancel = Cancel
common-edit = Edit
common-delete = Delete
common-or = or
common-client-id = Client ID
common-client-secret = Client Secret

## Application created (applications/created.html)
apps-created-page-title = Application Created - Vouch
apps-created-heading = Application Created
apps-created-save-creds = Save Your Credentials
apps-created-secret-once = The client secret will only be shown once. Store it securely.
apps-created-pkce = This application uses PKCE for security. No client secret required.
apps-created-view-all = View All Applications

## Application error / unauthorized / secret added
apps-error-go-back = Go Back
apps-unauth-page-title = Unauthorized - Vouch
apps-unauth-heading = Sign In Required
apps-unauth-body = You need to be signed in to manage applications.
apps-unauth-signin = Sign In
apps-secret-page-title = Secret Added - Vouch
apps-secret-heading = Secret Added
apps-secret-save = Save Your New Secret
apps-secret-once = This secret will only be shown once. Copy it now and store it securely.
apps-secret-new-label = New Client Secret
apps-secret-back-to = Back to

## Application detail (applications/detail.html)
apps-detail-back = Back to Applications
apps-detail-delete-confirm = Are you sure you want to delete this application? This action cannot be undone.
apps-detail-access-scope = Access Scope
apps-detail-auth-method = Auth Method
apps-detail-fapi-badge = FAPI 2.0
apps-detail-fapi-desc = PAR + DPoP + private_key_jwt
apps-detail-description = Description
apps-detail-created = Created
apps-detail-client-keys = Client Keys
apps-detail-inline-jwks = Inline JWKS
apps-detail-no-redirect = No redirect URIs configured
apps-detail-resource-uris = Resource URIs
apps-detail-client-secrets = Client Secrets
apps-detail-secrets-suffix = of 2 active
apps-detail-add-secret = Add Secret
apps-detail-no-secrets = No secrets configured.
apps-detail-secret-default = Secret
apps-detail-secret-active = active
apps-detail-secret-revoked = revoked
apps-detail-revoke = Revoke
apps-detail-revoke-confirm = Revoke this secret? It will no longer be accepted for authentication.
apps-detail-usage-stats = Usage Statistics
apps-detail-name = Name
apps-detail-one-uri = One URI per line
apps-detail-resource-help = One URI per line. Target resource servers for audience-restricted tokens (RFC 8707).
apps-detail-standard-desc = Client secret authentication.
apps-detail-fapi-short-desc = PAR + DPoP + private_key_jwt.
apps-detail-save-changes = Save Changes

## Application create form (applications/create.html)
apps-create-page-title = New Application - Vouch
apps-create-heading = Register New Application
apps-create-subtitle = Create an OAuth application to integrate with Vouch.
apps-create-name-label = Application Name
apps-create-name-placeholder = My Application
apps-create-name-help = A friendly name for your application.
apps-create-desc-label = Description (optional)
apps-create-desc-placeholder = Brief description of your application
apps-create-type-label = Application Type
apps-create-type-web = Web Application
apps-create-type-web-desc = Server-side app with secure backend. Uses client secret.
apps-create-type-spa = Single Page Application
apps-create-type-spa-desc = Browser-only app. Uses PKCE, no client secret.
apps-create-type-native = Native Application
apps-create-type-native-desc = Desktop or mobile app. Uses PKCE, no client secret.
apps-create-type-service = Service / Machine-to-Machine
apps-create-type-service-desc = Backend service with no user interaction. Uses client credentials.
apps-create-redirect-label = Redirect URIs
apps-create-redirect-help = One URI per line. Where users are redirected after authentication.
apps-create-resource-label = Resource URIs (optional)
apps-create-resource-help = One URI per line. Target resource servers that will receive access tokens (RFC 8707). Leave empty to allow any resource.
apps-create-secprofile-label = Security Profile
apps-create-secprofile-standard = Standard OAuth 2.0
apps-create-secprofile-standard-desc = Standard OAuth 2.0 with client secret authentication.
apps-create-secprofile-fapi = FAPI 2.0 Security Profile
apps-create-secprofile-fapi-desc = Enforces PAR, DPoP, and private_key_jwt. No client secret — authentication uses signed JWTs.
apps-create-fapi-jwks-info = FAPI 2.0 clients authenticate using signed JWTs instead of a client secret. Provide your public keys as a JWKS (inline JSON) or a JWKS URI endpoint.
apps-create-jwks-label = JWKS (inline JSON)
apps-create-jwks-help = JSON Web Key Set containing your public signing keys.
apps-create-jwks-uri-label = JWKS URI
apps-create-jwks-uri-help = HTTPS endpoint serving your JWKS.
apps-create-access-label = Who can use this application?
apps-create-access-org = Organization members only
apps-create-access-org-desc = Only users in your organization can authenticate with this app.
apps-create-access-personal = Only me
apps-create-access-personal-desc = Only you can authenticate with this app. Good for personal tools.
apps-create-access-public = Any Vouch user
apps-create-access-public-desc = Any authenticated Vouch user can use this app.

## Applications list (applications/list.html)
apps-list-page-title = My Applications - Vouch
apps-list-heading = My Applications
apps-list-new = New Application
apps-list-empty-heading = No applications yet
apps-list-empty-body = Build internal tools that authenticate users via YubiKey.
apps-list-empty-detail = Register an OAuth application to get a client ID and secret, then integrate using standard OAuth 2.0 / OIDC flows.
apps-list-create = Create Application
apps-list-th-name = Name
apps-list-th-type = Type
apps-list-th-scope = Scope
apps-list-th-status = Status
apps-list-th-last-used = Last Used
apps-list-th-actions = Actions
apps-list-status-active = Active
apps-list-status-inactive = Inactive
apps-list-never = Never
apps-list-delete-confirm = Are you sure you want to delete this application?

## Security keys management (enroll_keys.html, enroll_keys_container.html)
enroll-keys-page-title = Vouch - Security Keys
enroll-keys-heading = Security Keys
enroll-keys-cli-guidance = You can also manage keys from the command line:
enroll-keys-empty = No security keys registered yet.
enroll-keys-register-first = Register Your First Security Key
enroll-keys-rename-aria = Rename key
enroll-keys-added-prefix = Added
enroll-keys-delete-title = Delete key
enroll-keys-add-another = + Add Another Security Key

## Landing / home (landing.html)
home-page-title = Vouch - { $org }
home-welcome = Welcome to Vouch
home-tagline = { $org }'s hardware-backed authentication system
home-subtagline = Login once with your YubiKey. SSH, AWS, and Git work for 8 hours.
home-manage-keys = Manage Security Keys
home-no-browser-signin = Browser sign-in is not configured. Use the CLI enrollment command below.
home-sign-in-with = Sign in with { $provider }
home-register-hint = Register your security key using your work email
home-or-cli = or use the CLI
home-enroll-cli-label = Enroll via Command Line
home-download-label = Download the CLI
home-already-enrolled = Already Enrolled?
home-feature-hardware = Hardware-backed authentication
home-feature-shortlived = Short-lived credentials
home-feature-phishing = Phishing-resistant

## Login (login.html)
login-page-title = Vouch - Sign In
login-title = Sign In
login-continue-prefix = Sign in to continue to
login-touch-prompt = Touch your security key to sign in
login-status-insert = Insert your security key and touch it when it blinks.
login-button = Sign In with Security Key
login-privacy-policy = Privacy Policy
login-terms = Terms of Service
login-no-account-prefix = Don't have an account?
login-enroll-now = Enroll now
login-cert-test-login = Certification Test Login
login-cert-test-deny = Certification Test Deny

## Generic error page (error.html)
error-page-title = Vouch - Error
error-back = Back

## Enrollment success (success.html)
success-page-title = Vouch - Success
success-heading = Enrollment Complete
success-body = You can close this window and return to your terminal.
success-next-label = Next in your terminal
success-cmd-ssh = # SSH certificates
success-cmd-aws = # AWS credentials
success-cmd-github = # GitHub tokens

## Device verification (device_verify.html)
device-page-title = Vouch - Device Verification
device-heading = Enter Your Code
device-body = Enter the code shown in your terminal to continue.
device-continue = Continue

## Identity provider chooser (select_idp.html)
select-idp-page-title = Vouch - Choose Identity Provider
select-idp-heading = Choose your identity provider
select-idp-body = Sign in with the identity provider your organization uses.

## OAuth authorize / consent (authorize.html)
authorize-page-title = Sign in - Vouch
authorize-heading = Sign in to continue
authorize-subtitle = Hardware authentication required
authorize-wants-access = wants to access your Vouch identity
authorize-org-app-for = This is an organizational application for
authorize-org-app = This is an organizational application
authorize-use-cli = Use the Vouch CLI to authenticate:
authorize-refresh = Then refresh this page.

## OAuth access denied (authorize_denied.html)
authorize-denied-page-title = Access Denied - Vouch
authorize-denied-heading = Access Denied
authorize-denied-subtitle = You cannot use this application
authorize-denied-restricted-suffix = has restricted access.
authorize-denied-contact = If you believe you should have access, contact the application owner.

## GitHub connect result pages (github/success.html, github/error.html)
github-success-page-title = Vouch - GitHub Connected
github-success-heading = GitHub Connected
github-success-connected-prefix = Successfully connected to
github-success-next-steps = Next steps for your team:
github-success-step1 = 1. Configure Git to use Vouch:
github-success-step2 = 2. Test with any repository:
github-success-close = You can close this window.
github-error-try-again = Try Again

## GitHub connect page (github/connect.html)
github-connect-page-title = Vouch - Connect GitHub
github-connect-heading = Connect GitHub
github-connect-subtitle = Connect your organization's GitHub account to enable Git credential issuance.
github-connect-link-heading = Link Your GitHub Account
github-connect-link-body = To reconnect existing GitHub installations, link your GitHub account to verify your access.
github-connect-link-button = Link GitHub Account
github-connect-reconnect-heading = Reconnect Existing Installations
github-connect-reconnect-body = These GitHub accounts have the Vouch app installed and you have access to reconnect them:
github-connect-linked-as = Linked as
github-connect-connected-heading = Connected GitHub accounts:
github-connect-connected-more = You can connect additional GitHub organizations below.
github-connect-next-heading = What happens next:
github-connect-step1 = You'll be redirected to GitHub to install the Vouch App
github-connect-step2 = Select which repositories Vouch can access
github-connect-step3-prefix = Team members can then use
github-connect-step3-suffix = to configure their machines
github-connect-perms-heading = Permissions requested:
github-connect-perm-contents = Repository contents (read/write)
github-connect-perm-metadata = Repository metadata (read)
github-connect-button = Connect GitHub
github-connect-button-another = Connect Another GitHub Account

## Install / developer setup (install.html)
install-page-title = Developer Setup - Vouch
install-heading = Get Started with Vouch
install-subtitle = Install the CLI and enroll your YubiKey
install-prereqs-label = Prerequisites
install-prereq-key = FIDO2 security key (YubiKey 5 series recommended)
install-prereq-server-prefix = Server URL from your admin (or use
install-step1-title = Install the CLI
install-win-limited-title = Limited Windows Support
install-win-limited-body = The Vouch agent and SSH integration are not available on Windows. Only basic authentication and credential exchange are supported.
install-win-download-prefix = Download the Windows binary from the
install-win-releases-link = releases page
install-win-download-mid = , extract the zip file, and add
install-win-download-suffix = to a directory in your PATH.
install-win-supported-label = Supported:
install-download-directly = Or download directly:
install-step2-title = Enroll your YubiKey
install-step2-body = This opens a browser to verify your identity and register your YubiKey.
install-step3-title = Daily login
install-step3-body = After login, your identity is available to SSH, AWS, Git, and other tools automatically.

## Integrations (integrations.html)
integrations-page-title = Vouch - Integrations
integrations-heading = Integrations
integrations-subtitle = Manage server-configured integrations.
integrations-badge-org-wide = Organization-wide
integrations-badge-per-user = Per-user
integrations-github-desc = Get short-lived GitHub access tokens for Git operations.
integrations-github-not-configured = GitHub App not configured on this server.
integrations-github-requires-prefix = Requires
integrations-github-requires-suffix = environment variables.
integrations-requires-org = Requires organization membership.
integrations-no-accounts = No accounts connected
integrations-connect = Connect
integrations-ask-admin = Ask an org admin
integrations-connected = Connected:
integrations-manage = Manage
integrations-ssh-title = SSH Certificates
integrations-ssh-desc = Get short-lived SSH certificates signed by Vouch's CA.
integrations-ssh-get-cert = Get a certificate:
integrations-ssh-capub-prefix = CA public key (add to
integrations-ssh-capub-suffix = on your servers):
integrations-ssh-not-configured = SSH CA not configured on this server.
integrations-ssh-set-prefix = Set
integrations-ssh-set-mid = to enable. See the
integrations-ssh-guide-link = key management guide
integrations-more-prefix = Looking for AWS, EKS, Docker, or other integrations? See the
integrations-setup-guide-link = setup guide

## Client-side JS strings (injected via the #vouch-i18n JSON data block)
common-js-copied = Copied!
webauthn-err-notallowed = Operation was cancelled or timed out. Please try again.
webauthn-err-security = Security error. Please ensure you are on a secure (HTTPS) connection.
webauthn-err-abort = Operation was cancelled.
webauthn-err-invalidstate = This security key is already registered or no credentials found.
webauthn-err-notsupported = This security key is not supported. Please use a FIDO2-compatible key.
webauthn-err-pin = PIN error. Please check your security key PIN and try again.
login-js-touch = Touch your security key when it blinks...
login-js-start-failed = Failed to start authentication
login-js-waiting = Waiting for security key...
login-js-complete-failed = Failed to complete authentication
login-js-success-redirect = Success! Redirecting...
login-js-signed-in = Signed in successfully!
login-js-error-prefix = Error:{" "}
keys-js-delete-prefix = Delete key "
keys-js-delete-suffix = "? This action cannot be undone.
keys-js-delete-failed = Failed to delete key
keys-js-delete-failed-reauth = Failed to delete key after re-authentication
keys-js-delete-failed-prefix = Failed to delete key:{" "}
keys-js-stepup-1 = Deleting a key requires recent authentication.
keys-js-stepup-2 = Please touch your security key when prompted.
keys-js-reauth-start-failed = Failed to start re-authentication
keys-js-reauth-complete-failed = Failed to complete re-authentication
keys-js-reg-starting = Starting registration...
keys-js-reg-start-failed = Failed to start registration
keys-js-reg-touch = Touch your security key...
keys-js-reg-completing = Completing registration...
keys-js-reg-complete-failed = Failed to complete registration

## Application form validation — client-side JS (app-create.js, app-detail.js)
appcreate-js-redirect-required = At least one redirect URI is required.
appcreate-js-redirect-invalid-prefix = Invalid redirect URI(s):{" "}
appcreate-js-redirect-invalid-suffix = . Each URI must be a valid http:// or https:// URL.
appcreate-js-resource-toolong = ... (exceeds maximum length of 2048)
appcreate-js-resource-fragment = {" "}(must not contain a fragment)
appcreate-js-resource-scheme = {" "}(must be an absolute URI with a scheme)
appcreate-js-resource-invalid-prefix = Invalid resource URI(s):{" "}
appcreate-js-jwks-keys = JWKS must be a JSON object with a non-empty "keys" array.
appcreate-js-jwks-json = JWKS must be valid JSON.
appcreate-js-jwksuri-https = JWKS URI must use https://.
appcreate-js-jwksuri-invalid = JWKS URI must be a valid https:// URL.
appcreate-js-fapi-required = FAPI 2.0 requires either a JWKS or JWKS URI.

## Authenticated header navigation (macros/auth.html)
nav-keys = Keys
nav-apps = Apps
nav-integrations = Integrations
nav-admin = Admin
nav-sign-out = Sign out

## Admin section nav + shared (admin/*.html)
admin-nav-members = Members
admin-nav-audit = Audit Log
admin-nav-policies = Policies
admin-nav-scim = SCIM Tokens
admin-nav-domains = Email Domains
admin-next-page = Next page

## Admin members (admin/members.html)
admin-members-page-title = Vouch - Organization Members
admin-members-heading = Organization Members
admin-members-subtitle = Manage members, roles, and credentials.
admin-members-th-email = Email
admin-members-th-role = Role
admin-members-th-keys = Keys
admin-members-you = (you)
admin-members-role-admin = Admin
admin-members-role-member = Member
admin-members-btn-demote = Demote
admin-members-btn-promote = Promote
admin-members-btn-deactivate = Deactivate
admin-members-btn-activate = Activate
admin-members-btn-revoke = Revoke Keys
admin-members-btn-remove = Remove
admin-members-title-demote = Demote to member
admin-members-title-promote = Promote to admin
admin-members-title-deactivate = Deactivate user
admin-members-title-activate = Reactivate user
admin-members-title-revoke = Revoke all credentials
admin-members-title-remove = Remove from organization
admin-members-confirm-demote = Demote this user from admin?
admin-members-confirm-deactivate = Deactivate this user? Their sessions will be invalidated.
admin-members-confirm-revoke = Revoke all credentials for this user? This will delete their key(s) and invalidate all sessions. The user will need to re-enroll.
admin-members-confirm-remove = Remove this user from the organization? This permanently deletes the user and all their data.
admin-members-none = No members found.

## Admin audit log (admin/audit.html)
admin-audit-page-title = Vouch - Audit Log
admin-audit-subtitle = Security events for your organization.
admin-audit-filter-label = Filter:
admin-audit-filter-all = All
admin-audit-filter-logins = Logins
admin-audit-filter-promotions = Promotions
admin-audit-filter-demotions = Demotions
admin-audit-filter-deactivations = Deactivations
admin-audit-filter-removals = Removals
admin-audit-filter-revocations = Revocations
admin-audit-th-time = Time
admin-audit-th-ip = IP
admin-audit-th-event = Event
admin-audit-th-domain = Domain
admin-audit-th-details = Details
admin-audit-none = No audit events found.
admin-audit-older = Older events

## Admin email domains (admin/domains.html)
admin-domains-page-title = Vouch - Email Domains
admin-domains-subtitle = Manage which email domains attach signing-in users to this organization.
admin-domains-max-prefix = Maximum of
admin-domains-max-suffix = additional domains reached. Remove an existing entry before adding a new one.
admin-domains-add = Add Domain
admin-domains-domain-label = Domain (e.g. acme.co.uk)
admin-domains-add-help = After adding, publish a TXT record to verify ownership. Only verified domains attach new users to this organization.
admin-domains-th-domain = Domain
admin-domains-th-added = Added
admin-domains-th-added-by = Added by
admin-domains-idn-title = Decoded Unicode form of the IDN domain
admin-domains-status-primary = Primary
admin-domains-status-verified = Verified
admin-domains-status-unverified = Unverified
admin-domains-status-pending = Pending
admin-domains-verify = Verify
admin-domains-remove-confirm = Remove this domain? Existing users from it stay in the org, but new logins from this domain will no longer attach.
admin-domains-txt-prefix = Publish this TXT record on
admin-domains-txt-mid = , then click
admin-domains-dns-name = Name:
admin-domains-dns-type = Type:
admin-domains-dns-value = Value:
admin-domains-copy-token-title = Copy verification token
admin-domains-warning = Adding a domain claims it for this organization. Anyone with a verified email in a claimed domain who signs in will be attached as a member. Only verified domains participate in login matching; pending entries do not.

## Admin device posture policies (admin/policies.html)
admin-policies-page-title = Vouch - Device Posture Policies
admin-policies-heading = Device Posture Policies
admin-policies-subtitle = Enforce device security requirements for authentication. All active policies must pass.
admin-policies-builtin = Built-in Policies
admin-policies-on = On
admin-policies-off = Off
admin-policies-title-disable = Click to disable
admin-policies-title-enable = Click to enable
admin-policies-disk-macos = FileVault full-disk encryption
admin-policies-disk-windows = BitLocker drive encryption
admin-policies-disk-linux = LUKS/dm-crypt volume encryption
admin-policies-firewall-macos = Application Firewall (socketfilterfw)
admin-policies-firewall-windows = Windows Defender Firewall
admin-policies-firewall-linux = iptables, nftables, or ufw
admin-policies-screenlock-macos = Screen saver with password on wake
admin-policies-screenlock-windows = Lock screen on idle timeout
admin-policies-screenlock-linux = Screen locker configured
admin-policies-endpoint-desc = At least one EDR agent detected (CrowdStrike, SentinelOne, Carbon Black, etc.)
admin-policies-platform-macos = Secure Boot via Apple Silicon or T2 chip
admin-policies-platform-windows = UEFI Secure Boot enabled
admin-policies-platform-linux = UEFI Secure Boot enabled
admin-policies-osrecency-linux = Not checked — use a custom policy per distro
admin-policies-semver-explain = converts versions to numbers for correct comparison
admin-policies-custom = Custom Policies
admin-policies-new-btn = + New
admin-policies-playground-title = New Custom Policy
admin-policies-name-placeholder = e.g., Require macOS Sequoia
admin-policies-optional = (optional)
admin-policies-desc-placeholder = e.g., Require macOS 15 or later
admin-policies-rule-label = Rule
admin-policies-rule-hint = — must evaluate to true
admin-policies-cel-ref-title = CEL language reference
admin-policies-cel-valid = Valid expression
admin-policies-delete-confirm = Delete this custom policy?
admin-policies-none = No custom policies yet.
admin-policies-fieldref-summary = Field reference & test device
admin-policies-fieldref-th-field = Field
admin-policies-fieldref-th-test = Test value
admin-policies-example-rules = Example rules:
admin-policies-note-label = Note:
admin-policies-note-body = Posture data is self-reported by the CLI. Policies are a compliance baseline, not a cryptographic guarantee.

## Admin policies — client-side JS (admin.js, policies page)
admin-js-edit-policy-title = Edit Custom Policy
admin-js-cel-passes = — passes against test device
admin-js-cel-fails = — fails against test device
admin-js-cel-invalid = Invalid expression

## Admin SCIM tokens (admin/scim_tokens.html)
admin-scim-page-title = Vouch - SCIM Tokens
admin-scim-subtitle = Manage SCIM provisioning tokens for your identity provider.
admin-scim-new-created = New SCIM token created. Copy it now — it won't be shown again.
admin-scim-max = Maximum of 2 SCIM tokens reached. Revoke an existing token before creating a new one.
admin-scim-create = Create Token
admin-scim-desc-placeholder = e.g. Okta SCIM integration
admin-scim-expires-in = Expires in
admin-scim-days-30 = 30 days
admin-scim-days-90 = 90 days
admin-scim-days-180 = 180 days
admin-scim-days-365 = 365 days
admin-scim-th-expires = Expires
admin-scim-revoke-confirm = Revoke this SCIM token? Any integration using it will stop working.
admin-scim-none = No SCIM tokens. Create one to enable identity provider provisioning.
admin-scim-warning = SCIM tokens grant full read/write access to user provisioning. A maximum of 2 tokens is allowed to support key rotation while limiting exposure.
footer-install = Install
footer-docs = Docs
footer-privacy = Privacy
footer-terms = Terms
footer-status = Status
footer-version = v{ $version }
footer-copyright = Copyright { $year }
