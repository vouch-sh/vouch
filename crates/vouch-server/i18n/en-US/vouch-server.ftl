# Vouch server UI — English (en-US) source strings.
#
# Message ids use kebab-case `area-element`. Fluent ids disallow dots
# (dots denote attributes). Placeables `{ $name }` are filled from Rust via
# I18nContext::ta / t1 / t2.
#
# This is the source-of-truth catalog for BOTH server-rendered templates and
# the strings injected into static JS (see templates' `js_i18n` blocks).
#
# do-not-translate: some user-visible text is intentionally NOT in this catalog
# because it is code, not prose — shell commands, policy examples, JSON
# and URI placeholders, and proper nouns (OS names like macOS / Debian / Ubuntu).
# Those stay verbatim in the templates so they read identically in every locale.
#
# ---------------------------------------------------------------------------
# Terms (Fluent feature: https://projectfluent.org/fluent/guide/terms.html)
#   - Reusable nouns referenced as `{ -term-name }` from any message.
#   - Names match `crates/vouch-cli/i18n/en-US/vouch-cli.ftl` where they
#     overlap (`-product`, `-yubikey`, `-cmd`) so translators learn one
#     vocabulary across the CLI and server.
#   - Changing a term changes the rendered noun everywhere it's referenced.
# ---------------------------------------------------------------------------

-product = Vouch
-cmd = vouch
-yubikey = YubiKey
-security-key = security key
-fapi = FAPI 2.0
-github = GitHub
-ssh = SSH
-oauth = OAuth 2.0
-webauthn = WebAuthn
-jwks = JWKS

# Reusable noun phrase — appears verbatim in three help texts.
-one-uri-per-line = One URI per line.

## Common / layout
common-app-name = { -product }
common-copy = Copy
common-save = Save
common-cancel = Cancel
common-edit = Edit
common-delete = Delete
common-or = or
common-client-id = Client ID
common-client-secret = Client Secret

## Application created (applications/created.html)
apps-created-page-title = Application Created - { -product }
apps-created-heading = Application Created
apps-created-save-creds = Save Your Credentials
apps-created-secret-once = The client secret will only be shown once. Store it securely.
apps-created-pkce = This application uses PKCE for security. No client secret required.
apps-created-view-all = View All Applications

## Application error / unauthorized / secret added
apps-error-go-back = Go Back
# Error-page titles and messages, supplied by the applications web handlers
# (handlers/applications/web.rs) via `error_page(...)`.
apps-error-title-error = Error
apps-error-title-not-found = Not Found
apps-error-title-invalid-input = Invalid Input
apps-error-load-applications = Failed to load applications.
apps-error-org-scope-required = Organization scope requires organization membership.
apps-error-create-failed = Failed to create application.
apps-error-app-not-found = Application not found.
apps-error-load-application = Failed to load application.
apps-error-update-failed = Failed to update application.
apps-error-delete-failed = Failed to delete application.
apps-error-no-client-secrets = This application type does not use client secrets.
apps-error-fapi-no-secrets = FAPI clients using private_key_jwt do not use client secrets.
apps-error-secret-add-failed = Failed to add secret.
apps-error-secret-max = Maximum of 2 active secrets allowed.
apps-error-secret-not-found = Secret not found.
apps-error-secret-last-active = Cannot delete the last active secret.
apps-error-secret-delete-failed = Failed to delete secret.
apps-secret-page-title = Secret Added - { -product }
apps-secret-heading = Secret Added
apps-secret-save = Save Your New Secret
apps-secret-once = This secret will only be shown once. Copy it now and store it securely.
apps-secret-new-label = New Client Secret
# Merged from prior `apps-secret-back-to = Back to` + plain `{{ name }}`.
apps-secret-back-to = Back to { $name }

# Form validation failures, one per AppValidationError variant
# (handlers/applications/validate.rs::localized). These are the browser-facing
# half of each failure; the JSON API returns a separate ASCII English
# error_description for the same variant, because RFC 6749 §5.2 addresses that
# field to the client developer and restricts its character set.
#
# `$uris`, `$uri`, `$profile`, `$alg`, and `$kty` are echoed back from the
# submitted request and are not translated.
apps-invalid-name-required = An application name is required.
apps-invalid-application-type = Invalid application type. Choose web, native, spa, or service.
apps-invalid-access-scope = Invalid access scope. Choose personal, organization, or public.
apps-invalid-fapi-profile = Invalid FAPI profile "{ $profile }". Choose none or fapi2_security.
apps-invalid-redirect-uris-required = At least one redirect URI is required.
apps-invalid-redirect-uris = Invalid redirect URI(s): { $uris }. Each URI must use https://, or http:// with localhost, 127.0.0.1, or [::1], and must not contain a fragment. A custom scheme is accepted only for native applications.
apps-invalid-post-logout-redirect-uris = Invalid post-logout redirect URI(s): { $uris }. Each URI must be a valid http:// or https:// URL without a fragment.
apps-invalid-resource-uri = Invalid resource URI "{ $uri }": { $detail }. Resource URIs must be absolute URIs without a fragment.
apps-invalid-jwks-mutually-exclusive = Provide either a JWKS or a JWKS URI, not both.
apps-invalid-fapi-confidential-required = The FAPI 2.0 Security Profile requires a confidential application type: web or service.
apps-invalid-fapi-missing-jwks = FAPI 2.0 requires a JWKS or JWKS URI for private_key_jwt authentication.
apps-invalid-auth-method-missing-jwks = This application authenticates with a method that requires key material (private_key_jwt or self_signed_tls_client_auth), so it must keep a JWKS or JWKS URI. Provide one, or change its authentication method first.
apps-invalid-fapi-downgrade = A FAPI 2.0 application cannot be changed to a standard profile. Create a new standard application instead.
apps-invalid-fapi-jwks-algorithm = FAPI 2.0 requires a JWKS key usable with ES256, PS256, or EdDSA for client-assertion signing. None of the configured keys qualify: each either declares an algorithm outside that set, has a key type the signing-key matcher cannot select for those algorithms, or is marked for a non-signing use. Add a compatible key, or adjust an existing key's alg, kty, or use.
apps-invalid-request-object-jwks-algorithm = This application requires Request Objects signed with { $alg }, and none of the submitted keys can verify one. It needs a key of type { $kty } whose alg, if declared, is { $alg } and whose use, if declared, is sig. Add a compatible key, or adjust an existing key's alg, kty, or use.
apps-invalid-self-signed-jwks-x5c = This application authenticates with self_signed_tls_client_auth, whose certificate is carried in a JWKS key's x5c member. None of the configured keys carry one, so the application could never complete mTLS authentication. Add a key with an x5c certificate.
apps-invalid-jwks-not-json = The JWKS must be valid JSON.
apps-invalid-jwks-missing-keys = The JWKS must be a JSON object with a non-empty "keys" array.
apps-invalid-jwks-key-shape = The JWKS contains a key with an invalid field type — "alg" and "use", for example, must be strings.
apps-invalid-jwks-uri = The JWKS URI must be a valid https:// URL.

## Application detail (applications/detail.html)
apps-detail-back = Back to Applications
apps-detail-delete-confirm = Are you sure you want to delete this application? This action cannot be undone.
apps-detail-access-scope = Access Scope
apps-detail-auth-method = Auth Method
apps-detail-fapi-badge = { -fapi }
apps-detail-fapi-desc = PAR + DPoP + private_key_jwt
apps-detail-description = Description
apps-detail-created = Created
apps-detail-client-keys = Client Keys
apps-detail-inline-jwks = Inline { -jwks }
apps-detail-no-redirect = No redirect URIs configured
apps-detail-resource-uris = Resource URIs
apps-detail-client-secrets = Client Secrets
# Merged from prior `apps-detail-secrets-suffix = of 2 active`. The template
# wraps this in parens. `$count` is the active-secret count, `$max` is the
# limit (currently 2; kept as a placeable so a future limit change is a
# one-line code edit, no catalog change).
apps-detail-secrets-count = { $count } of { $max } active
apps-detail-add-secret = Add Secret
apps-detail-no-secrets = No secrets configured.
apps-detail-secret-default = Secret
apps-detail-secret-active = active
apps-detail-secret-revoked = revoked
apps-detail-revoke = Revoke
apps-detail-revoke-confirm = Revoke this secret? It will no longer be accepted for authentication.
apps-detail-usage-stats = Usage Statistics
apps-detail-name = Name
apps-detail-one-uri = { -one-uri-per-line }
apps-detail-resource-help = { -one-uri-per-line } Target resource servers for audience-restricted tokens (RFC 8707).
apps-detail-standard-desc = Client secret authentication.
apps-detail-fapi-short-desc = PAR + DPoP + private_key_jwt.
apps-detail-save-changes = Save Changes

## Application create form (applications/create.html)
apps-create-page-title = New Application - { -product }
apps-create-heading = Register New Application
apps-create-subtitle = Create an { -oauth } application to integrate with { -product }.
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
apps-create-redirect-help = { -one-uri-per-line } Where users are redirected after authentication.
apps-create-resource-label = Resource URIs (optional)
apps-create-resource-help = { -one-uri-per-line } Target resource servers that will receive access tokens (RFC 8707). Leave empty to allow any resource.
apps-create-postlogout-label = Post-Logout Redirect URIs (optional)
apps-create-postlogout-help = { -one-uri-per-line } Where users are redirected after signing out (RP-Initiated Logout 1.0). Must be https:// or loopback http://, no fragment.
apps-create-secprofile-label = Security Profile
apps-create-secprofile-standard = Standard { -oauth }
apps-create-secprofile-standard-desc = Standard { -oauth } with client secret authentication.
apps-create-secprofile-fapi = { -fapi } Security Profile
apps-create-secprofile-fapi-desc = Enforces PAR, DPoP, and private_key_jwt. No client secret — authentication uses signed JWTs.
apps-create-fapi-jwks-info = { -fapi } clients authenticate using signed JWTs instead of a client secret. Provide your public keys as a { -jwks } (inline JSON) or a { -jwks } URI endpoint.
apps-create-jwks-label = { -jwks } (inline JSON)
apps-create-jwks-help = JSON Web Key Set containing your public signing keys.
apps-create-jwks-uri-label = { -jwks } URI
apps-create-jwks-uri-help = HTTPS endpoint serving your { -jwks }.
apps-create-access-label = Who can use this application?
apps-create-access-org = Organization members only
apps-create-access-org-desc = Only users in your organization can authenticate with this app.
apps-create-access-personal = Only me
apps-create-access-personal-desc = Only you can authenticate with this app. Good for personal tools.
apps-create-access-public = Any { -product } user
apps-create-access-public-desc = Any authenticated { -product } user can use this app.

## Applications list (applications/list.html)
apps-list-page-title = My Applications - { -product }
apps-list-heading = My Applications
apps-list-new = New Application
apps-list-empty-heading = No applications yet
apps-list-empty-body = Build internal tools that authenticate users via { -yubikey }.
apps-list-empty-detail = Register an { -oauth } application to get a client ID and secret, then integrate using standard { -oauth } / OIDC flows.
apps-list-create = Create Application
apps-list-th-name = Name
apps-list-th-type = Type
apps-list-th-scope = Scope
apps-list-th-status = Status
apps-list-th-last-used = Last Used
apps-list-th-actions = Actions
# Status pill labels are kept as separate ids per the Fluent good-practices
# rule "Reserve Variants for Grammar/Style Only, Not UI Logic" — these are
# distinct UI states, not grammatical variants of one message.
apps-list-status-active = Active
apps-list-status-inactive = Inactive
apps-list-never = Never
apps-list-delete-confirm = Are you sure you want to delete this application?
# Application type pill (applications/list.html) and the type shown on the
# created confirmation (applications/created.html). Compact forms suit the
# table pill and are reused on the created page.
apps-type-web = Web
apps-type-spa = SPA
apps-type-native = Native
apps-type-service = Service
# Access scope pill plus its hover tooltip (applications/list.html). The display
# name and its description are one conceptual pair, kept together via a Fluent
# attribute (.desc) rather than as separate ids.
apps-scope-organization = Organization
    .desc = Only users in your organization can authenticate
apps-scope-personal = Personal
    .desc = Only you can authenticate
apps-scope-public = Public
    .desc = Any { -product } user can authenticate

## Security keys management (enroll_keys.html, enroll_keys_container.html)
enroll-keys-page-title = { -product } - { -security-key }s
enroll-keys-heading = Security Keys
enroll-keys-cli-guidance = You can also manage keys from the command line:
enroll-keys-empty = No security keys registered yet.
enroll-keys-register-first = Register Your First Security Key
# Fluent attribute pattern (https://projectfluent.org/fluent/guide/attributes.html):
# the value is the action verb; the .aria-label is what a screen reader announces.
enroll-keys-rename = Rename
    .aria-label = Rename key
# Merged from prior `enroll-keys-added-prefix = Added`. `$when` is a rendered
# timestamp from the template.
enroll-keys-added = Added { $when }
# Value is the action; .title is the tooltip a sighted user sees on hover.
enroll-keys-delete = Delete
    .title = Delete key
enroll-keys-add-another = + Add Another Security Key

## Landing / home (landing.html)
home-page-title = { -product } - { $org }
home-welcome = Welcome to { -product }
home-tagline = { $org }'s hardware-backed authentication system
home-subtagline = Login once with your { -yubikey }. { -ssh }, AWS, and Git work for 8 hours.
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
login-page-title = { -product } - Sign In
login-logo-alt = Application logo
login-title = Sign In
# DOCUMENTED FRAGMENT: paired with a `<span class="font-semibold ...">` styled
# client name in the template (login.html). Merging into a single message with
# a `{ $client }` placeable would lose the visual emphasis on the client name,
# which matters for an OAuth consent screen.
login-continue-prefix = Sign in to continue to
login-touch-prompt = Touch your { -security-key } to sign in
login-status-insert = Insert your { -security-key } and touch it when it blinks.
login-button = Sign In with { -security-key }
login-privacy-policy = Privacy Policy
login-terms = Terms of Service
# DOCUMENTED FRAGMENT: followed by an `<a>` link with the `login-enroll-now`
# text inside (login.html). Cannot merge without losing the link element.
login-no-account-prefix = Don't have an account?
login-enroll-now = Enroll now
login-cert-test-login = Certification Test Login
login-cert-test-deny = Certification Test Deny

## Generic error page (error.html)
error-page-title = { -product } - Error
error-heading = Error
error-back = Back

## Enrollment failures (error.html, rendered from handlers/enroll.rs)
enroll-error-device-auth-approve-failed = Failed to approve the sign-in request. Please run the command again.
enroll-error-session-create-failed = Failed to start enrollment. Please run the command again.
enroll-error-unknown-provider-title = Unknown Provider
enroll-error-unknown-provider = Identity provider '{ $slug }' is not configured.
enroll-error-not-configured-title = Not Configured
enroll-error-idp-not-configured = Identity provider is not configured. Please contact your administrator.
enroll-error-oidc-not-configured = OIDC not configured. If using SAML, responses should be sent to /saml/acs, not /oauth/callback.
enroll-error-auth-start-failed = Failed to start authentication
enroll-error-state-create-failed = Failed to create session state
enroll-error-missing-code = Missing authorization code
enroll-error-missing-state = Missing state parameter
enroll-error-invalid-state = Invalid state parameter
enroll-error-state-expired = Invalid or expired state
enroll-error-state-verify-failed = Failed to verify state

## Browser key management and WebAuthn errors.
##
## These reach the browser as the `message` field of a JSON error body, which
## keys.js and login.js alert verbatim, so they are page text rather than
## protocol text. The machine-readable `code` beside each one stays ASCII.
keys-error-invalid-id = Invalid key ID format
keys-error-name-empty = Name cannot be empty
keys-error-name-too-long = Name must be { $max } characters or less
keys-error-last-key = Cannot delete your last key. Register another key first.
keys-error-delete-conflict = Key deletion conflicted with a concurrent operation. Please try again.
keys-error-rename-failed =
    Could not rename key. Please choose a name between 1 and { $max } characters.
enroll-error-session-invalid = Invalid or expired session
enroll-error-session-lookup-failed = Failed to look up enrollment session
enroll-error-registration-link-used = This registration link has already been used
# { $detail } is the verifier's own diagnostic, passed through as written.
enroll-error-attestation-failed = Attestation verification failed: { $detail }
enroll-error-key-already-registered = This security key is already registered
enroll-error-key-serialize-failed = Failed to serialize key
enroll-error-invalid-session-hours = Invalid session hours
enroll-error-browser-session-create-failed = Failed to create session
enroll-error-render-failed = Failed to render template
login-error-invalid-user-handle = Invalid user handle format
login-error-session-expired = Authentication session expired
login-error-challenge-failed = Failed to generate challenge
login-error-time-overflow = Time calculation overflow
login-error-state-already-used = Authentication state has already been used
login-error-auth-failed = Authentication failed
login-error-device-auth-failed = Failed to complete CLI authorization
login-error-session-create-failed = Failed to create session
login-error-missing-origin = Origin header required
login-error-origin-mismatch = Request origin mismatch
enroll-error-auth-complete-failed = Failed to complete authentication
enroll-error-token-verify-failed = Failed to verify identity token
enroll-error-invalid-email = The identity provider returned an invalid email address. Please contact your administrator.
enroll-error-domain-not-allowed-title = Domain Not Allowed
enroll-error-domain-not-allowed = Only users from the following domains can enroll: { $domains }. Your email ({ $email }) is not from an allowed domain.
enroll-error-identity-conflict-title = Account Linking Blocked
enroll-error-identity-conflict = Your identity provider did not confirm the user identifier bound to this account. To protect the account, sign-in was refused. Please contact your administrator.
enroll-error-account-deactivated-title = Account Deactivated
enroll-error-account-deactivated = This account has been deactivated by your organization, so sign-in was refused. Please contact your administrator to restore access.
enroll-error-user-create-failed = Failed to create user
enroll-error-session-failed = Failed to create session
enroll-error-enrollment-start-failed = Failed to start enrollment. Please try again.

## Enrollment success (success.html)
success-page-title = { -product } - Success
success-heading = Enrollment Complete
success-body = You can close this window and return to your terminal.
success-next-label = Next in your terminal
success-cmd-ssh = # SSH certificates
success-cmd-aws = # AWS credentials
success-cmd-github = # GitHub tokens

## Device verification (device_verify.html)
device-page-title = { -product } - Device Verification
device-heading = Enter Your Code
device-body = Enter the code shown in your terminal to continue.
device-code-label = Device code
device-continue = Continue

## Identity provider chooser (select_idp.html)
select-idp-page-title = { -product } - Choose Identity Provider
select-idp-heading = Choose your identity provider
select-idp-body = Sign in with the identity provider your organization uses.

## OAuth authorize / consent (authorize.html)
authorize-page-title = Sign in - { -product }
authorize-heading = Sign in to continue
authorize-subtitle = Hardware authentication required
authorize-wants-access = wants to access your { -product } identity
authorize-org-app-for = This is an organizational application for
authorize-org-app = This is an organizational application
authorize-use-cli = Use the { -product } CLI to authenticate:
authorize-refresh = Then refresh this page.

## OAuth access denied (authorize_denied.html)
authorize-denied-page-title = Access Denied - { -product }
authorize-denied-heading = Access Denied
authorize-denied-subtitle = You cannot use this application
# DOCUMENTED FRAGMENT: preceded by `<strong>{{ client_name }}</strong>` in
# the template. Merging would lose the styled client name.
authorize-denied-restricted-suffix = has restricted access.
authorize-denied-contact = If you believe you should have access, contact the application owner.

# Reasons shown in the body of authorize_denied.html. Every construction of
# AuthorizeDeniedTemplate resolves one of these — the field is a `Tr`, so a
# bare string does not compile.
#
# The `$detail` placeable in four of them carries an OAuth error_description
# verbatim. That text is English by RFC 6749 §5.2 ("Human-readable ASCII
# [USASCII] text ... to assist the client developer") and is passed through
# untranslated on purpose; the sentence around it is what gets localized.
authorize-denied-redirect-uri-unregistered = Invalid redirect_uri: not registered for this application.
authorize-denied-redirect-uri-required = Invalid request: redirect_uri is required when multiple redirect URIs are registered.
authorize-denied-request-and-request-uri = Invalid request: the request and request_uri parameters are mutually exclusive.
authorize-denied-client-id-required = Invalid request: client_id is required.
authorize-denied-client-id-required-with-request = Invalid request: client_id is required with the request parameter.
authorize-denied-client-id-required-with-request-uri = Invalid request: client_id is required with request_uri.
authorize-denied-request-uri-format = Invalid request_uri format.
authorize-denied-request-uri-scheme = Invalid request_uri: must be a PAR URN or an HTTPS URL.
authorize-denied-request-uri-unregistered = Invalid request: request_uri is not registered for this client.
authorize-denied-request-uri-expired = Invalid or expired request_uri. Please restart the authorization flow.
authorize-denied-invalid-request-object = Invalid Request Object: { $detail }
authorize-denied-invalid-request-object-coded = Invalid Request Object ({ $code }): { $detail }
authorize-denied-request-object-fetch-failed = Failed to fetch Request Object: { $detail }
authorize-denied-invalid-request = Invalid request: { $detail }
authorize-denied-session-expired = Authorization session expired. Please try again.
authorize-denied-server-error = The authorization server could not complete the request. Please try again, or contact the application owner if this persists.
authorize-denied-unknown-client = Unknown client application. Please contact the application administrator.
authorize-denied-client-deactivated = This application has been deactivated.
authorize-denied-no-access = You don't have access to this application.
authorize-denied-access-denied-detail = { $detail }
authorize-denied-jarm-signing-failed = The authorization server could not produce a signed response. Please try again, or contact the application owner if this persists.
authorize-denied-generic = An error occurred. Please try again.

## GitHub connect result pages (github/success.html, github/error.html)
github-success-page-title = { -product } - { -github } Connected
github-success-heading = { -github } Connected
# DOCUMENTED FRAGMENT: followed by `<span class="text-gray-300 font-medium">`
# styled account name. Keep split to preserve the visual emphasis.
github-success-connected-prefix = Successfully connected to
github-success-next-steps = Next steps for your team:
github-success-step1 = 1. Configure Git to use { -product }:
github-success-step2 = 2. Test with any repository:
github-success-close = You can close this window.
github-error-try-again = Try Again

## GitHub connect page (github/connect.html)
github-connect-page-title = { -product } - Connect { -github }
github-connect-heading = Connect { -github }
github-connect-subtitle = Connect your organization's { -github } account to enable Git credential issuance.
github-connect-link-heading = Link Your { -github } Account
github-connect-link-body = To reconnect existing { -github } installations, link your { -github } account to verify your access.
github-connect-link-button = Link { -github } Account
github-connect-reconnect-heading = Reconnect Existing Installations
github-connect-reconnect-body = These { -github } accounts have the { -product } app installed and you have access to reconnect them:
github-connect-linked-as = Linked as
github-connect-connected-heading = Connected { -github } accounts:
github-connect-connected-more = You can connect additional { -github } organizations below.
github-connect-next-heading = What happens next:
github-connect-step1 = You'll be redirected to { -github } to install the { -product } App
github-connect-step2 = Select which repositories { -product } can access
# DOCUMENTED FRAGMENT: prefix + `<code>vouch setup github</code>` + suffix in
# the template (github/connect.html). The `<code>` styling on the command is
# load-bearing — keeping the command visually distinct from the surrounding
# instructions is the point of the line.
github-connect-step3-prefix = Team members can then use
github-connect-step3-suffix = to configure their machines
github-connect-perms-heading = Permissions requested:
github-connect-perm-contents = Repository contents (read/write)
github-connect-perm-metadata = Repository metadata (read)
github-connect-button = Connect { -github }
github-connect-button-another = Connect Another { -github } Account

## Install / developer setup (install.html)
install-page-title = Developer Setup - { -product }
install-heading = Get Started with { -product }
install-subtitle = Install the CLI and enroll your { -yubikey }
install-prereqs-label = Prerequisites
# Accessible name for the OS tab strip (role="tablist")
install-tabs-label = Operating system
install-prereq-key = FIDO2 { -security-key } ({ -yubikey } 5 series recommended)
# DOCUMENTED FRAGMENT: followed by `<code>{{ server_url }}</code>)` in the
# template — note the message ends with an open paren and the closing paren
# lives outside `<code>` in the HTML. Splitting preserves the `<code>` style
# on the server URL.
install-prereq-server-prefix = Server URL from your admin (or use
install-step1-title = Install the CLI
install-win-limited-title = Limited Windows Support
install-win-limited-body = The { -product } agent and SSH integration are not available on Windows. Only basic authentication and credential exchange are supported.
# DOCUMENTED FRAGMENT: prefix + `<a>` releases link + mid + `<code>vouch.exe</code>`
# + suffix in install.html. The link and the `<code>` for the binary name are
# load-bearing styling that can't move through a plain placeable.
install-win-download-prefix = Download the Windows binary from the
install-win-releases-link = releases page
install-win-download-mid = , extract the zip file, and add
install-win-download-suffix = to a directory in your PATH.
install-win-supported-label = Supported:
install-download-directly = Or download directly:
install-step2-title = Enroll your { -yubikey }
install-step2-body = This opens a browser to verify your identity and register your { -yubikey }.
install-step3-title = Daily login
install-step3-body = After login, your identity is available to SSH, AWS, Git, and other tools automatically.
# DOCUMENTED FRAGMENT: shell-comment annotations heading the apt/rpm code
# blocks (install.html). The commands themselves stay English as code; only
# these `#`-prefixed comment lines are prose. Shared across both package
# managers where the wording is identical.
install-comment-gpg = # Import GPG key
install-comment-add-repo = # Add repository
install-comment-install = # Install
# DOCUMENTED FRAGMENT: the step-3 simulated terminal session (install.html) is
# a stack of separately-styled <div>s interleaved with the untranslated
# `$ vouch login` command, so each translatable line is its own id.
install-step3-comment = # Start your day with a single touch
install-step3-prompt-pin = Enter PIN: ****
install-step3-prompt-touch = Touch your { -yubikey }...
install-step3-authenticated = ✓ Authenticated for 8 hours

## Integrations (integrations.html)
integrations-page-title = { -product } - Integrations
integrations-heading = Integrations
integrations-subtitle = Manage server-configured integrations.
integrations-badge-org-wide = Organization-wide
integrations-badge-per-user = Per-user
integrations-github-desc = Get short-lived { -github } access tokens for Git operations.
integrations-github-not-configured = { -github } App not configured on this server.
# DOCUMENTED FRAGMENT: prefix + `<code>VOUCH_GITHUB_APP_*</code>` + suffix in
# integrations.html. The `<code>` style on the env-var pattern is load-bearing.
integrations-github-requires-prefix = Requires
integrations-github-requires-suffix = environment variables.
integrations-requires-org = Requires organization membership.
integrations-no-accounts = No accounts connected
integrations-connect = Connect
integrations-ask-admin = Ask an org admin
integrations-connected = Connected:
integrations-manage = Manage
integrations-ssh-title = SSH Certificates
integrations-ssh-desc = Get short-lived SSH certificates signed by { -product }'s CA.
integrations-ssh-get-cert = Get a certificate:
# DOCUMENTED FRAGMENT: prefix + `<code>/etc/ssh/ca.pub</code>` + suffix in
# integrations.html. `<code>` on the path is load-bearing.
integrations-ssh-capub-prefix = CA public key (add to
integrations-ssh-capub-suffix = on your servers):
integrations-ssh-not-configured = SSH CA not configured on this server.
# DOCUMENTED FRAGMENT: prefix + `<code>VOUCH_SSH_CA_KEY</code>` + mid + `<a>`
# link + integrations-ssh-guide-link. Code + link styling is load-bearing.
integrations-ssh-set-prefix = Set
integrations-ssh-set-mid = to enable. See the
integrations-ssh-guide-link = key management guide
# DOCUMENTED FRAGMENT: prefix + `<a>` link with `integrations-setup-guide-link`
# text. Link element prevents merge.
integrations-more-prefix = Looking for AWS, EKS, Docker, or other integrations? See the
integrations-setup-guide-link = setup guide

## Client-side JS strings (injected via the /i18n.js script bundle)
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
login-js-error = Error: { $message }
keys-js-delete = Delete key "{ $name }"? This action cannot be undone.
keys-js-delete-failed = Failed to delete key
keys-js-delete-failed-reauth = Failed to delete key after re-authentication
keys-js-delete-failed-message = Failed to delete key: { $message }
# Single multiline message (newline preserved between lines) so translators see
# the full prompt as one block rather than two concatenated fragments.
keys-js-stepup =
    Deleting a key requires recent authentication.
    Please touch your { -security-key } when prompted.
keys-js-reauth-start-failed = Failed to start re-authentication
keys-js-reauth-complete-failed = Failed to complete re-authentication
keys-js-reg-starting = Starting registration...
keys-js-reg-start-failed = Failed to start registration
keys-js-reg-touch = Touch your security key...
keys-js-reg-completing = Completing registration...
keys-js-reg-complete-failed = Failed to complete registration

## Application form validation — client-side JS (app-create.js, app-detail.js)
appcreate-js-redirect-required = At least one redirect URI is required.
# Mirrors apps-invalid-redirect-uris, the server-side wording for the same
# rule. Keep the two in step: this is the message the form shows before
# submitting, and that one is what comes back if it submits anyway.
appcreate-js-redirect-invalid = Invalid redirect URI(s): { $uris }. Each URI must use https://, or http:// with localhost, 127.0.0.1, or [::1], and must not contain a fragment. A custom scheme is accepted only for native applications.
# Per-URI validation errors. Each takes the offending URI as a placeable so JS
# never concatenates strings around translated text — that pattern previously
# required a `{ " " }(reason)` leading-space hack in the catalog.
appcreate-js-resource-fragment-uri = { $uri } must not contain a fragment.
appcreate-js-resource-scheme-uri = { $uri } must be an absolute URI with a scheme.
appcreate-js-resource-toolong-uri = { $uri } exceeds the maximum length of 2048 characters.
appcreate-js-resource-invalid = Invalid resource URI(s): { $errors }.
appcreate-js-jwks-keys = { -jwks } must be a JSON object with a non-empty "keys" array.
appcreate-js-jwks-json = { -jwks } must be valid JSON.
appcreate-js-jwksuri-https = { -jwks } URI must use https://.
appcreate-js-jwksuri-invalid = { -jwks } URI must be a valid https:// URL.
appcreate-js-fapi-required = { -fapi } requires either a { -jwks } or { -jwks } URI.
appcreate-js-postlogout-invalid = Invalid post-logout redirect URI(s): { $uris }. Each must be a valid https:// or loopback http:// URL without a fragment.

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
admin-nav-scim = API Tokens
admin-nav-domains = Email Domains
admin-nav-subdomain = Issuer Subdomain
admin-next-page = Next page

## Admin members (admin/members.html)
#
# Each per-row action button uses the Fluent attribute pattern: the value is
# the visible button label, `.title` is the hover tooltip. Translators see
# the label and tooltip together (https://projectfluent.org/fluent/guide/attributes.html).
admin-members-page-title = { -product } - Organization Members
admin-members-heading = Organization Members
admin-members-subtitle = Manage members, roles, and credentials.
admin-members-th-email = Email
admin-members-th-role = Role
admin-members-th-keys = Keys
admin-members-you = (you)
admin-members-role-admin = Admin
admin-members-role-member = Member
admin-members-demote = Demote
    .title = Demote to member
admin-members-promote = Promote
    .title = Promote to admin
admin-members-deactivate = Deactivate
    .title = Deactivate user
admin-members-activate = Activate
    .title = Reactivate user
admin-members-revoke = Revoke Keys
    .title = Revoke all credentials
admin-members-remove = Remove
    .title = Remove from organization
admin-members-confirm-demote = Demote this user from admin?
admin-members-confirm-deactivate = Deactivate this user? Their sessions will be invalidated.
# CLDR plural selector (https://projectfluent.org/fluent/guide/selectors.html):
# `$count` is the number of registered keys on the target user (member.key_count).
admin-members-confirm-revoke = Revoke all credentials for this user? This will delete their { $count ->
        [one] key
       *[other] keys
    } and invalidate all sessions. The user will need to re-enroll.
admin-members-confirm-remove = Remove this user from the organization? This permanently deletes the user and all their data.
admin-members-none = No members found.

## Admin audit log (admin/audit.html)
admin-audit-page-title = { -product } - Audit Log
admin-audit-subtitle = Security events for your organization.
admin-audit-filter-label = Filter:
admin-audit-filter-all = All
admin-audit-filter-logins = Logins
admin-audit-filter-promotions = Promotions
admin-audit-filter-demotions = Demotions
admin-audit-filter-deactivations = Deactivations
admin-audit-filter-removals = Removals
admin-audit-filter-revocations = Revocations
admin-audit-filter-email-label = Email
admin-audit-filter-user-id-label = User ID
admin-audit-filter-since-label = Since (UTC)
admin-audit-filter-until-label = Until (UTC)
admin-audit-filter-apply = Apply
admin-audit-filter-clear = Clear filters
admin-audit-th-time = Time
admin-audit-th-ip = IP
admin-audit-th-event = Event
admin-audit-th-domain = Domain
admin-audit-th-target = Target
admin-audit-th-details = Details
admin-audit-none = No audit events found.
admin-audit-older = Older events

## Admin email domains (admin/domains.html)
admin-domains-page-title = { -product } - Email Domains
admin-domains-subtitle = Manage which email domains attach signing-in users to this organization.
# Merged from prior `admin-domains-max-prefix` + `admin-domains-max-suffix`.
# `$count` is the remaining additional-domain capacity.
admin-domains-max = Maximum of { $count } additional domains reached. Remove an existing entry before adding a new one.
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
# DOCUMENTED FRAGMENT: prefix + `<code>{{ row.domain }}</code>` + mid + `<em>`
# action verb. The styled domain + emphasized action verb in the middle
# prevent a single-message merge without losing styling.
admin-domains-txt-prefix = Publish this TXT record on
admin-domains-txt-mid = , then click
admin-domains-dns-name = Name:
admin-domains-dns-type = Type:
admin-domains-dns-value = Value:
admin-domains-copy-token-title = Copy verification token
admin-domains-warning = Adding a domain claims it for this organization. Anyone with a verified email in a claimed domain who signs in will be attached as a member. Only verified domains participate in login matching; pending entries do not.
# Appended to the remove-domain flash when the removal also auto-released
# the org's issuer subdomain (rendered in the poster's locale).
admin-domains-subdomain-auto-released = The issuer subdomain '{ $label }' was released because this domain backed it; delete any AWS IAM OIDC identity providers for that issuer host.
# Flash messages and error strings used by domain management POST handlers.
admin-domains-flash-add-pending = Added { $domain } as pending. Publish the TXT record shown below, then click Verify.
admin-domains-flash-verified = Verified domain { $domain }.
admin-domains-flash-removed = { $revoked ->
    [0] Removed { $domain }. No matching users had active sessions to revoke.
    [one] Removed { $domain }. Revoked sessions for 1 user; org membership is unchanged.
   *[other] Removed { $domain }. Revoked sessions for { $revoked } users; org membership is unchanged.
}
admin-domains-flash-removed-revoke-error = Removed { $domain }, but session revocation for matching users failed; check server logs and revoke manually.
admin-domains-error-not-found = Domain not found on this organization.
admin-domains-error-not-pending = This domain is not pending verification on this organization.
admin-domains-error-dns-lookup = DNS lookup failed. Check that the TXT record is published and try again.
admin-domains-error-txt-not-found = TXT record not found or token does not match. DNS changes may take a few minutes to propagate.
admin-domains-error-verified-by-other-org = Another organization verified this domain first. Remove the pending entry from this organization and contact support if you believe this is in error.
admin-domains-error-max-domains = This organization has reached the maximum number of additional domains.
admin-domains-error-primary-domain = This is already your organization's primary domain.
admin-domains-error-already-attached = This domain is already attached to your organization.
admin-domains-error-claimed-by-other-org = This domain is already claimed by another organization.
admin-domains-error-pending-other-org = This domain has a pending verification claim on another organization.
admin-domains-error-held-other-org = This domain is held by another organization; it must be removed or expire before your organization can claim it.
admin-domains-error-internal = Something went wrong; please try again.
admin-domains-invalid-empty = Enter a domain name, for example example.com.
admin-domains-invalid-ascii = Domain must be ASCII. For internationalized domains, enter the punycode form (for example xn--acme-cua.com).
admin-domains-invalid-ip = Enter a hostname like example.com, not an IP address.
admin-domains-invalid-too-long = Domain must be 253 characters or fewer.
admin-domains-invalid-no-dot = Enter a domain with at least one dot, for example example.com.
admin-domains-invalid-dot-edge = Domain must not start or end with a dot.
admin-domains-invalid-empty-label = Domain must not contain consecutive dots.
admin-domains-invalid-label-too-long = Each label in the domain must be 63 characters or fewer.
admin-domains-invalid-label-hyphen-edge = Domain labels must not start or end with a hyphen.
admin-domains-invalid-label-chars = Domain labels may only contain letters, digits, and hyphens.
admin-domains-invalid-reserved-tld = '.{ $tld }' is a reserved top-level label and cannot be used.

## Admin issuer subdomain (admin/subdomain.html)
admin-subdomain-page-title = { -product } - Issuer Subdomain
admin-subdomain-subtitle = Give this organization its own OIDC issuer host for AWS workload identity federation.
admin-subdomain-current-label = Claimed subdomain
admin-subdomain-issuer-label = Issuer URL
admin-subdomain-discovery-label = Discovery URL
admin-subdomain-copy-title = Copy URL
admin-subdomain-provider-hint = Create your AWS IAM OIDC identity provider with the issuer URL above; this issuer has its own signing keys, so role trust can be scoped to the provider ARN alone. If you later release this subdomain, delete the corresponding IAM OIDC provider.
admin-subdomain-claim = Claim Subdomain
admin-subdomain-label-select = Subdomain (based on your verified email domains)
admin-subdomain-claim-help = Claiming activates OIDC discovery on the subdomain and switches this organization's AWS federation tokens to the new issuer. Update your AWS IAM OIDC providers and role trust policies afterwards.
admin-subdomain-empty = No subdomains are available to claim yet. Subdomains come from your verified email domains — verifying acme.com lets you claim acme-com. Add and verify a domain under
# Shown when the org HAS verified domains but every candidate subdomain is
# unusable (e.g. an apex label longer than DNS allows).
admin-subdomain-empty-reserved = No subdomains are available to claim: { $count ->
        [one] the subdomain { $labels } from your verified domains cannot be used as an issuer subdomain
       *[other] the subdomains { $labels } from your verified domains cannot be used as issuer subdomains
    }. To use an issuer subdomain, add and verify another domain under
admin-subdomain-release = Release
admin-subdomain-release-confirm = Release this subdomain? AWS federation tokens revert to the shared issuer immediately, and after 30 days the label may be claimed by another organization. Delete any AWS IAM OIDC identity providers for this issuer host.
admin-subdomain-warning = Tokens issued for AWS federation use this issuer as soon as a subdomain is claimed or released — coordinate changes with your AWS IAM OIDC provider and role trust configuration. Released subdomains cannot be claimed by another organization for 30 days.
# Flash messages set by the POST handlers (rendered in the poster's locale).
admin-subdomain-flash-claimed = Claimed issuer subdomain '{ $label }'. Your issuer URL is { $issuer }.
admin-subdomain-flash-claimed-plain = Claimed issuer subdomain '{ $label }'.
admin-subdomain-flash-released = Released issuer subdomain '{ $label }'. Delete any AWS IAM OIDC identity providers for the released issuer host; the subdomain may eventually be claimed by another organization.
# One message per label-validation rule (SubdomainLabelError variant).
admin-subdomain-error-invalid-empty = The subdomain must not be empty.
admin-subdomain-error-invalid-ascii = The subdomain must be ASCII; enter internationalized names in punycode.
admin-subdomain-error-invalid-length = The subdomain must be 63 characters or fewer.
admin-subdomain-error-invalid-dot = The subdomain must not contain dots.
admin-subdomain-error-invalid-hyphen = The subdomain must not start or end with a hyphen.
admin-subdomain-error-invalid-charset = The subdomain may only contain letters, digits, and hyphens.
admin-subdomain-error-invalid-letter = The subdomain must contain at least one letter.
admin-subdomain-error-invalid-reserved = The subdomain '{ $label }' is reserved for platform use.
admin-subdomain-error-not-eligible = This subdomain is not available to your organization. A subdomain is derived from one of your verified domains — for example, verifying acme.com lets you claim acme-com.
admin-subdomain-error-already-claimed = This organization already has the issuer subdomain '{ $existing }'; release it before claiming another.
admin-subdomain-error-conflict = This subdomain is already claimed by another organization.
admin-subdomain-error-recently-released = This subdomain was recently released by another organization and cannot be claimed yet.
admin-subdomain-error-internal = Something went wrong while updating the subdomain; please try again.
admin-subdomain-error-nothing-to-release = This organization has no issuer subdomain to release.
admin-subdomain-error-requires-encryption = Issuer subdomains are not available on this server because document storage is not encrypted. Per-organization signing keys are only created on deployments with encrypted storage.
admin-subdomain-error-no-subdomain = This organization does not have an issuer subdomain; claim one before rotating keys.
# Key rotation actions and confirmations.
admin-subdomain-keys-title = Signing keys
admin-subdomain-keys-col-alg = Algorithm
admin-subdomain-keys-col-state = State
admin-subdomain-keys-col-kid = Key ID
admin-subdomain-keys-col-since = Since
admin-subdomain-key-state-current = Current (signing)
admin-subdomain-key-state-next = Next (staged)
admin-subdomain-key-state-previous = Previous (verify-only)
admin-subdomain-rotate = Rotate Signing Keys
admin-subdomain-rotate-confirm = Switch signing to the staged next keys now? The old keys remain published for verification until you revoke them.
admin-subdomain-flash-rotated = Signing keys rotated. The previous keys remain valid for verification until you revoke them.
admin-subdomain-flash-rotate-not-ready = The next keys are still propagating to relying-party caches. Rotation is available after { $ready }.
admin-subdomain-flash-rotate-previous-unrevoked = Previous keys from the last rotation are still published. Revoke them before rotating again.
admin-subdomain-flash-rotate-not-bootstrapped = Signing keys have not been created yet. They are created the first time the issuer is used; try again afterwards.
admin-subdomain-revoke = Revoke Old Keys
admin-subdomain-revoke-confirm = Delete the previous signing keys? Any token still signed by them will stop verifying.
admin-subdomain-flash-revoked = Previous signing keys revoked and removed from the JWKS.
admin-subdomain-flash-revoke-not-ready = Tokens signed by the previous keys may still be in use. Revocation is available after { $ready }.
admin-subdomain-flash-nothing-to-revoke = There are no previous keys to revoke.
admin-subdomain-emergency-rotate = Emergency Rotate
admin-subdomain-emergency-rotate-confirm = Immediately replace both signing keys? Tokens signed by the old keys will fail verification until relying parties refresh their JWKS cache (up to 1 hour). Use only when key compromise is suspected.
admin-subdomain-emergency-rotate-warning = Warning: outstanding AWS federation tokens will be invalidated immediately.
admin-subdomain-flash-emergency-rotation-done = Emergency key rotation complete. Both signing keys have been replaced. Update any relying parties that cache the JWKS.

## Admin device posture policies (admin/policies.html)
admin-policies-page-title = { -product } - Device Posture Policies
admin-policies-heading = Device Posture Policies
admin-policies-subtitle = Enforce device security requirements for authentication. All active policies must pass.
admin-policies-list-heading = Policies
admin-policies-counts = { $custom } of { $maxCustom } custom · { $active } of { $maxActive } active
admin-policies-badge-builtin = Built-in
admin-policies-badge-custom = Custom
# Fluent attribute pattern: the value is the displayed pill label (current
# state), the `.title` is the action invoked by clicking it (the inverse).
admin-policies-on = On
    .title = Click to disable
admin-policies-off = Off
    .title = Click to enable
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
admin-policies-mdm-note = At least one MDM agent detected (Jamf, Kandji, Workspace ONE, Mosyle, Intune, etc.)
admin-policies-platform-macos = Secure Boot via Apple Silicon or T2 chip
admin-policies-platform-windows = UEFI Secure Boot enabled
admin-policies-platform-linux = UEFI Secure Boot enabled
admin-policies-osrecency-linux = Not checked — use a custom policy per distro
admin-policies-semver-explain = encodes versions as numbers for correct comparison
admin-policies-copy-btn = Copy to a custom policy
admin-policies-new-btn = + New
admin-policies-playground-title = New Custom Policy
admin-policies-name-placeholder = e.g., Require macOS Sequoia
admin-policies-optional = (optional)
admin-policies-desc-placeholder = e.g., Require macOS 15 or later
# Builder: decision point and condition family selectors
admin-policies-applies-label = Applies to
admin-policies-applies-issue = Token issuance (vouch login)
admin-policies-applies-exchange = Token exchange (workload / agent credentials)
admin-policies-applies-hint = Device checks are only available on token issuance — an exchange request carries no device posture.
admin-policies-checks-label = Checks
admin-policies-checks-device = Device state
admin-policies-checks-history = Recent activity
admin-policies-polarity-device = Allow the request only when ALL of these hold:
admin-policies-polarity-history = Deny the request when:
admin-policies-add-check = + Add check
admin-policies-add-osfloor = + Add OS version floor
admin-policies-osfloor-label = OS version floor:
admin-policies-osfloor-windows-build = Windows build
# Screen-reader labels for the builder row controls; the rows read as prose
# for sighted users, so these controls have no visible labels of their own.
admin-policies-row-field-label = Device field
admin-policies-row-op-label = Comparison
admin-policies-row-value-label = Value
admin-policies-row-event-label = Event
admin-policies-row-shape-label = Condition
admin-policies-row-threshold-label = Number of occurrences
admin-policies-row-window-amount-label = Time window length
admin-policies-row-window-unit-label = Time window unit
admin-policies-row-cancel-label = Cancelling event
admin-policies-floor-enable-label = Enable { $os } minimum
admin-policies-floor-min-label = { $os } minimum
admin-policies-window-cap-note = Windows are capped at 24 hours — history older than that is not kept.
admin-policies-warn-login-lockout = This locks users out: the login being evaluated is not yet in the history it checks, so a user returning after the window is denied — and denied again on every retry. Require login recency on token exchange instead.
admin-policies-warn-login-cooldown = This denies issuance because a login recently succeeded — a login cooldown. Users can obtain a token at most once per window.
admin-policies-preview-label = Generated policy
admin-policies-edit-as-text = Edit as text
# History condition shapes: each label completes the sentence
# "<event> <shape> <window>", so they read as prose in the row.
admin-policies-shape-happened = happened in the last
admin-policies-shape-not-happened = did not happen in the last
admin-policies-shape-count = happened at least
admin-policies-shape-not-since = is missing or was followed in the last
admin-policies-times-in-last = times in the last
admin-policies-followed-by = by
admin-policies-unit-s = seconds
admin-policies-unit-m = minutes
admin-policies-unit-h = hours
admin-policies-unit-d = days
# Field groups (builder dropdown + reference table)
admin-policies-group-os = Operating system
admin-policies-group-security = Security posture
admin-policies-group-agents = Security agents
admin-policies-group-process = Process context
admin-policies-group-meta = Metadata
# History events (builder dropdown), sentence-level labels
admin-policies-event-login-success = successful login
admin-policies-event-login-failed = failed login
admin-policies-event-logout = logout
admin-policies-event-token-issued = token issuance
admin-policies-event-token-revoked = token revocation
admin-policies-event-token-exchange = token exchange
admin-policies-event-ssh-credential = SSH credential issuance
admin-policies-event-aws-credential = AWS credential issuance
admin-policies-event-github-credential = GitHub credential issuance
# Set operators (numeric/string operators render as symbols)
admin-policies-op-contains = contains
admin-policies-op-not-contains = does not contain
# Field type labels (reference table)
admin-policies-type-bool = boolean
admin-policies-type-long = number
admin-policies-type-text = string
admin-policies-type-text-enum = string — one of: { $values }
admin-policies-type-set = set of strings — known: { $values }
admin-policies-type-derived-num = number — derived from { $source }
admin-policies-rule-label = Rule
admin-policies-rule-hint = — a Cedar forbid rule; issuance is denied when it fires
admin-policies-ref-title = Dogwood policy language reference
admin-policies-valid = Valid policy
admin-policies-invalid-badge = invalid
admin-policies-invalid-title = This policy no longer validates and denies every request while active. Edit it to see the error.
admin-policies-delete-confirm = Delete this custom policy?
admin-policies-sample-device-note = Your rule is tested against this sample device when editing. Fields not listed below default to "" (string), false (boolean), or 0 (number).
admin-policies-fieldref-summary = Field reference & test device
admin-policies-fieldref-th-field = Field
admin-policies-fieldref-th-test = Test value
admin-policies-example-rules = Example rules:
admin-policies-eventref-heading = Event history fields
admin-policies-eventref-note = In a temporal rule, the braces after an event name filter which past events count. Match a field against a literal to select events — output.result: true means successful logins only — or against a context reference to require it to match the current request, as in input.ip: context.input.ip. On the decision being evaluated, the same input fields are readable directly as context.input.*.
admin-policies-eventref-none = no matchable fields — the event itself is the signal
admin-policies-note-label = Note:
admin-policies-note-body = Posture data is self-reported by the CLI. Policies are a compliance baseline, not a cryptographic guarantee.

## Posture policy names, descriptions, and remediation guidance
admin-policies-name-disk-encryption = Disk Encryption
admin-policies-desc-disk-encryption = Require full-disk encryption (FileVault, BitLocker, LUKS)
admin-policies-fix-disk-encryption = Enable full-disk encryption on your device
admin-policies-fix-disk-encryption-macos = Enable FileVault in System Settings > Privacy & Security
admin-policies-fix-disk-encryption-linux = Enable LUKS encryption with cryptsetup
admin-policies-fix-disk-encryption-windows = Enable BitLocker in Settings > Device encryption

admin-policies-name-firewall = Firewall
admin-policies-desc-firewall = Require an active firewall
admin-policies-fix-firewall = Enable your system firewall
admin-policies-fix-firewall-macos = Enable Firewall in System Settings > Network > Firewall
admin-policies-fix-firewall-linux = Enable firewall with: sudo ufw enable
admin-policies-fix-firewall-windows = Enable Windows Firewall in Windows Security

admin-policies-name-screen-lock = Screen Lock
admin-policies-desc-screen-lock = Require screen lock on idle
admin-policies-fix-screen-lock = Enable screen lock on your device
admin-policies-fix-screen-lock-macos = Set screen lock in System Settings > Lock Screen
admin-policies-fix-screen-lock-linux = Configure screen lock in your display settings. If authenticating via SSH, screen lock status may not be detectable — try authenticating from a graphical session
admin-policies-fix-screen-lock-windows = Set screen lock in Settings > Accounts > Sign-in options

admin-policies-name-endpoint-protection = Endpoint Protection
admin-policies-desc-endpoint-protection = Require at least one EDR agent installed
admin-policies-fix-endpoint-protection = Install an endpoint detection and response (EDR) agent
# macOS and Linux share this guidance.
admin-policies-fix-endpoint-protection-macos = Install an EDR agent (e.g., CrowdStrike, SentinelOne)
admin-policies-fix-endpoint-protection-windows = Install an EDR agent (e.g., CrowdStrike, Microsoft Defender for Endpoint)

admin-policies-name-mdm-enrollment = MDM Enrollment
admin-policies-desc-mdm-enrollment = Require enrollment in mobile device management (Jamf, Kandji, Intune)
admin-policies-fix-mdm-enrollment = Enroll this device in your organization's device management (MDM), then retry

admin-policies-name-platform-integrity = Platform Integrity
admin-policies-desc-platform-integrity = Require Secure Boot to be enabled
admin-policies-fix-platform-integrity = Enable Secure Boot on your device
admin-policies-fix-platform-integrity-macos = Secure Boot is managed by Apple and should be enabled by default
# Linux and Windows share this guidance.
admin-policies-fix-platform-integrity-windows = Enable Secure Boot in your UEFI/BIOS firmware settings

admin-policies-name-os-recency = OS Recency
admin-policies-desc-os-recency = Require a supported OS version (N-1)
admin-policies-fix-os-recency = Update your operating system to a supported version
admin-policies-fix-os-recency-macos = Update macOS to a supported version (14 or later)
admin-policies-fix-os-recency-linux = Linux is not covered by the built-in OS recency check. Your organization may have a custom policy for your distribution
admin-policies-fix-os-recency-windows = Update Windows to a supported version (build 26100 or later)

admin-policies-name-issuance-rate-limit = Issuance Rate Limit
admin-policies-desc-issuance-rate-limit = Deny token issuance after 10 issuances within one hour
admin-policies-fix-issuance-rate-limit = Too many token issuances in the last hour. Wait and retry

admin-policies-name-exchange-rate-limit = Exchange Rate Limit
admin-policies-desc-exchange-rate-limit = Deny token exchange after 30 exchanges within one hour
admin-policies-fix-exchange-rate-limit = Too many token exchanges in the last hour. Wait and retry

admin-policies-name-failed-login-burst = Failed Login Burst
admin-policies-desc-failed-login-burst = Deny token issuance after 5 failed logins within ten minutes
admin-policies-fix-failed-login-burst = Too many failed login attempts recently. Wait a few minutes and retry

admin-policies-name-token-exchange-step-up = Token Exchange Step-Up
admin-policies-desc-token-exchange-step-up = Token exchange (WIF/agent credentials) requires a hardware login within 15 minutes
admin-policies-fix-token-exchange-step-up = A recent hardware login is required. Run `vouch login` and retry

admin-policies-name-exchange-ip-consistency = Exchange IP Consistency
admin-policies-desc-exchange-ip-consistency = Token exchange must come from the same IP as a successful login within 8 hours
admin-policies-fix-exchange-ip-consistency = This request came from a different network than your recent login. Run `vouch login` from this network and retry

admin-policies-name-logout-invalidates-exchange = Logout Invalidates Exchange
admin-policies-desc-logout-invalidates-exchange = Token exchange is denied after logout until the user logs in again
admin-policies-fix-logout-invalidates-exchange = You logged out since your last login. Run `vouch login` and retry

admin-policies-err-empty = Policy text must not be empty
admin-policies-err-invalid = Invalid policy: { $detail }
# Builder rule-spec errors (shown in the validation box)
admin-policies-err-rule-empty = Add at least one complete condition
admin-policies-err-device-on-exchange = Device conditions only apply to token issuance — switch "Applies to", or use recent-activity checks
admin-policies-err-unknown-field = Unknown device field: { $field }
admin-policies-err-bad-operator = That operator does not apply to { $field }
admin-policies-err-bad-value = The value does not fit { $field }
admin-policies-err-unknown-value = "{ $value }" is not a known value for { $field }
admin-policies-err-unknown-event = Unknown history event: { $event }
admin-policies-err-bad-version = "{ $value }" is not a version like 15.3.1
admin-policies-err-bad-window = The window must be between 1 second and 24 hours
admin-policies-err-bad-threshold = The count must be at least 1
admin-policies-err-bad-text = Text values must not contain control characters
admin-policies-err-too-long = The generated policy exceeds { $max } characters — remove some conditions
# Shown when a deny cannot be traced to a specific policy.
admin-policies-deny-unattributed = device posture
admin-policies-deny-generic = Check your device settings to meet your organization's compliance requirements
admin-policies-deny-message = Device posture policy '{ $policy }' not satisfied. { $remediation }

## Admin policies — client-side JS (policy-builder.js, policies page)
admin-js-edit-policy-title = Edit Custom Policy
admin-js-copy-of = Copy of { $name }
admin-js-policy-passes = — passes against test device
admin-js-policy-fails = — fails against test device
admin-js-policy-invalid = Invalid policy
admin-js-policy-history-note = — reads event history, which the test device has none of; the shape summaries below describe what the policy will do
admin-js-edit-as-text-confirm = Editing the text directly means this policy can no longer be edited with the builder. Continue?
admin-js-version-encodes = → { $num }
# Shape-aware outcome summaries for history rules, one line per condition
admin-js-preview-all = This rule denies only when all of the above hold at the same time.
admin-js-preview-happened = Denies when a { $event } occurred in the last { $window }; allows otherwise.
admin-js-preview-not-happened = Denies when there was no { $event } in the last { $window }.
admin-js-preview-count = Denies at { $n } or more { $event } events in { $window }; allows at { $m } or fewer.
admin-js-preview-not-since = Denies when there was no { $anchor } in the last { $window }, or the most recent one was followed by a { $cancel }.

## Admin SCIM tokens (admin/scim_tokens.html)
admin-scim-page-title = { -product } - API Tokens
admin-scim-subtitle = Manage API tokens for SCIM provisioning and audit event access.
admin-scim-new-created = New API token created. Copy it now — it won't be shown again.
admin-scim-max = Maximum of 2 API tokens reached. Revoke an existing token before creating a new one.
admin-scim-create = Create Token
admin-scim-desc-placeholder = e.g. Okta SCIM integration
admin-scim-expires-in = Expires in
admin-scim-days-30 = 30 days
admin-scim-days-90 = 90 days
admin-scim-days-180 = 180 days
admin-scim-days-365 = 365 days
admin-scim-th-expires = Expires
admin-scim-th-scopes = Scopes
admin-scim-scope-provisioning = SCIM
admin-scim-scope-audit-read = Audit read
admin-scim-audit-read-label = Also grant read-only audit log access ({ $scope })
admin-scim-revoke-confirm = Revoke this API token? Any integration using it will stop working.
admin-scim-none = No API tokens. Create one to enable identity provider provisioning or audit log access.
admin-scim-warning = API tokens grant full read/write SCIM provisioning access and, if selected, read-only audit log access. A maximum of 2 tokens is allowed to support key rotation while limiting exposure.
# Skip-navigation link at the top of every page (base.html)
skip-to-content = Skip to main content
footer-install = Install
footer-docs = Docs
footer-privacy = Privacy
footer-terms = Terms
footer-status = Status
footer-version = v{ $version }
footer-copyright = Copyright { $year }

## RP-Initiated Logout 1.0 — confirmation page (logout_confirm.html)
logout-confirm-title = { -product } - Sign Out
logout-confirm-heading = Sign out?
logout-confirm-body = You are about to sign out of { -product }.
logout-confirm-btn = Sign Out
logout-confirm-cancel = Cancel

## RP-Initiated Logout 1.0 — done page (logout_done.html)
logout-done-title = { -product } - Signed Out
logout-done-heading = You have been signed out.
logout-done-body = Your session has ended. Close this tab or return to the application.

## Redirect interstitials (form_post_response.html, saml_post_form.html)
redirect-title = Redirecting...
redirect-continue = Continue
redirect-form-post-noscript = Submitting authorization response. If you are not redirected, click the button below.
redirect-saml-noscript = Redirecting to identity provider. If you are not redirected, click the button below.

## Audit event catalogue — group headings and per-kind descriptions.
##
## One `audit-group-*` message per `AuditEventGroup` and one `audit-event-*`
## message per `AuditEventKind` (crates/vouch-server/src/db/audit.rs). The
## "Audit Events" section of docs/src/admin/audit.md is generated from these
## via `make docs-gen` (tests/audit_docs_gen.rs); the parity test in
## infra/i18n.rs enforces exact registry ↔ catalog correspondence both ways.
## Text may use markdown backticks (rendered as code in mdBook); a literal
## `{` or `}` would need Fluent escaping as {"{"} / {"}"}.

audit-group-authentication = Authentication and key lifecycle
audit-group-credentials = Credential issuance
audit-group-oauth-clients = OAuth clients
audit-group-administration = Administration and organization

audit-event-login-success = User authenticated — FIDO2 passkey login, or a returning user signing in on the website via the upstream IdP (the latter has no `authenticator_id`)
audit-event-login-failed = Failed authentication attempt
audit-event-enrollment = User enrolled their first hardware key
audit-event-logout = User logged out (including RFC 7009 token revocation)
audit-event-key-registered = Additional hardware key registered (`vouch register`)
audit-event-key-removed = Hardware key removed
audit-event-device-auth-approved = Browser approved a CLI device-authorization request
audit-event-key-registration-replay = Replayed key-registration link rejected (possible attack)
audit-event-identity-bound = Upstream IdP identity (issuer + subject) bound to an account on its first IdP login; `data.idp_issuer` names the issuer
audit-event-identity-bind-refused = IdP sign-in refused: the asserted email matched an account already bound to a different subject at the same issuer (possible upstream email reassignment); `data.idp_issuer` names the issuer
audit-event-ssh-credential = SSH certificate issued; `data` includes the serial, principals, requesting agent, and expiry
audit-event-aws-credential = AWS OIDC token issued; `data` includes the pinned IAM `role_arn` (the `https://aws.amazon.com/roles` claim), the requesting agent, and token expiry
audit-event-github-credential = GitHub installation token issued or installation connected; `data` includes repositories and permissions
audit-event-token-exchange = RFC 8693 token exchange (workload identity federation); `data` includes the client, audience, scope, and issued token type
audit-event-oauth-token-issued = Token issued at `/oauth/token` (`data.details` carries the grant type)
audit-event-oauth-token-revoked = All tokens for an application revoked
audit-event-oauth-client-registered = OAuth client registered (RFC 7591 or applications UI)
audit-event-oauth-client-updated = OAuth client configuration updated
audit-event-oauth-client-deleted = OAuth client deleted
audit-event-oauth-secret-added = Client secret added
audit-event-oauth-secret-revoked = Client secret revoked
audit-event-scim-operation = SCIM provisioning operation (`data` carries operation and resource type)
audit-event-admin-promote = Org-admin role granted
audit-event-admin-demote = Org-admin role removed
audit-event-admin-deactivate = User account deactivated
audit-event-admin-activate = User account reactivated
audit-event-admin-revoke-credentials = Admin revoked a member's keys, sessions, and certificates
audit-event-admin-remove-user = Admin removed a member from the organization
audit-event-policy-denied = A posture or temporal policy denied credential issuance
audit-event-admin-policy-toggle = Posture policy enabled or disabled
audit-event-admin-policy-create = Custom posture policy created
audit-event-admin-policy-update = Custom posture policy updated
audit-event-admin-policy-delete = Custom posture policy deleted
audit-event-admin-create-scim-token = SCIM API token created
audit-event-admin-delete-scim-token = SCIM API token deleted
audit-event-admin-revoke-scim-token = SCIM API token revoked
audit-event-org-domain-added = Additional email domain added to the organization
audit-event-org-domain-verified = Additional email domain ownership verified
audit-event-org-domain-removed = Additional email domain removed by an admin
audit-event-org-domain-expired = Stale additional domain removed by the cleanup task (never verified, or unverified past its TTL)
audit-event-org-domain-unverified = Verified additional domain flipped to unverified after repeated DNS re-check failures
audit-event-org-subdomain-claimed = Issuer subdomain claimed for the organization
audit-event-org-subdomain-released = Issuer subdomain released (by an admin, or automatically when its backing domain became unverified)
audit-event-org-issuer-key-rotated = Per-org issuer signing keys rotated (one event per algorithm)
audit-event-org-issuer-key-revoked = Per-org previous signing keys revoked (one event per algorithm)
audit-event-org-issuer-key-emergency-rotation = Emergency rotation of per-org issuer keys (one event per algorithm)
