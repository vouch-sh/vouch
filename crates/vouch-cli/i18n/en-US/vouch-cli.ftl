# Vouch CLI — en-US message catalog.
#
# IDs follow kebab-case and are scoped by area:
#   cli-*           - top-level command / Cli struct
#   cmd-<sub>-*     - subcommand-level attributes
#   arg-<scope>-*   - clap arg help / long-help
#   fido2-err-*     - CTAP2 / WebAuthn user-facing error messages
#   enroll-*        - enroll command output
#
# Translators: this file is the source of truth for runtime strings; the
# matching English in clap derive attributes (where present) is the fallback
# clap shows if i18n init fails. Keep them aligned for en-US.
#
# ---------------------------------------------------------------------------
# Terms (Fluent feature):
#   - Reusable nouns. Reference as { -term-name } in any message.
#   - Translators change the noun ONCE and it propagates everywhere.
#   - Names start with `-`. Term references survive placeable substitution.
# ---------------------------------------------------------------------------

-yubikey = YubiKey
-product = Vouch
-cmd = vouch
-github = GitHub

cli-about = Hardware-backed identity for developers
cli-long-about = { -product } issues short-lived credentials after FIDO2 verification with a { -yubikey }.
    No credential issuance without human presence proof.
cli-verbose-help = Enable verbose output
cli-lang-help = Override the user-facing language (BCP-47, e.g. en-US, fr-FR)
cli-server-help = { -product } server URL
cli-color-help = Control color output
cli-after-help =
    Exit codes:
      0  Success
      1  General error
      2  Not authenticated (session expired or missing)
      3  Hardware key not detected
      4  Network/server unreachable
      5  Permission denied
      6  Configuration error

## enroll command

cmd-enroll-about = Enroll with browser-based OIDC + WebAuthn (recommended for new users)

enroll-starting = Starting enrollment...
enroll-waiting = Waiting for browser authorization...
enroll-waiting-progress = Waiting for browser authorization
enroll-registering-key = Registering your { -yubikey } with the server...
enroll-key-registered = { -yubikey } registered! (device ID: { $device_id })

# Browser opened automatically: show URL + code + fallback hint.
enroll-browser-block =
    Opening browser to complete enrollment...

      URL:  { $url }
      Code: { $code }

    If the browser didn't open, visit the URL above and enter the code.

# Browser failed to open: numbered manual fallback.
enroll-manual-block =
    To complete enrollment:

      1. Open this URL in your browser:
         { $url }

      2. Enter this code:
         { $code }

# Success summary printed once enrollment + auto-registration finish.
enroll-success-block =
    Enrollment successful!
    Enrolled as: { $email }

# "Next steps" call-out shown at the very end of a successful enrollment.
enroll-next-steps =
    Set up integrations:
      { -cmd } setup ssh      # SSH certificates
      { -cmd } setup aws      # AWS credentials
      { -cmd } setup github   # GitHub tokens

    Or add a backup key:
      { -cmd } login && { -cmd } register --name "Backup Key"

enroll-err-timeout =
    Enrollment timed out. Please try again.
    Make sure to complete the sign-in in your browser window and enter the code shown above.
enroll-err-denied = authorization was denied
enroll-err-code-expired = The code has expired. Please try again.
enroll-err-failed = Enrollment failed: { $reason }
enroll-err-start = Failed to start enrollment
enroll-err-key-init = Failed to initialize the hardware-backed signing key
enroll-err-register = Failed to register client with the server (RFC 7591)

## Client / session errors

client-err-not-authenticated = not authenticated — run '{ -cmd } login' first

## RFC 9421 HTTP message signing errors

httpsig-err-no-signature =
    Failed to sign request for { $path }: HTTP message signing produced no
    signature — re-run { -cmd } enroll or unlock your keychain and try again
httpsig-err-key-unavailable =
    Hardware-backed signing key unavailable for { $path }: this request must be
    signed (RFC 9421). Run { -cmd } enroll (or unlock your keychain) and try again

## FIDO2 / CTAP2 user-facing errors

fido2-err-credential-excluded = This { -yubikey } is already registered for this service.
fido2-err-pin-invalid =
    Incorrect PIN. Please try again.
    Hint: Too many wrong attempts will lock your { -yubikey }.
fido2-err-pin-blocked =
    Your { -yubikey } PIN is blocked due to too many incorrect attempts.
    You must reset the FIDO2 application to continue:

    WARNING: This will delete all FIDO2 credentials on this { -yubikey }!

    Option 1: ykman fido reset  (install: brew install ykman)
    Option 2: Use the { -yubikey } Manager GUI app to reset FIDO2

    After reset, run `{ -cmd } enroll` to re-register your { -yubikey }.
fido2-err-pin-auth-invalid = PIN authentication failed. Please try again.
fido2-err-pin-auth-blocked =
    PIN authentication is temporarily blocked.
    Please unplug your { -yubikey } and plug it back in, then try again.
fido2-err-pin-not-set =
    Your { -yubikey } PIN is not set.
    This is unexpected — try running this command again.
fido2-err-pin-required = A PIN is required for this operation.
fido2-err-pin-policy =
    PIN does not meet policy requirements.
    PIN must be at least 8 characters.
fido2-err-pin-token-expired = PIN authentication expired. Please try again.
fido2-err-generic = { $operation } failed: { $reason }

## WebAuthn (Windows) user-facing errors

webauthn-err-cancelled = Authentication cancelled.
webauthn-err-device-not-found =
    No security key found.
    Insert your { -yubikey } and try again.
webauthn-err-keyset-full =
    Your { -yubikey } has no free passkey slots.
    Delete an existing credential with `ykman fido credentials delete` and try again.
webauthn-err-timeout =
    Timed out waiting for { -yubikey }.
    Insert your key and try again.
webauthn-err-not-supported =
    Your authenticator does not support resident keys or user verification.
    { -cmd } requires a { -yubikey } 5 or later with PIN configured.
webauthn-err-invalid-parameter =
    Internal error: invalid WebAuthn parameter (HRESULT 0x{ $code }).
    Please file a bug at https://github.com/vouch-sh/vouch/issues.
webauthn-err-generic = { $operation } failed: 0x{ $code } { $detail }
webauthn-err-not-passkey =
    Your authenticator has a credential for this service, but it was not stored as a passkey.
    Re-enroll with `{ -cmd } enroll` to create a compatible credential.

## PIN setup prompts

fido2-pin-prompt-new = New PIN (minimum 8 characters):
fido2-pin-prompt-confirm = Confirm PIN:
fido2-pin-err-too-short = PIN must be at least 8 characters.
fido2-pin-err-too-long = PIN must be at most 63 characters.
fido2-pin-err-mismatch = PINs do not match. Please try again.

fido2-insert-prompt = Please insert your { -yubikey }...
fido2-detected = detected!
fido2-pin-prompt = { -yubikey } PIN:
fido2-setup-pin-intro =
    Your { -yubikey } does not have a PIN configured.
    A PIN is required for FIDO2 authentication to prove you are present.

    Let's set one up now.
fido2-setting-pin = Setting PIN...
fido2-setting-pin-done = done!
fido2-err-insert-prompt =
    Timed out waiting for { -yubikey } after { $timeout }s.
    Insert your key and try again.
fido2-err-not-ready = { -yubikey } not ready after insertion - try removing and reinserting it
fido2-err-pin-query = failed to query PIN status
fido2-err-pin-unsupported = This device does not support PIN authentication
fido2-err-pin-already-set = A PIN is already set on this { -yubikey }.
fido2-err-pin-set-failed = Failed to set PIN: { $reason }
fido2-err-attestation = attestation verification failed
fido2-err-no-assertion = no assertion returned
fido2-err-read-pin = failed to read PIN
fido2-err-read-pin-confirmation = failed to read PIN confirmation
fido2-pin-policy-block =
    PIN does not meet requirements.
    PIN must be at least 8 characters.
fido2-err-no-credentials =
    No credentials found for this service.
    Have you enrolled with `{ -cmd } enroll`?
fido2-err-not-passkey =
    Your { -yubikey } has a credential for this service, but it was not stored as a passkey.
    Re-enroll with `{ -cmd } enroll` to create a compatible credential.

## Subcommand `about` text

cmd-register-about = Register an additional { -yubikey } (requires login first)
cmd-login-about = Authenticate with your { -yubikey }
cmd-status-about = Show current session status
cmd-logout-about = End your current session
cmd-env-about = Output credential environment variables for `eval`
cmd-env-long-about =
    Usage: eval "$({ -cmd } env --type aws --shell bash --role <ARN>)"
cmd-init-about = Output a shell hook for ambient auth status
cmd-init-long-about = Add `eval "$({ -cmd } init bash)"` to your shell profile.
cmd-keys-about = Manage registered security keys
cmd-keys-long-about = Without a subcommand, opens an interactive menu.
cmd-exec-about = Run a command with { -product }-provided credentials in the environment
cmd-credential-about = Obtain credentials for various services
cmd-setup-about = Configure integrations
cmd-aws-about = AWS Identity Center commands for multi-account management
cmd-completions-about = Generate shell completions
cmd-doctor-about = Check your { -product } environment for common issues
cmd-posture-about = Show device posture signals (what the CLI detects about this machine)
cmd-diag-about = Run diagnostic test of { -yubikey } registration + authentication (bypasses server)
cmd-diag-long-about =
    Not available on Windows: depends on the CTAP2 protocol which Windows blocks for non-elevated processes.

## Shared arg help

arg-register-name-help = Human-readable name for this { -yubikey } (e.g., "My { -yubikey } 5"). Defaults to "{ -yubikey }" if not specified.
arg-register-timeout-help = Timeout in seconds for { -yubikey } detection (0 for no timeout).
arg-login-timeout-help = Timeout in seconds for { -yubikey } detection (0 for no timeout).
arg-status-format-help = Output format.
arg-env-type-help = Credential type to export.
arg-env-shell-help = Shell syntax to emit.
arg-env-role-help = AWS IAM role ARN (required for --type aws).
arg-init-shell-help = Shell to generate hook for.
arg-exec-type-help = Credential type to inject.
arg-exec-role-help = AWS IAM role ARN (required for --type aws).
arg-exec-command-help = Command and arguments to execute.
arg-doctor-quiet-help = Suppress output (exit code only).
arg-doctor-json-help = Output as JSON.
arg-posture-format-help = Output format.

## Session-shared lines (reused by enroll, login, register)

session-agent-ready = Your identity is now available. Check with: { -cmd } status
session-agent-not-running = Note: Agent not running. Start it with: vouch-agent --foreground
session-stored-locally = Your identity is stored locally. Check with: { -cmd } status

## login command

login-starting = Logging in...
login-contacting-server = Contacting server ({ $server })...
login-contact-ok = ok
login-success-as = Login successful as { $email }!
login-success = Login successful!
login-session-expires = Session expires: { $expiry }
login-err-not-registered =
    This { -yubikey } is not registered with the server.
    Run '{ -cmd } enroll' to register it.
login-err-invalid-client =
    Client registration is invalid or expired.
    The client will be re-registered on the next attempt.
    Please run this command again. If it persists, run '{ -cmd } enroll' to start fresh.

## register command

register-starting = Registering additional { -yubikey } '{ $name }'...
register-contacting-server = Contacting server...
register-contact-ok = ok
register-completing = Completing registration...
register-completed-ok = ok
register-success-block =
    Registration successful!
    Device ID: { $device_id }

    You can manage your keys with: { -cmd } keys
register-existing-keys =
    Note: You have { $count ->
        [one] { $count } existing key
       *[other] { $count } existing keys
    } registered.
register-not-authenticated =
    Not authenticated.

    To register your first key: { -cmd } enroll
    To add additional keys: { -cmd } login, then { -cmd } register
register-chrome-blocking =
    Google Chrome is using your { -yubikey }, so we can't register it from
    the command line. Opening your browser to finish registration there
    instead. (Tip: quit Chrome and re-run if you'd prefer the CLI.)

register-browser-block =
    Opening browser to complete registration...

      URL: { $url }

    If the browser didn't open, visit the URL above. You may be
    prompted to sign in again. After registration, run `{ -cmd } keys`
    to verify.
register-manual-block =
    To complete registration:

      1. Open this URL in your browser:
         { $url }

      2. Sign in (if prompted) and complete the WebAuthn ceremony.

    After registration, run `{ -cmd } keys` to verify.

## logout command

logout-success = Logged out successfully.
logout-not-logged-in = Not currently logged in.

## status command

status-not-authenticated = Not authenticated.
status-session-expired = Session expired.
status-session-invalid = Session invalid: { $reason }
status-hint-login = Run '{ -cmd } login' to authenticate.
status-hint-relogin = Run '{ -cmd } login' to re-authenticate.
status-authenticated = Authenticated
status-label-email = Email:
status-label-device = Device:
status-label-agent = Agent:
status-label-expires = Expires:
status-agent-running = running
status-agent-not-running = not running
status-hint-start-agent = Hint: Start the agent for faster status checks: vouch-agent --foreground
# Remaining-time renderer for the Expires: line. Selector branches on the
# integer `hours` value so locales can decide whether to drop the hours
# segment when zero or always show both.
status-time-remaining = { $hours ->
        [0] in { $minutes }m
       *[other] in { $hours }h { $minutes }m
    }

## posture command

posture-title = Device Posture (v{ $version })
posture-label-os = OS:
posture-label-build = Build:
posture-label-architecture = Architecture:
posture-label-disk-encryption = Disk encryption:
posture-label-screen-lock = Screen lock:
posture-label-firewall = Firewall:
posture-label-secure-boot = Secure boot:
posture-label-sip = SIP:
posture-label-tpm = TPM:
posture-label-auto-update = Auto-update:
posture-label-uptime = Uptime:
posture-label-access-control = Access control:
posture-label-edr = EDR:
posture-label-mdm = MDM:
posture-label-elevated = Elevated:
posture-label-tty = TTY:
posture-label-parent-process = Parent process:
posture-label-cli-version = CLI version:
# Boolean-state value pairs. Each renders one of two arms based on a `$on`
# (or `$b`) placeable carrying the stringified bool ("true"/"false"). State
# pairs are kept together here so translators see both arms side-by-side and
# can keep them consistent (capitalization, punctuation, locale-specific
# wording). The `not-checked` plain id stays separate — it's the "we didn't
# attempt the check" state, not a boolean arm.
posture-val-enabled-or-missing = { $on ->
    [true] enabled
   *[false] not detected
}
posture-val-enabled-or-disabled = { $on ->
    [true] enabled
   *[false] disabled
}
posture-val-present-or-missing = { $on ->
    [true] present
   *[false] not detected
}
posture-val-enforcing-or-permissive = { $on ->
    [true] enforcing
   *[false] permissive/disabled
}
posture-val-yes-no = { $b ->
    [true] yes
   *[false] no
}
# Standalone "we checked and found nothing" / "we didn't attempt the check"
# states — used by EDR/MDM list rendering and the disk-encryption /
# screen-lock / firewall blocks when the underlying signal couldn't be read.
posture-val-not-detected = not detected
posture-val-not-checked = not checked

posture-screen-lock-with-idle = (idle timeout: { $timeout }s)
posture-uptime-d-h-m = { $days }d { $hours }h { $minutes }m

## doctor command

doctor-title = { -product } Doctor - Environment Diagnostics
doctor-all-passed = All checks passed!
doctor-some-failed = Some checks failed. Review the issues above.
doctor-check-yubikey-label = { -yubikey } connectivity ...
doctor-check-agent-label = Agent running ...
doctor-check-server-label = Server reachable ...
doctor-check-clock-label = Clock in sync with server ...
doctor-check-doh-label = DNS-over-HTTPS resolution ...
doctor-check-session-label = Session valid ...
doctor-check-ssh-label = SSH configuration ...
doctor-check-eks-label = EKS configuration ...
doctor-check-ssm-label = SSM configuration ...
doctor-check-server-url-label = Server URL security ...
doctor-doh-disabled =
    disabled — DNS queries are visible to your local network.
    Set VOUCH_DOH=cloudflare (or google/quad9) to encrypt them.

doctor-yubikey-found = FIDO2 device found
doctor-yubikey-not-found = No FIDO2 device found: { $reason }
doctor-yubikey-win-api-missing = Windows WebAuthn API not available. Update to Windows 10 1903 or later.
doctor-yubikey-win-api-available =
    Windows WebAuthn API available (version { $version }); { -cmd } login uses the system Security dialog
    to authenticate your { -yubikey } — no admin privileges required.

doctor-agent-running-pid = Agent is running (PID { $pid })
doctor-agent-running = Agent is running
doctor-agent-connection-failed = Agent connection failed: { $reason }
doctor-agent-socket-exists = Socket exists but connection failed: { $reason }
doctor-agent-not-running = Agent not running. Start with: vouch-agent --foreground

doctor-server-invalid-url = Invalid server URL: { $reason }
doctor-server-unreachable = Server unreachable: { $reason }
doctor-server-reachable = Server at { $server } is reachable
doctor-server-status = Server returned status: { $status }

doctor-clock-ok = System clock within { $secs }s of server
doctor-clock-skew =
    System clock is { $secs }s { $direction } the server.
    Signed requests will fail once skew exceeds 300s.
    Sync your clock (Windows: Settings → Time & Language → Date & Time → "Sync now"; macOS: `sudo sntp -sS time.apple.com`).
doctor-clock-direction-behind = behind
doctor-clock-direction-ahead = ahead of

doctor-doh-zero-addresses = { $label }: { $host } resolved to zero addresses
doctor-doh-resolved = { $label }: { $host } resolved to { $count } address(es)
doctor-doh-error = { $label }: { $reason }

doctor-session-valid = Session valid for { $hours }h { $mins }m ({ $email })
doctor-session-expired = Session expired. Run: { -cmd } login
doctor-session-none = No active session. Run: { -cmd } login
doctor-session-no-config = No config found. Run: { -cmd } login
doctor-session-token-only = Session token found (agent not running for full validation)
doctor-session-no-token = No session token. Run: { -cmd } login

doctor-ssh-no-home = Could not determine home directory
doctor-ssh-key-missing = { -product } SSH key not found. Run: { -cmd } setup ssh
doctor-ssh-config-missing-entry = No { -product } entry in SSH config. Run: { -cmd } setup ssh
doctor-ssh-config-unreadable = Could not read SSH config
doctor-ssh-config-not-found = SSH config not found
doctor-ssh-configured = SSH configured for { -product }

doctor-eks-no-home = Could not determine home directory
doctor-eks-no-kubeconfig = No kubeconfig found (EKS not configured)
doctor-eks-configured = EKS configured for { -product }
doctor-eks-no-vouch-entry = Kubeconfig exists (no { -product } EKS integration). Run: { -cmd } setup eks --cluster <name>
doctor-eks-unreadable = Could not read kubeconfig

doctor-ssm-no-home = Could not determine home directory
doctor-ssm-configured = SSM configured for { -product }
doctor-ssm-plugin-found = session-manager-plugin found (not configured). Run: { -cmd } setup ssm
doctor-ssm-plugin-missing-but-configured = SSH config references SSM but session-manager-plugin not found on PATH
doctor-ssm-not-configured = SSM not configured (session-manager-plugin not found)

doctor-server-url-insecure = Server uses plain HTTP ({ $server }). Use HTTPS or set VOUCH_ALLOW_INSECURE=1.
doctor-server-url-secure = Server URL is secure (HTTPS or localhost)

## keys command

keys-none = No keys registered.
keys-prompt-select = Select a key to manage:
keys-help-navigation = ↑↓ to move, Enter to select, Esc to exit
keys-help-action = Select an action
keys-help-undo = This action cannot be undone
keys-action-exit = Exit
keys-action-delete = Delete this key
keys-action-back = Back to list
keys-action-quit = Quit
keys-marker-current = { " " }(current session)
keys-marker-current-short = (current)
keys-action-prompt = Key: { $name }{ $marker }
keys-cancelled = Cancelled.
keys-err-selection = Selection error: { $reason }
keys-err-confirmation = Confirmation error: { $reason }
keys-warn-current-session = WARNING: This is the key used for your current session. Your session will be invalidated.
keys-confirm-delete = Delete key '{ $name }'?{ $warning }
keys-step-up-needed = Fresh authentication required to delete a key.
keys-header = Registered keys:
keys-table-id = ID
keys-table-name = NAME
keys-table-model = MODEL
keys-table-created = CREATED
keys-table-current = CURRENT
keys-legend = * = key used for current session
keys-confirm-remove-line = You are about to remove the key '{ $name }' (ID: { $id }).
keys-warn-remove-current-session =
    WARNING: This is the key used for your current session.
             Your session will be invalidated.
keys-confirm-y-n = Are you sure? [y/N]
keys-sessions-revoked =
    { $count ->
        [one] { $count } session revoked.
       *[other] { $count } sessions revoked.
    }
keys-err-not-found = Key not found: { $id }
keys-err-name-empty = Name cannot be empty
keys-err-name-long = Name must be 100 characters or less

## env command

env-err-aws-needs-role = AWS credentials require --role.

## exec command

exec-err-no-command = No command specified.
exec-err-no-command-short = no command specified
exec-err-aws-needs-role = AWS credentials require --role.
exec-err-execute-failed = failed to execute { $program }: { $reason }
exec-err-execute-simple = failed to execute: { $program }
exec-err-exit-status = command exited with status { $code }
exec-err-aws-missing-key-id = AWS credentials missing AccessKeyId
exec-err-aws-missing-secret = AWS credentials missing SecretAccessKey
exec-err-aws-missing-token = AWS credentials missing SessionToken
exec-err-github-missing-token = GitHub credential missing 'token' field
exec-err-github-fetch = failed to get GitHub token from { -product } server
exec-err-codeartifact-fetch = failed to get CodeArtifact token
exec-err-rds-needs-hostname = RDS credentials require --rds-hostname.
exec-err-rds-needs-username = RDS credentials require --rds-username.

## diag command

diag-intro-block =
    === { -yubikey } Diagnostic Test ===

    This test will:
    1. Register a new credential on your { -yubikey }
    2. Authenticate with that credential
    3. Verify the signature using aws-lc-rs
diag-insert-prompt = Please insert your { -yubikey }...
diag-detected = detected!
diag-pin-prompt = { -yubikey } PIN:
diag-touch-register = Touch your { -yubikey } to register...
diag-touch-authenticate = Touch your { -yubikey } to authenticate...
diag-registration-header = === REGISTRATION ===
diag-authentication-header = === AUTHENTICATION ===
diag-registration-success = Registration successful!
diag-authentication-success = Authentication successful!
diag-rpid-header = === RPID VERIFICATION ===
diag-rpid-match = OK RPID hash matches
diag-rpid-mismatch = FAIL RPID hash MISMATCH!
diag-lib-verification-header = === LIBRARY VERIFICATION ===
diag-lib-verification-passed = OK ctap-hid-fido2 library verification: PASSED
diag-lib-verification-failed = FAIL ctap-hid-fido2 library verification: FAILED
diag-aws-lc-header = === AWS-LC-RS VERIFICATION ===
diag-keys-identical = OK Public keys are IDENTICAL (byte-by-byte)
diag-keys-differ = FAIL Public keys DIFFER!
diag-aws-lc-passed = OK aws-lc-rs verification ({ $kind }): PASSED
diag-aws-lc-failed = FAIL aws-lc-rs verification ({ $kind }): FAILED
diag-aws-lc-failed-reason = FAIL aws-lc-rs verification ({ $kind }): FAILED - { $reason }
diag-sig-header = === SIGNATURE ANALYSIS ===
diag-cred-id-header = === CREDENTIAL ID CHECK ===
diag-cred-id-match = OK Credential IDs match
diag-cred-id-mismatch = FAIL Credential ID MISMATCH - authenticator used different credential!
diag-summary-header = === SUMMARY ===
diag-summary-lib-ok =
    The ctap-hid-fido2 library CAN verify the signature.
    This suggests the issue is with how we're calling aws-lc-rs.
diag-summary-lib-fail =
    Even the ctap-hid-fido2 library CANNOT verify the signature.
    This suggests a fundamental issue with the { -yubikey } or authentication flow.

    Possible causes:
    1. { -yubikey } firmware bug (especially FIPS models)
    2. Credential corruption on the { -yubikey }
    3. Different key pair being used for signing vs registration
diag-openssl-header =
    === OPENSSL VERIFICATION DATA ===
    To verify with OpenSSL, run these commands:
diag-no-cleanup = Note: Non-resident credential used - no cleanup needed on { -yubikey }.
diag-export-header = === EXPORTING FIXTURE ===
diag-fixture-saved = Fixture saved to: { $path }
diag-err-registration = Registration failed - check PIN and touch { -yubikey }
diag-err-attestation = Attestation verification failed!
diag-err-no-attested-data = No attested credential data in auth_data!
diag-err-cose-parse = Failed to parse COSE key
diag-err-cose-not-map = COSE key is not a map
diag-err-missing-x = Missing x coordinate
diag-err-missing-y = Missing y coordinate
diag-err-coord-length = Invalid coordinate lengths: x={ $x_len }, y={ $y_len }
diag-err-authentication = Authentication failed
diag-err-no-assertion = No assertion returned
diag-err-fixture-save = Failed to save fixture: { $reason }

## aws command

cmd-aws-console-about = Open the AWS Management Console in your browser

arg-aws-sso-session-help = SSO session name from ~/.aws/config (default: first found).
arg-aws-console-role-help = AWS IAM role ARN to assume (auto-detected from ~/.aws/config if not specified).

aws-err-sso-session-not-found =
    SSO session '{ $name }' not found in ~/.aws/config.
    Run 'aws configure sso' or check --sso-session.
aws-err-no-sso-session =
    No SSO session found in ~/.aws/config.
    Run 'aws configure sso' first.
aws-using-sso-session = Using SSO session '{ $name }'. Specify --sso-session to use a different one.
aws-err-not-configured =
    AWS not configured.
    Run '{ -cmd } setup aws --role <role-arn>' first, or specify --role.
aws-err-agent-idc-readonly-unsupported =
    Coding agent detected ({ $source }): Identity Center portal credentials
    (--account) cannot be restricted to ReadOnlyAccess, unlike the STS --role path.
    Use an STS role (--role <arn>) or a dedicated read-only permission set instead.
aws-err-idc-not-configured =
    Identity Center not configured for this SSO session.
    Run '{ -cmd } setup aws' to complete the setup.

# Retained: exercised by the i18n pluralization test (`every_catalog_key_resolves`).
aws-accounts-summary =
    { $count ->
        [one] { $count } account
       *[other] { $count } accounts
    }

aws-console-opening = Opening AWS Console...
aws-console-browser-failed = Could not open browser automatically. Open the URL above in your browser.
aws-console-err-invalid-role-arn = invalid role ARN
aws-console-err-aws-credentials = failed to get AWS credentials
aws-console-err-serialize-session = failed to serialize session JSON
aws-console-err-signin-request = failed to request signin token
aws-console-err-signin-failed = federation getSigninToken failed ({ $status }): { $body }
aws-console-err-signin-parse = failed to parse signin token response
aws-console-err-invalid-federation-url = invalid federation endpoint URL
aws-console-err-role-required-with-account = --role (permission-set name) is required with --account
arg-aws-console-account-help = AWS account ID for the Identity Center path (interprets --role as a permission-set name).

## setup aws wizard

setup-aws-err-needs-terminal =
    `{ -cmd } setup aws` needs an interactive terminal for guided setup.
    For non-interactive use, pass --role <arn> or --discover.
wizard-aws-prompt-role-arn = Enter the IAM role ARN Vouch should assume
wizard-aws-err-invalid-role-arn = invalid IAM role ARN
wizard-aws-trust-policy-header = Add this trust policy to the role so Vouch can assume it:
wizard-aws-oidc-provider-hint =
    If you have not yet registered Vouch as an OIDC provider, create it once:
      aws iam create-open-id-connect-provider --url { $issuer_url } --client-id-list { $audience }
wizard-aws-press-enter = Press Enter once the policy is applied in AWS...
wizard-aws-err-cancelled = Setup cancelled.
wizard-aws-pattern-select = Choose your AWS access pattern
wizard-aws-pattern-single = Single account (assume one role directly)
wizard-aws-pattern-chain = Management account + role chaining (many accounts)
wizard-aws-pattern-idc = Management account + IAM Identity Center
wizard-aws-prompt-member-role-name = Member-account role name to assume
wizard-aws-prompt-member-role-path = Member-account role path
wizard-aws-permission-policy-header = Attach this permission policy to { $role_arn }:
wizard-aws-prompt-session-name = SSO session name to save this under
wizard-aws-saved-vouch-config = Saved Vouch configuration for session '{ $name }'.
wizard-aws-enumerating-accounts = Enumerating accounts via AWS Organizations...
wizard-aws-no-accounts-found = No active accounts found.
wizard-aws-err-management-role-not-configured =
    No management role configured for this SSO session.
    Run '{ -cmd } setup aws' to complete setup.
wizard-aws-idc-setup-hint =
    In IAM Identity Center, register Vouch as a trusted token issuer and add a
    customer-managed application:
      Issuer URL:  { $issuer_url }
      Aud claim:   { $audience }
    Grant this role sso-oauth:CreateTokenWithIAM on the application.
wizard-aws-prompt-idc-app-arn = Enter the Identity Center customer-managed application ARN
wizard-aws-prompt-session-start-url = SSO start URL
wizard-aws-prompt-session-region = SSO region
wizard-aws-created-sso-session = Created [sso-session { $name }] in ~/.aws/config.

## credential/ssh

# Shared duration renderer ("Xh Ym"). Used wherever an SSH certificate's
# remaining or total lifetime is shown.
credential-ssh-duration = { $hours }h { $minutes }m

credential-ssh-cached-line = SSH certificate still valid ({ $duration } remaining).
credential-ssh-issued-line = SSH certificate provisioned (valid for { $duration }).
credential-ssh-generated-keypair = Generated SSH keypair: { $path }
credential-ssh-not-provisioned = SSH certificate not provisioned ({ $reason }). Run: { -cmd } credential ssh
# Full display block for `{ -cmd } credential ssh` when the cached cert is
# still valid. Translators can re-order lines or rename labels in place
# without coordinating across separate keys.
credential-ssh-cached-display =
    SSH certificate still valid.
      Certificate: { $cert_path }
      Serial: { $serial }
      Principals: { $principals }
      Remaining: { $remaining }

    Use --force to re-issue.
# Full block emitted when a new SSH keypair is generated alongside the
# certificate. Translators see the heading and both "Created:" lines (with
# their specific file paths) together in one message.
credential-ssh-keypair-created =
    Generating new SSH keypair...
    Created: { $private_path }
    Created: { $public_path }
# Full display block for a freshly-issued certificate.
credential-ssh-issued-display =
    SSH certificate issued successfully!
      Certificate: { $cert_path }
      Serial: { $serial }
      Principals: { $principals }
      Valid for: { $valid_for }
# Full block emitted when the agent picked up the new credentials. Includes
# the displayed socket path and the matching export command in one message so
# translators see the whole "credentials in agent, here's how to use them"
# flow without coordinating across 3 keys. The `export` line is literal shell
# text the user copy-pastes; translators leave it alone, same as `{ -cmd }`.
credential-ssh-agent-loaded =
    SSH credentials loaded into agent.
      SSH agent socket: { $socket_path }

    To use the agent, set SSH_AUTH_SOCK:
      export SSH_AUTH_SOCK={ $socket_path }

# Full block when the agent isn't available. The Host/IdentityFile/CertificateFile
# stanza is literal SSH client config; translators leave it as-is, same as
# any other config snippet in this catalog.
credential-ssh-hint-add-config =
    To use this certificate, add to your ~/.ssh/config:

      Host *
          IdentityFile { $key_path }
          CertificateFile { $cert_path }

## credential helpers (shared)

# Surfaced to stderr by credential helpers (Docker, Git, …) when the user
# hasn't run `{ -cmd } enroll`. The leading "vouch:" prefix is the credential-
# helper convention parent tools recognize.
credential-helper-err-not-configured = vouch: not configured - run '{ -cmd } enroll' first

## credential/docker

credential-docker-err-unknown-registry = vouch: unknown registry type for URL: { $url }

## credential/github

credential-github-err-create-client = vouch: failed to create client: { $error }
credential-github-err-fetch-token = vouch: failed to get { -github } token: { $error }

## credential/cargo

# Emitted when cargo invokes the credential helper for an unsupported login
# action ({ -cmd } manages auth, not `cargo login`).
# Full block when cargo asks the helper to log in (which vouch doesn't
# support — auth happens via `{ -cmd } login`). The shell snippet lives in
# the message so translators see the "do this instead" instruction
# together.
credential-cargo-login-needed =
    To authenticate with registry '{ $registry }', run:

        { -cmd } login

credential-cargo-login-hint = use '{ -cmd } login' to authenticate
credential-cargo-logout =
    Note: 'cargo logout' does not affect your { -product } session for registry '{ $registry }'.
    To fully log out, run: { -cmd } logout

## setup command

cmd-setup-aws-about = Configure AWS CLI/SDK to use { -product } credentials
cmd-setup-ssh-about = Configure SSH to use { -product } certificates
cmd-setup-github-about = Configure Git to use { -product } for GitHub credentials
cmd-setup-eks-about = Configure kubectl to use { -product } credentials for Amazon EKS clusters
cmd-setup-k8s-about = Configure kubectl to use { -product } OIDC credentials for generic Kubernetes clusters
cmd-setup-docker-about = Configure Docker to use { -product } for container registry authentication
cmd-setup-cargo-about = Configure Cargo to use { -product } for private registry authentication
cmd-setup-codecommit-about = Configure Git to use { -product } for AWS CodeCommit credentials
cmd-setup-ssm-about = Configure SSH for AWS Systems Manager Session Manager
cmd-setup-anthropic-about = Configure Anthropic (Claude) Workload Identity Federation
cmd-setup-anthropic-long-about =
    Persists federation parameters to `~/.config/vouch/config.json` for use by
    `{ -cmd } credential anthropic`. This is the workload path: the
    minted token acts as a non-human service account, intended for
    CI/headless automation. It does not configure Claude Code.
cmd-setup-openai-about = Configure OpenAI Workload Identity Federation
cmd-setup-openai-long-about =
    Persists federation parameters to `~/.config/vouch/config.json` AND
    auto-configures the OpenAI Codex CLI by writing a
    `[model_providers.vouch]` block (with refreshing auth
    command) into `~/.codex/config.toml` and setting it as the
    top-level `model_provider`.

    If Codex already has a different `model_provider` or a
    conflicting `vouch` provider block, the command errors —
    pass `--force` to overwrite.
cmd-setup-codeartifact-about = Configure a package manager for AWS CodeArtifact

# setup/aws arg help
arg-setup-aws-profile-help = AWS profile name to configure. Defaults to "vouch" if not specified.
arg-setup-aws-role-help = AWS IAM role ARN to assume. Required unless --discover is set.
arg-setup-aws-region-help = AWS region to set in the profile.
arg-setup-aws-discover-help = Discover accounts and roles via SSO and generate profiles automatically.

# setup/ssh arg help
arg-setup-ssh-hosts-help = Host patterns to trust with this CA (e.g., "*.example.com"). If specified, adds entry to ~/.ssh/known_hosts.

# setup/github arg help
arg-setup-github-host-help = GitHub host to configure (default: github.com).
arg-setup-github-configure-help = Automatically configure git (otherwise just show instructions).

# setup/eks arg help
arg-setup-eks-cluster-help = EKS cluster name.
arg-setup-eks-region-help = AWS region (auto-detected from AWS profile or environment if not specified).
arg-setup-eks-profile-help = AWS profile to use (defaults to auto-detected { -cmd } profile).
arg-setup-eks-kubeconfig-help = Path to kubeconfig file (defaults to ~/.kube/config).

# setup/k8s arg help
arg-setup-k8s-cluster-help = Kubernetes cluster name.
arg-setup-k8s-server-help = Kubernetes API server URL (e.g., https://k8s.example.com:6443).
arg-setup-k8s-ca-help = Path to the cluster's certificate authority file (PEM format).
arg-setup-k8s-audience-help = OIDC audience (must match --oidc-client-id on the API server). Defaults to "kubernetes".
arg-setup-k8s-kubeconfig-help = Path to kubeconfig file (defaults to ~/.kube/config).

# setup/docker arg help
arg-setup-docker-registries-help = Container registries to configure (e.g., ghcr.io).
arg-setup-docker-configure-help = Automatically configure Docker (otherwise just show instructions).

# setup/cargo arg help
arg-setup-cargo-registry-help = Registry name to configure (if not specified, configures global provider).
arg-setup-cargo-configure-help = Write the configuration (otherwise just show instructions).

# setup/codecommit arg help
arg-setup-codecommit-region-help = AWS region (default: wildcard matching all regions).
arg-setup-codecommit-profile-help = AWS profile to use (defaults to auto-detected { -cmd } profile).
arg-setup-codecommit-configure-help = Automatically configure git (otherwise just show instructions).

# setup/ssm arg help
arg-setup-ssm-profile-help = AWS profile to use (defaults to auto-detected { -cmd } profile).
arg-setup-ssm-region-help = AWS region (auto-detected from AWS profile or environment if not specified).
arg-setup-ssm-hosts-help = SSH host patterns for SSM proxying (i-* = EC2 instances, mi-* = managed instances).
arg-setup-ssm-force-help = Replace existing { -product } SSM configuration if present.

# setup/anthropic arg help
arg-setup-anthropic-federation-rule-id-help = Anthropic federation rule ID (`fdrl_...`).
arg-setup-anthropic-organization-id-help = Anthropic organization ID (UUID).
arg-setup-anthropic-service-account-id-help = Anthropic service account ID (`svac_...`).
arg-setup-anthropic-workspace-id-help = Anthropic workspace ID (`wrkspc_...`).
arg-setup-anthropic-audience-help = `aud` claim to request on the assertion (optional).
arg-setup-anthropic-token-endpoint-help = Token endpoint override (defaults to Anthropic's public endpoint).

# setup/openai arg help
arg-setup-openai-identity-provider-id-help = OpenAI Workload Identity Provider ID for the { -product } issuer.
arg-setup-openai-service-account-id-help = OpenAI service account ID.
arg-setup-openai-audience-help = `aud` claim to request on the assertion (matches OpenAI's configured audience for this provider).
arg-setup-openai-token-endpoint-help = Token endpoint override (defaults to OpenAI's public endpoint).
arg-setup-openai-force-help = Overwrite an existing Codex `model_provider` or `vouch` provider block.

# setup/codeartifact arg help
arg-setup-codeartifact-tool-help = Package manager to configure (cargo, pip, npm).
arg-setup-codeartifact-domain-help = CodeArtifact domain name (or use --profile / saved default).
arg-setup-codeartifact-domain-owner-help = AWS account ID that owns the domain.
arg-setup-codeartifact-region-help = AWS region.
arg-setup-codeartifact-repository-help = CodeArtifact repository name.
arg-setup-codeartifact-profile-help = Named CodeArtifact profile to use / save.

## Shared setup helpers

setup-err-load-config = failed to load config - run '{ -cmd } enroll' first
setup-err-load-vouch-config = failed to load { -product } config
setup-err-not-configured = not configured - run '{ -cmd } enroll' first
setup-err-anthropic-not-enrolled = not configured — run '{ -cmd } enroll' first
setup-err-no-home = could not determine home directory

## server-url validation

# Emitted when `--allow-insecure` lets the CLI talk to an http:// server.
# Newline-separated so each line surfaces independently in the terminal.
server-url-warn-insecure =
    WARNING: Using insecure HTTP connection to { $url }.
    Credentials will be transmitted in plaintext.

## clock-skew warning

# Emitted when CLI ↔ server clock skew exceeds the threshold. Direction
# branches on the boolean `local_behind` so translators can place the
# adverb where it reads naturally; the platform sync hint follows on the
# next line so translators can re-order or rephrase it within the same
# message rather than juggling two keys.
http-warn-clock-skew =
    { $local_behind ->
        [true] Warning: system clock is { $secs }s behind the server. Signed requests may fail.
       *[other] Warning: system clock is { $secs }s ahead of the server. Signed requests may fail.
    }
    Sync your clock — on Windows: Settings → Time & Language → Date & Time → "Sync now"; on macOS: `sudo sntp -sS time.apple.com`.

## install-path warnings

# Emitted at setup time when the resolved vouch binary path is version-pinned
# (Homebrew Cellar, Nix store, Scoop apps) and therefore likely to break on
# the next package upgrade. Embedded shell commands stay as written so users
# can copy-paste them verbatim. The platform-specific hint is computed in Rust
# and passed in as `$hint` so this remains a single multi-line message.
install-path-warn-version-pinned =
    Warning: writing a version-pinned path to your config:
      { $path }
    { $hint }
install-path-warn-bare =
    Warning: could not determine an absolute path to the { -cmd } binary.
    Writing bare '{ $binary }' to the config; this relies on $PATH at the time credentials are fetched.
    If credential-fetching commands fail with "executable not found", hand-edit the config to use an absolute path.
install-path-hint-homebrew =
    This path will be removed by `brew upgrade`. Ensure { $stable } exists (`brew link { -cmd }`) and re-run `{ -cmd } setup ...` to use it instead.
install-path-hint-scoop =
    This path will be removed by `scoop update`. Ensure { $stable } exists (`scoop reset { -cmd }`) and re-run `{ -cmd } setup ...` to use it instead.
install-path-hint-nix =
    Nix store paths are content-addressed and may be garbage-collected. Ensure { $stable } exists and re-run `{ -cmd } setup ...` to use it instead.

## setup/aws

setup-aws-profile-already-exists =
    Profile [{ $profile }] already exists in ~/.aws/config.
    To update it, edit ~/.aws/config directly.

# Full output block when an existing { -product } profile already targets the
# requested role. Shell command sits inside the block as literal text so the
# whole user-facing instruction stays one message — translators see the flow
# (prose → command → end) without juggling multiple keys.
setup-aws-already-configured-block =
    Already configured: profile [{ $profile }] uses role { $role_arn }

    Use it with:
      aws --profile { $profile } sts get-caller-identity

# Full post-setup instructions block. Embedded shell commands and the doc URL
# stay as literal text in the message body — translators understand they're
# code/data and don't translate them, exactly like the `{ $profile }`
# placeable. Keeping the entire block as one message means a translator can
# re-flow the prose and adjust spacing without coordinating across 5 keys.
setup-aws-added-profile-block =
    Added profile [{ $profile }] to ~/.aws/config

    Use AWS CLI with the profile:

      aws --profile { $profile } sts get-caller-identity

    Or set the environment variable:

      export AWS_PROFILE={ $profile }
      aws sts get-caller-identity

    Prerequisites:
      1. You must be logged in to { -product }: { -cmd } login
      2. The AWS role must trust the { -product } OIDC provider

    To configure AWS role trust policy, see:
      https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html
setup-aws-discover-skipped = Skipped [{ $profile }] — already exists
setup-aws-discover-added = Added profile [{ $profile }] → { $role_arn }
# Numeric arms ride as FluentValue::Number so locales can plural-form the
# noun (e.g. "0 profil/1 profil/2 profile" rules).
setup-aws-discover-summary = { $created ->
        [one] { $created } profile created,
       *[other] { $created } profiles created,
    } { $skipped ->
        [one] { $skipped } skipped
       *[other] { $skipped } skipped
    }
setup-aws-err-no-sso-session = No SSO session found in ~/.aws/config. Run 'aws configure sso' first.
setup-aws-err-sso-expired = SSO session expired or missing. Run '{ -cmd } aws login' first.

## setup/anthropic

setup-anthropic-success-block =
    Anthropic (Claude) Workload Identity Federation configured.

      Federation params: { $config_path }

    This mints a service-account token for CI/headless automation.
    Get a token:
      { -cmd } login                 # { -yubikey } tap, once per session
      { -cmd } credential anthropic  # prints sk-ant-oat01-...

    Smoke test:
      curl -sS https://api.anthropic.com/v1/messages \
        -H "authorization: Bearer $({ -cmd } credential anthropic)" \
        -H "anthropic-version: 2023-06-01" \
        -H "content-type: application/json" \
        -d '{"{"}"model":"claude-sonnet-4-6","max_tokens":64,"messages":[{"{"}"role":"user","content":"hi"{"}"}]{"}"}'

## setup/cargo

setup-cargo-header =
    Cargo Credential Provider Setup
    ================================
setup-cargo-already-registry = { -product } is already configured for registry '{ $name }'
setup-cargo-already-global = { -product } is already configured as global credential provider
setup-cargo-config-file = Configuration file: { $path }
setup-cargo-configured-registry = Cargo configured for registry '{ $name }'
setup-cargo-configured-global = Cargo configured with global credential provider
setup-cargo-config-added = Configuration added to: { $path }
# Full "show me what to add" block for a specific registry. The TOML stanza
# is part of the message so translators see (and can adjust spacing of) the
# whole config-instructions flow in one place. Indented `[…]` lines start with
# `{""}` because Fluent treats a leading `[` on a continuation line as a
# variant key — the empty placeable forces TextElement parsing.
setup-cargo-instructions-specific =
    Add to ~/.cargo/config.toml:

    {""}[registries.{ $registry }]
    credential-provider = { $command }

    Or run: { -cmd } setup cargo --configure

# Full block for global credential-providers configuration. Same shape as
# `setup-cargo-instructions-specific`; the per-registry commented example
# lives inside the message so translators can rephrase the "Or for a
# specific registry" hint without coordinating with a sibling key.
setup-cargo-instructions-global =
    Add to ~/.cargo/config.toml:

    {""}[registry]
    global-credential-providers = { $command }

    {""}# Or for a specific registry:
    {""}# [registries.my-private-registry]
    {""}# credential-provider = { $command }

    Or run: { -cmd } setup cargo --configure
setup-cargo-more-info =
    For more information, see:
      https://doc.rust-lang.org/cargo/reference/registry-authentication.html

## setup/github

setup-github-header =
    GitHub Credential Setup
    =======================
setup-github-not-configured-block =
    GitHub App is not configured on the server.
    Contact your administrator to enable GitHub integration.
setup-github-org-not-connected-block =
    Your organization has not connected GitHub.
    An organization admin needs to visit: { $server }/github/connect
setup-github-all-suspended-block =
    All GitHub installations are currently suspended.
    Contact your administrator to resolve this.
setup-github-not-logged-in-block =
    Login status: Not logged in

    Run '{ -cmd } login' first to authenticate.
setup-github-could-not-check = Note: Could not check GitHub status: { $reason }
# Fluent selector: $configured is a stringified bool ("true" / "false").
# Translators can localize the visible word without changing call sites.
setup-github-app-configured =
    GitHub App configured: { $configured ->
        [true] Yes
       *[false] No
    }
setup-github-org-connected =
    Organization connected: { $connected ->
        [true] Yes
       *[false] No
    }
setup-github-accounts-header = Connected GitHub accounts:
# $suspended is a stringified bool too — appends "(SUSPENDED)" when true.
setup-github-account-line =
    { $indent }- { $login } ({ $kind }){ $suspended ->
        [true] { " " }(SUSPENDED)
       *[false] { "" }
    }
setup-github-existing-warning-block =
    Warning: Existing credential helper detected: { $existing }
    This may conflict with { -product }.
setup-github-err-run-config = failed to run git config
setup-github-err-helper = failed to configure git credential helper
setup-github-configured-block =
    Git configured for { $host }

    Configuration added:
      { $key } = { $value }
# Full "show me what to add" block when --configure isn't passed. The two
# git config lines live inside the message so translators see the heading
# and the snippet together. The indented `[…]` line starts with `{""}` —
# Fluent treats a leading `[` on a continuation line as a variant key
# (deprecated syntax) unless an empty placeable forces TextElement parsing.
setup-github-add-to-gitconfig =
    Add to ~/.gitconfig:

      {""}[credential "https://{ $host }"]
          helper = { $helper_command }

    Or run: { -cmd } setup github --configure
setup-github-to-verify =
    To verify, run:
      git ls-remote https://{ $host }/YOUR-ORG/YOUR-REPO.git

## setup/docker

setup-docker-header =
    Docker Credential Helper Setup
    ==============================
setup-docker-configured = Docker credential helper configured successfully.
setup-docker-no-registries-add =
    To configure registries, add them to ~/.docker/config.json:
setup-docker-configured-registries-header = Configured registries:
setup-docker-registry-line = { $indent }- { $registry }
setup-docker-step1-block =
    Step 1: Create symlink for docker-credential-vouch

      ln -sf "{ $vouch_path }" "{ $symlink_path }"
setup-docker-step2-header =
    Step 2: Configure Docker to use the credential helper

      Add to ~/.docker/config.json:
setup-docker-tail-block =
    Or run: { -cmd } setup docker --configure [REGISTRIES...]

    Examples:
      { -cmd } setup docker --configure ghcr.io
      { -cmd } setup docker --configure 123456789012.dkr.ecr.us-east-1.amazonaws.com
      { -cmd } setup docker --configure 123456789012.dkr.ecr.us-west-2.amazonaws.com
setup-docker-supported-block =
    Supported registries:
      - AWS ECR:     *.dkr.ecr.*.amazonaws.com
      - GitHub:      ghcr.io
setup-docker-updated-file = Updated: { $path }
setup-docker-err-create-dir = failed to create { $path }
setup-docker-err-read = failed to read { $path }
setup-docker-err-parse = failed to parse { $path }
setup-docker-err-serialize = failed to serialize Docker config
setup-docker-err-write = failed to write { $path }

## setup/kubernetes

setup-k8s-header =
    Kubernetes OIDC Setup
    =====================
setup-k8s-summary =
    Cluster:   { $cluster }
    Server:    { $server }
    Audience:  { $audience }
    { -product }:     { $vouch }
setup-k8s-updated-block =
    Updated kubeconfig: { $kubeconfig }
      Cluster: { $cluster } ({ $server })
      User:    { $user_name } (via { -cmd } credential k8s)
      Context: { $context }
setup-k8s-tail-block =
    To use:
      kubectl config use-context { $context }
      kubectl get pods

    Prerequisites:
      1. Run '{ -cmd } login' to authenticate
      2. Kubernetes API server must be configured with --oidc-issuer-url={ $vouch } --oidc-client-id={ $audience }
setup-k8s-err-read-ca = failed to read certificate authority file: { $path }

## setup/openai

setup-openai-success-block =
    OpenAI Workload Identity Federation configured.

      Federation params: ~/.config/vouch/config.json
      Codex provider block: { $config_path } ([model_providers.{ $provider_id }])

    NOTE: OpenAI must onboard the { -product } issuer as a workload identity provider
          before this works — custom OIDC issuers are not self-service. Contact
          OpenAI to register your { -product } base URL.

    Get a token:
      { -cmd } login              # { -yubikey } tap, once per session
      { -cmd } credential openai  # prints a short-lived OpenAI access token

    Ensure OPENAI_API_KEY is UNSET in every environment Codex runs in —
    it shadows the configured auth command.

    Note: the [model_providers.vouch] block is owned by `{ -cmd } setup openai` —
    re-running this command overwrites it. Edit the top-level `model_provider`
    if you want to switch Codex back to a different provider.

setup-openai-err-conflict =
    Codex already has model_provider = { $existing } in { $path }.

    Remove the `model_provider` entry from config.toml, or re-run
    `{ -cmd } setup openai --force` to switch the default to `{ $provider_id }`.
setup-openai-err-providers-not-table =
    cannot configure OpenAI: `model_providers` exists in
    ~/.codex/config.toml but is not a table. Remove or rename
    the `model_providers` entry and try again.
setup-openai-err-read = failed to read { $path }
setup-openai-err-parse = failed to parse { $path }
setup-openai-err-create-dir = failed to create { $path }
setup-openai-err-write = failed to write { $path }

## setup/ssh

setup-ssh-downloading-ca = Downloading SSH CA public key from server...
setup-ssh-saved-ca = Saved CA public key: { $path }
setup-ssh-complete-block =
    SSH CA setup complete!

    To trust user certificates signed by this CA, configure your SSH servers:

      1. Copy the CA public key to each server:
         scp { $ca_path } root@server:/etc/ssh/vouch_ca.pub

      2. Create /etc/ssh/sshd_config.d/99-vouch-ca.conf with:

         TrustedUserCAKeys /etc/ssh/vouch_ca.pub

      3. Validate the configuration and reload sshd:

         sudo sshd -t && sudo systemctl reload sshd

    Users can then authenticate with:
      { -cmd } login
      { -cmd } credential ssh
      ssh user@server

setup-ssh-stale-agent-rewrite = Updated stale { -product } IdentityAgent path in { $config_path } -> { $agent_socket }
setup-ssh-already-configured = SSH config already configured for { -product }
setup-ssh-updated-config = Updated SSH config: { $path }
setup-ssh-added-host-agent = { $indent }Added { -product } IdentityAgent for specified hosts
setup-ssh-added-identity-block =
    { $indent }Added { -product } IdentityFile and CertificateFile
    { $indent }Note: IdentityAgent not set globally to avoid conflicts with other SSH agents.
    { $indent }To use the { -product } agent for specific hosts, re-run with: { -cmd } setup ssh --hosts "pattern"
setup-ssh-ca-already-trusted = CA already trusted in known_hosts
setup-ssh-added-ca-trust = Added CA to known_hosts for hosts: { $hosts }
setup-ssh-err-get-ca = failed to get SSH CA public key
setup-ssh-err-write-ca = failed to write { $path }
setup-ssh-err-read-config = failed to read { $path }
setup-ssh-err-write-config = failed to write { $path }
setup-ssh-err-ca-empty = CA public key file is empty
setup-ssh-err-ca-invalid = CA public key file does not contain a valid key
setup-ssh-err-lock-file = failed to open lock file { $path }
setup-ssh-err-lock-acquire = failed to acquire known_hosts lock
setup-ssh-err-agent-socket = failed to resolve SSH agent socket path

## setup/ssm

setup-ssm-err-empty = { $label } must not be empty
setup-ssm-err-newline = { $label } must not contain newline characters
setup-ssm-err-invalid-char =
    { $label } contains invalid character '{ $char }'.
    Only alphanumeric characters, spaces, underscores, hyphens, dots,
    asterisks, and question marks are allowed.
setup-ssm-err-plugin-missing =
    session-manager-plugin not found on PATH.

    Install it from:
      https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html

setup-ssm-header =
    AWS SSM Setup
    =============
setup-ssm-summary =
    Profile:  { $profile }
    Region:   { $region }
    Hosts:    { $hosts }

setup-ssm-already-configured = SSH config already contains { -product } SSM configuration.
setup-ssm-existing-profile = { $indent }Profile: { $value }
setup-ssm-existing-region = { $indent }Region:  { $value }
setup-ssm-existing-hosts = { $indent }Hosts:   { $value }
setup-ssm-reconfigure-hint = To reconfigure, re-run with --force or remove the '{ $marker }' block from { $path }.
setup-ssm-replacing = Replacing existing { -product } SSM configuration (--force).
setup-ssm-result-block =
    Updated SSH config: { $path }

    To use:
      { -cmd } login
      ssh ec2-user@i-0abc123def456

    Prerequisites:
      1. Run '{ -cmd } login' to authenticate
      2. EC2 instances must have the SSM agent installed and an IAM instance
         profile with SSM permissions
setup-ssm-undo =
    To undo:
      Remove the '{ $marker }' block from { $path }
setup-ssm-err-read = failed to read { $path }
setup-ssm-err-write = failed to write { $path }

## setup/eks

setup-eks-err-aws-not-configured = AWS not configured. Run '{ -cmd } setup aws --role <role-arn>' first.
setup-eks-header-block =
    Amazon EKS Setup
    ================

    Cluster:  { $cluster }
    Region:   { $region }
    Profile:  { $profile }
setup-eks-fetching = Fetching cluster details...
setup-eks-result-block =
    Updated kubeconfig: { $kubeconfig }
      Cluster: { $cluster } ({ $endpoint })
      User:    { $user_name } (via { -cmd } credential eks)
      Context: { $context }

    To use:
      kubectl config use-context { $context }
      kubectl get pods

    Prerequisites:
      1. Run '{ -cmd } login' to authenticate
      2. EKS Access Entry must exist for the IAM role in your AWS profile

## setup/codecommit

setup-codecommit-header =
    CodeCommit Credential Setup
    ===========================
setup-codecommit-aws-profile = AWS profile: { $profile }
setup-codecommit-aws-role = AWS role:    { $role }
setup-codecommit-err-helper-pattern = failed to configure git credential helper for { $pattern }
setup-codecommit-err-http-path = failed to set useHttpPath for { $pattern }
setup-codecommit-success-block =
    Git configured for CodeCommit.

    Credential helper (HTTPS URLs):
# Two git-config lines emitted per CodeCommit URL pattern after `git config`
# succeeds. Stays as a single multi-line message because the pair is always
# written together and reordering or rephrasing one without the other would
# leave the user with an inconsistent confirmation.
setup-codecommit-helper-pair =
    { $indent }credential.{ $pattern }.helper = { $helper }
    { $indent }credential.{ $pattern }.useHttpPath = true
setup-codecommit-remote-helper-block =
    Remote helper (codecommit:// URLs):
      { $symlink } -> { $vouch }
setup-codecommit-step1-block =
    Step 1: Create symlink for codecommit:// URL support

      ln -sf "{ $vouch }" "{ $symlink }"
setup-codecommit-step2 =
    Step 2: Configure git credential helper for HTTPS URLs

      Add to ~/.gitconfig:
setup-codecommit-or-run = Or run: { -cmd } setup codecommit --configure
setup-codecommit-tail-block =
    To verify, run:
      git ls-remote https://git-codecommit.{ $region }.amazonaws.com/v1/repos/YOUR-REPO
      git ls-remote codecommit::{ $region }://YOUR-REPO

    To undo:
      rm "{ $path }"
# Loop body: emitted once per credential pattern after the tail block above.
setup-codecommit-undo-config = { $indent }git config --global --remove-section credential."{ $pattern }"
setup-codecommit-err-aws-not-configured = AWS not configured. Run '{ -cmd } setup aws --role <role-arn>' first.
setup-codecommit-err-profile-not-found =
    AWS profile '{ $profile }' not found in ~/.aws/config.
    Run '{ -cmd } setup aws --role <role-arn>' first.
setup-codecommit-err-no-vouch-profile =
    No { -product } AWS profile found in ~/.aws/config.
    Run '{ -cmd } setup aws --role <role-arn>' first.
setup-codecommit-err-run-config = failed to run git config
setup-codecommit-warn-existing-block =
    Warning: Existing CodeCommit credential helper detected:
      { $line }
    This may conflict. Consider removing it.

## setup/codeartifact

setup-ca-header =
    CodeArtifact Setup
    ==================
setup-ca-saved-profile = Saved CodeArtifact profile '{ $name }' to config.
setup-ca-cargo-usage =
    Usage:
      cargo build --registry { $name }
      cargo publish --registry { $name }

    Cargo will automatically call { -product } to obtain a fresh CodeArtifact
    token each time it needs to authenticate.
setup-ca-cargo-already-block =
    { -product } is already configured for registry '{ $name }'

    Configuration file: { $path }
setup-ca-cargo-configured-block =
    Cargo configured for CodeArtifact registry '{ $name }'
    Configuration written to: { $path }
setup-ca-pip-auto-block =
    pip will automatically call { -product } to obtain a fresh CodeArtifact
    token each time it needs to authenticate. No more 12-hour token expiry!
setup-ca-pip-wrote = Wrote pip config: { $path }
setup-ca-keyring-conflict-block =
    Note: { $path } already exists (not managed by vouch).
    To use { -cmd } for CodeArtifact authentication, you can:
      1. Rename the existing keyring and re-run this command:
         mv { $path } { $path }.bak
      2. Or manually create a symlink to vouch:
         ln -sf "{ $vouch_path }" "{ $path }"
setup-ca-uv-auto-block =
    uv will automatically call { -product } to obtain a fresh CodeArtifact
    token each time it needs to authenticate. No more 12-hour token expiry!

    Note: If you also use pip, run `{ -cmd } setup codeartifact --tool pip` to
    configure pip separately (uv does not read pip.conf).
setup-ca-uv-wrote = Wrote uv config: { $path }
setup-ca-npm-block =
    Registry URL: { $url }

    Note: Unlike Cargo and pip, npm does not support dynamic credential
    helpers. The token written to ~/.npmrc expires in ~12 hours.
    To refresh: { -cmd } setup codeartifact --tool npm --repository { $repository }

    Tip: pnpm supports dynamic credential helpers. Use --tool pnpm for
    automatic token refresh without manual re-login.
setup-ca-npm-wrote = Wrote npm config: { $path }
setup-ca-npmrc-conflict-block =
    Note: ~/.npmrc has an existing { $other_tool } configuration for this registry.
    It will be replaced. npm and pnpm use different auth mechanisms
    (_authToken vs tokenHelper) and cannot coexist for the same registry.
setup-ca-pnpm-auto-block =
    pnpm will automatically call { -product } to obtain a fresh CodeArtifact
    token each time it needs to authenticate. No more 12-hour token expiry!
setup-ca-pnpm-conflict-block =
    Note: { $path } already exists (not managed by vouch).
    To use { -cmd } for pnpm CodeArtifact authentication, either:
      1. Rename the existing file and re-run this command:
         mv { $path } { $path }.bak
      2. Or manually create a symlink to vouch:
         ln -sf "{ $vouch_path }" "{ $path }"
setup-ca-pnpm-wrote = Wrote pnpm config: { $path }
setup-ca-refreshed-npmrc = Refreshed CodeArtifact token in ~/.npmrc
setup-ca-err-save-profile = failed to save CodeArtifact profile
setup-ca-err-create-dir = failed to create { $path }
setup-ca-err-read = failed to read { $path }
setup-ca-err-parse = failed to parse { $path }
setup-ca-err-write = failed to write { $path }
setup-ca-err-serialize-pip = failed to serialize pip config for { $path }
setup-ca-err-fetch-token = failed to get CodeArtifact token

## setup/kubeconfig

setup-kc-err-read = failed to read kubeconfig: { $path }
setup-kc-err-parse = failed to parse kubeconfig: { $path }
setup-kc-err-serialize = failed to serialize kubeconfig
