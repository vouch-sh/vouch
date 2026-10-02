# Test-only second catalog, never shipped: embedded only by the
# `#[cfg(test)]` `TestLocalizations` struct below, which lives outside the
# production `i18n/` folder. Its sole purpose is to prove the SAML ACS error
# keys (and the two reused enroll keys) render a non-`en-US` value when a
# non-en-US `I18nContext` is active — the latent defect this bug fixes.
#
# Values are deliberately `[ZZ]`-prefixed so a passing assertion cannot be a
# coincidence of the value matching the English literal.
error-heading = [ZZ] Error
saml-error-missing-relaystate = [ZZ] Missing RelayState parameter
saml-error-invalid-relaystate = [ZZ] Invalid RelayState parameter
saml-error-not-configured = [ZZ] SAML IdP not configured for this state. If using OIDC, responses go to /oauth/callback.
saml-error-auth-failed-title = [ZZ] Authentication Failed
saml-error-verify-failed = [ZZ] Failed to verify SAML response. Please try again.
enroll-error-state-expired = [ZZ] Invalid or expired state
enroll-error-state-verify-failed = [ZZ] Failed to verify state
