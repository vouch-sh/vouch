// Login page WebAuthn authentication flow.
// Template variables are passed via data-* attributes on #login-config.

(function() {
    var configEl = document.getElementById('login-config');
    var rpId = configEl ? configEl.dataset.rpId : '';
    var pendingAuth = configEl ? (configEl.dataset.pendingAuth || null) : null;

    async function startLogin() {
        var btn = document.getElementById('login-btn');
        var status = document.getElementById('status');
        btn.disabled = true;
        btn.classList.add('opacity-60', 'cursor-not-allowed');
        status.className = 'status-waiting mb-6';
        status.textContent = t('login-js-touch');

        try {
            var startResp = await fetch('/login/webauthn/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pending_auth: pendingAuth })
            });

            if (!startResp.ok) {
                var err = await startResp.json();
                throw new Error(err.message || t('login-js-start-failed'));
            }

            var options = await startResp.json();
            var challenge = base64urlToBuffer(options.challenge);

            var credentialRequestOptions = {
                publicKey: {
                    challenge: challenge,
                    rpId: options.rp_id,
                    timeout: options.timeout,
                    userVerification: options.user_verification,
                    hints: ['security-key'],
                    allowCredentials: []
                }
            };

            status.textContent = t('login-js-waiting');
            var credential = await navigator.credentials.get(credentialRequestOptions);

            var assertionResponse = credential.response;

            var completeResp = await fetch('/login/webauthn/complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    state: options.state,
                    credential_id: bufferToBase64url(credential.rawId),
                    authenticator_data: bufferToBase64url(assertionResponse.authenticatorData),
                    client_data_json: bufferToBase64url(assertionResponse.clientDataJSON),
                    signature: bufferToBase64url(assertionResponse.signature),
                    user_handle: bufferToBase64url(assertionResponse.userHandle),
                    pending_auth: pendingAuth
                })
            });

            if (!completeResp.ok) {
                var errResp = await completeResp.json();
                throw new Error(errResp.message || t('login-js-complete-failed'));
            }

            var result = await completeResp.json();

            if (result.success && result.redirect_url) {
                status.className = 'status-success mb-6';
                status.textContent = t('login-js-success-redirect');
                window.location.href = result.redirect_url;
            } else if (result.error) {
                throw new Error(result.error);
            } else {
                status.className = 'status-success mb-6';
                status.textContent = t('login-js-signed-in');
                window.location.href = '/';
            }

        } catch (err) {
            status.className = 'status-error mb-6';
            status.textContent = t('login-js-error', { message: webauthnError(err) });
            btn.disabled = false;
            btn.classList.remove('opacity-60', 'cursor-not-allowed');
        }
    }

    document.addEventListener('DOMContentLoaded', function() {
        var btn = document.getElementById('login-btn');
        if (btn) {
            btn.addEventListener('click', startLogin);
        }
    });
})();
