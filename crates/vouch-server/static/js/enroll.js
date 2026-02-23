// Enrollment page WebAuthn registration flow.
// Template variables are passed via data-* attributes on #enroll-config.

(function() {
    var configEl = document.getElementById('enroll-config');
    var stateToken = configEl ? configEl.dataset.state : '';

    async function startRegistration() {
        var btn = document.getElementById('register-btn');
        var status = document.getElementById('status');
        btn.disabled = true;
        btn.classList.add('opacity-60', 'cursor-not-allowed');
        status.className = 'status-waiting mb-6';
        status.textContent = 'Touch your security key when it blinks...';

        try {
            var startResp = await fetch('/enroll/webauthn/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ oidc_state: stateToken })
            });

            if (!startResp.ok) {
                var err = await startResp.json();
                throw new Error(err.message || 'Failed to start registration');
            }

            var options = await startResp.json();

            var challenge = base64urlToBuffer(options.challenge);
            var userId = base64urlToBuffer(options.user_id);

            var excludeCredentials = (options.exclude_credential_ids || []).map(function(id) {
                return {
                    type: 'public-key',
                    id: base64urlToBuffer(id),
                    transports: ['usb', 'nfc']
                };
            });

            var credential = await navigator.credentials.create({
                publicKey: {
                    challenge: challenge,
                    rp: { id: options.rp_id, name: options.rp_name },
                    user: {
                        id: userId,
                        name: options.user_email,
                        displayName: options.user_display_name
                    },
                    pubKeyCredParams: options.algorithms.map(function(alg) {
                        return { type: 'public-key', alg: alg };
                    }),
                    authenticatorSelection: {
                        authenticatorAttachment: 'cross-platform',
                        userVerification: 'required',
                        residentKey: 'required'
                    },
                    excludeCredentials: excludeCredentials,
                    timeout: 60000,
                    attestation: 'direct'
                }
            });

            var attestationResponse = credential.response;
            var completeResp = await fetch('/enroll/webauthn/complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    state: options.state,
                    credential_id: bufferToBase64url(credential.rawId),
                    attestation_object: bufferToBase64url(attestationResponse.attestationObject),
                    client_data_json: bufferToBase64url(attestationResponse.clientDataJSON)
                })
            });

            if (!completeResp.ok) {
                var errResp = await completeResp.json();
                throw new Error(errResp.message || 'Failed to complete registration');
            }

            status.className = 'status-success mb-6';
            status.textContent = 'Success! You can close this window and return to your terminal.';
            btn.style.display = 'none';

        } catch (err) {
            status.className = 'status-error mb-6';
            status.textContent = 'Error: ' + webauthnError(err);
            btn.disabled = false;
            btn.classList.remove('opacity-60', 'cursor-not-allowed');
        }
    }

    document.addEventListener('DOMContentLoaded', function() {
        var btn = document.getElementById('register-btn');
        if (btn) {
            btn.addEventListener('click', startRegistration);
        }
    });
})();
