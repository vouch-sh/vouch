// Key management page: register, rename, and delete security keys.
//
// The key list is rendered server-side (Askama). Rename submits via a plain
// form POST (see enroll_keys_container.html) — matching the server-rendered,
// redirect-back CRUD pattern used by the admin pages. This script drives the
// flows that must run in the browser — WebAuthn registration, RFC 9470 step-up
// re-authentication, and the click-to-edit toggle for the rename UI — and
// reloads the page on success so the server-rendered list reflects the change.

(function() {
    document.addEventListener('DOMContentLoaded', function() {
        // Event delegation from document keeps a single handler regardless of
        // how many keys are rendered.
        document.addEventListener('click', function(event) {
            var addBtn = event.target.closest('[data-action="add-key"]');
            if (addBtn) {
                addNewKey(addBtn);
                return;
            }
            var deleteBtn = event.target.closest('[data-action="delete"]');
            if (deleteBtn) {
                deleteKey(deleteBtn.dataset.keyId, deleteBtn.dataset.keyName);
                return;
            }
            var renameBtn = event.target.closest('[data-action="rename"]');
            if (renameBtn) {
                enterEditMode(renameBtn.closest('[data-key-id]'));
                return;
            }
            var cancelBtn = event.target.closest('[data-action="cancel-rename"]');
            if (cancelBtn) {
                exitEditMode(cancelBtn.closest('.key-rename-form'), true);
            }
        });

        // Esc reverts and exits edit mode; Enter falls through to native submit.
        document.addEventListener('keydown', function(event) {
            if (event.key !== 'Escape') return;
            var input = event.target.closest('.key-name-input');
            if (!input) return;
            event.preventDefault();
            exitEditMode(input.closest('.key-rename-form'), true);
        });

        // Clicking outside the input cancels the edit (no silent autosave).
        // The mousedown handler on Save/Cancel keeps focus on the input so this
        // blur fires only for genuine outside clicks.
        document.addEventListener('focusout', function(event) {
            var input = event.target.closest('.key-name-input');
            if (!input) return;
            var form = input.closest('.key-rename-form');
            if (!form || form.classList.contains('hidden')) return;
            exitEditMode(form, true);
        });

        // Keep focus on the input when the user clicks Save or Cancel — without
        // this, focusout would fire on mousedown and cancel before the click
        // submit runs.
        document.addEventListener('mousedown', function(event) {
            var btn = event.target.closest('.key-rename-save, .key-rename-cancel');
            if (btn) event.preventDefault();
        });
    });

    function enterEditMode(card) {
        if (!card) return;
        var displayRow = card.querySelector('.key-name-display-row');
        var form = card.querySelector('.key-rename-form');
        if (!displayRow || !form) return;
        displayRow.classList.remove('flex');
        displayRow.classList.add('hidden');
        form.classList.remove('hidden');
        form.classList.add('flex');
        var input = form.querySelector('.key-name-input');
        if (input) {
            input.focus();
            input.select();
        }
    }

    function exitEditMode(form, revert) {
        if (!form) return;
        var card = form.closest('[data-key-id]');
        var displayRow = card ? card.querySelector('.key-name-display-row') : null;
        if (revert) {
            var input = form.querySelector('.key-name-input');
            if (input) input.value = form.dataset.originalName || '';
        }
        form.classList.remove('flex');
        form.classList.add('hidden');
        if (displayRow) {
            displayRow.classList.remove('hidden');
            displayRow.classList.add('flex');
        }
    }

    async function deleteKey(keyId, keyName) {
        if (!confirm('Delete key "' + keyName + '"? This action cannot be undone.')) {
            return;
        }

        try {
            var response = await fetch('/enroll/keys/' + keyId, {
                method: 'DELETE',
                credentials: 'same-origin'
            });

            // RFC 9470: Check for step-up authentication challenge
            if (response.status === 401) {
                var wwwAuth = response.headers.get('WWW-Authenticate') || '';
                if (wwwAuth.indexOf('insufficient_user_authentication') !== -1) {
                    // Re-authenticate inline with FIDO2, then retry delete
                    await stepUpReauth();
                    var retryResp = await fetch('/enroll/keys/' + keyId, {
                        method: 'DELETE',
                        credentials: 'same-origin'
                    });
                    if (!retryResp.ok) {
                        var retryErr = await retryResp.json();
                        throw new Error(retryErr.message || 'Failed to delete key after re-authentication');
                    }
                    await finishAfterDelete(retryResp);
                    return;
                }
                // Regular expired session
                window.location.href = '/login';
                return;
            }

            if (!response.ok) {
                var err = await response.json();
                throw new Error(err.message || 'Failed to delete key');
            }

            await finishAfterDelete(response);
        } catch (err) {
            alert('Failed to delete key: ' + err.message);
        }
    }

    // Decide where to go after a successful delete. Deleting the key that the
    // current session is bound to cascade-revokes that session, so a plain
    // reload would bounce through the page GET to /enroll/start. The server
    // reports `current_session_revoked` (true only when the deleted key is this
    // session's own authenticator, not merely any session of that key); when
    // set, go to /login to re-authenticate with a remaining key. Otherwise the
    // session is intact, so just refresh the list.
    async function finishAfterDelete(response) {
        var revoked = false;
        try {
            var result = await response.json();
            revoked = !!(result && result.current_session_revoked);
        } catch (e) {
            revoked = false;
        }
        if (revoked) {
            window.location.href = '/login';
        } else {
            window.location.reload();
        }
    }

    // RFC 9470: Perform inline FIDO2 re-authentication to get a fresh session.
    // Calls the same WebAuthn assertion endpoints as the login page.
    async function stepUpReauth() {
        alert('Deleting a key requires recent authentication.\nPlease touch your security key when prompted.');

        var startResp = await fetch('/login/webauthn/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({})
        });

        if (!startResp.ok) {
            var err = await startResp.json();
            throw new Error(err.message || 'Failed to start re-authentication');
        }

        var options = await startResp.json();
        var challenge = base64urlToBuffer(options.challenge);

        var credential = await navigator.credentials.get({
            publicKey: {
                challenge: challenge,
                rpId: options.rp_id,
                timeout: options.timeout,
                userVerification: options.user_verification,
                hints: ['security-key'],
                allowCredentials: []
            }
        });

        var assertionResponse = credential.response;
        var completeResp = await fetch('/login/webauthn/complete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({
                state: options.state,
                credential_id: bufferToBase64url(credential.rawId),
                authenticator_data: bufferToBase64url(assertionResponse.authenticatorData),
                client_data_json: bufferToBase64url(assertionResponse.clientDataJSON),
                signature: bufferToBase64url(assertionResponse.signature),
                user_handle: bufferToBase64url(assertionResponse.userHandle)
            })
        });

        if (!completeResp.ok) {
            var errResp = await completeResp.json();
            throw new Error(errResp.message || 'Failed to complete re-authentication');
        }
        // Fresh session cookie is now set by the Set-Cookie header
    }

    async function addNewKey(btn) {
        var originalText = btn.textContent;
        btn.disabled = true;
        btn.textContent = 'Starting registration...';

        try {
            var startResp = await fetch('/enroll/webauthn/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin'
            });

            if (!startResp.ok) {
                var err = await startResp.json();
                throw new Error(err.message || 'Failed to start registration');
            }

            var options = await startResp.json();
            btn.textContent = 'Touch your security key...';

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
                    excludeCredentials: excludeCredentials,
                    authenticatorSelection: {
                        authenticatorAttachment: 'cross-platform',
                        userVerification: 'required',
                        residentKey: 'required'
                    },
                    hints: ['security-key'],
                    timeout: 60000,
                    attestation: 'direct'
                }
            });

            btn.textContent = 'Completing registration...';

            var attestationResponse = credential.response;
            var completeResp = await fetch('/enroll/webauthn/complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
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

            window.location.reload();

        } catch (err) {
            alert(webauthnError(err));
            btn.disabled = false;
            btn.textContent = originalText;
        }
    }
})();
