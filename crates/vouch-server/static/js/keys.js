// Key management page: list, rename, delete, and register new security keys.
// Template variables are passed via data-* attributes on #keys-config.

(function() {
    var configEl = document.getElementById('keys-config');
    var rpId = configEl ? configEl.dataset.rpId : '';
    var keysData = [];

    document.addEventListener('DOMContentLoaded', function() {
        loadKeys();

        // Static buttons
        var addFirstBtn = document.getElementById('add-first-key-btn');
        if (addFirstBtn) {
            addFirstBtn.addEventListener('click', addNewKey);
        }

        var addAnotherBtn = document.getElementById('add-another-key-btn');
        if (addAnotherBtn) {
            addAnotherBtn.addEventListener('click', addNewKey);
        }

        var retryBtn = document.getElementById('retry-btn');
        if (retryBtn) {
            retryBtn.addEventListener('click', loadKeys);
        }

        // Event delegation for dynamically rendered key items
        var keysItems = document.getElementById('keys-items');
        if (keysItems) {
            keysItems.addEventListener('click', function(event) {
                var deleteBtn = event.target.closest('[data-action="delete"]');
                if (deleteBtn) {
                    deleteKey(deleteBtn.dataset.keyId, deleteBtn.dataset.keyName);
                }
            });

            keysItems.addEventListener('blur', function(event) {
                if (event.target.classList.contains('key-name')) {
                    handleNameBlur(event.target);
                }
            }, true);

            keysItems.addEventListener('keydown', function(event) {
                if (event.target.classList.contains('key-name')) {
                    handleNameKeydown(event, event.target);
                }
            });
        }
    });

    async function loadKeys() {
        showLoading();

        try {
            var response = await fetch('/enroll/keys/api', {
                credentials: 'same-origin'
            });

            if (!response.ok) {
                var err = await response.json();
                throw new Error(err.message || 'Failed to load keys');
            }

            var data = await response.json();
            keysData = data.keys;
            renderKeys();
        } catch (err) {
            showError(err.message);
        }
    }

    function showLoading() {
        document.getElementById('loading').classList.remove('hidden');
        document.getElementById('keys-container').classList.add('hidden');
        document.getElementById('error-state').classList.add('hidden');
    }

    function showError(message) {
        document.getElementById('loading').classList.add('hidden');
        document.getElementById('keys-container').classList.add('hidden');
        document.getElementById('error-state').classList.remove('hidden');
        document.getElementById('error-message').textContent = message;
    }

    function renderKeys() {
        document.getElementById('loading').classList.add('hidden');
        document.getElementById('error-state').classList.add('hidden');
        document.getElementById('keys-container').classList.remove('hidden');

        if (keysData.length === 0) {
            document.getElementById('empty-state').classList.remove('hidden');
            document.getElementById('keys-list').classList.add('hidden');
        } else {
            document.getElementById('empty-state').classList.add('hidden');
            document.getElementById('keys-list').classList.remove('hidden');

            var container = document.getElementById('keys-items');
            container.innerHTML = keysData.map(function(key) {
                return '<div class="border border-vouch-border rounded-lg p-4 bg-vouch-surface" data-key-id="' + key.id + '">' +
                    '<div class="flex items-start justify-between">' +
                        '<div class="flex-1 min-w-0 mr-4">' +
                            '<div class="flex items-center gap-2 mb-1">' +
                                '<input type="text" class="key-name font-medium text-gray-200 bg-transparent border-b border-transparent hover:border-vouch-border focus:border-vouch-accent focus:outline-none transition-colors w-full" value="' + escapeHtml(key.name) + '" data-key-id="' + key.id + '" data-original="' + escapeHtml(key.name) + '" />' +
                            '</div>' +
                            '<div class="text-sm text-gray-500">' +
                                (key.device_model ? '<span class="mr-3">' + escapeHtml(key.device_model) + '</span>' : '') +
                                '<span>Added ' + formatDate(key.created_at) + '</span>' +
                            '</div>' +
                        '</div>' +
                        '<button data-action="delete" data-key-id="' + key.id + '" data-key-name="' + escapeHtml(key.name) + '" class="text-gray-500 hover:text-vouch-error p-1' + (keysData.length <= 1 ? ' hidden' : '') + '" title="Delete key">' +
                            '<svg class="w-5 h-5 pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>' +
                        '</button>' +
                    '</div>' +
                '</div>';
            }).join('');
        }
    }

    async function handleNameBlur(input) {
        var keyId = input.dataset.keyId;
        var original = input.dataset.original;
        var newName = input.value.trim();

        if (newName === original || newName === '') {
            input.value = original;
            return;
        }

        try {
            var response = await fetch('/enroll/keys/' + keyId, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ name: newName })
            });

            if (!response.ok) {
                var err = await response.json();
                throw new Error(err.message || 'Failed to rename key');
            }

            input.dataset.original = newName;
            var key = keysData.find(function(k) { return k.id === keyId; });
            if (key) key.name = newName;
        } catch (err) {
            alert('Failed to rename key: ' + err.message);
            input.value = original;
        }
    }

    function handleNameKeydown(event, input) {
        if (event.key === 'Enter') {
            event.preventDefault();
            input.blur();
        }
        if (event.key === 'Escape') {
            input.value = input.dataset.original;
            input.blur();
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
                    await loadKeysAfterDelete();
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

            await loadKeysAfterDelete();
        } catch (err) {
            alert('Failed to delete key: ' + err.message);
        }
    }

    // Reload key list after a successful delete. If the deleted key was used
    // for the current session, the session was cascade-deleted too — redirect
    // to login so the user can re-authenticate with a remaining key.
    async function loadKeysAfterDelete() {
        var response = await fetch('/enroll/keys/api', {
            credentials: 'same-origin'
        });

        if (response.status === 401) {
            // Session was invalidated (deleted key's session cascade)
            window.location.href = '/login';
            return;
        }

        if (!response.ok) {
            var err = await response.json();
            throw new Error(err.message || 'Failed to load keys');
        }

        var data = await response.json();
        keysData = data.keys;
        renderKeys();
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
        // Fresh vouch_session cookie is now set by the Set-Cookie header
    }

    async function addNewKey(event) {
        var btn = event.currentTarget;
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

            loadKeys();

        } catch (err) {
            alert(webauthnError(err));
        } finally {
            btn.disabled = false;
            btn.textContent = originalText;
        }
    }
})();
