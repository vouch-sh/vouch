// Application detail page: toggle between view and edit modes, validate URIs,
// FAPI 2.0 security profile editing.

(function() {
    document.addEventListener('DOMContentLoaded', function() {
        var editBtn = document.getElementById('edit-btn');
        var cancelBtn = document.getElementById('cancel-edit-btn');
        var editForm = document.getElementById('edit-mode');
        var redirectTextarea = document.getElementById('redirect_uris');
        var redirectError = document.getElementById('redirect-uri-error');
        var resourceTextarea = document.getElementById('resource_uris');
        var resourceError = document.getElementById('resource-uri-error');

        // FAPI edit elements (may not exist for non-confidential types)
        var editFapiJwksSection = document.getElementById('edit-fapi-jwks-section');
        var editJwksTextarea = document.getElementById('edit-jwks');
        var editJwksError = document.getElementById('edit-jwks-error');
        var editJwksUriInput = document.getElementById('edit-jwks-uri');
        var editJwksUriError = document.getElementById('edit-jwks-uri-error');

        function toggleEditForm() {
            var viewMode = document.getElementById('view-mode');
            var editMode = document.getElementById('edit-mode');

            viewMode.classList.toggle('hidden');
            editMode.classList.toggle('hidden');
            editBtn.classList.toggle('hidden');
        }

        if (editBtn) {
            editBtn.addEventListener('click', toggleEditForm);
        }

        if (cancelBtn) {
            cancelBtn.addEventListener('click', toggleEditForm);
        }

        // Auto-open edit form if ?edit=1 is in URL
        if (new URLSearchParams(window.location.search).get('edit') === '1') {
            toggleEditForm();
        }

        // --- URI validation (mirrors app-create.js rules) ---

        function validateRedirectUris() {
            var uris = redirectTextarea.value.trim().split('\n').filter(function(line) {
                return line.trim();
            });

            var invalid = [];
            for (var i = 0; i < uris.length; i++) {
                var trimmed = uris[i].trim();
                try {
                    var url = new URL(trimmed);
                    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
                        invalid.push(trimmed);
                    }
                } catch (e) {
                    invalid.push(trimmed);
                }
            }

            if (invalid.length > 0) {
                return 'Invalid redirect URI(s): ' + invalid.join(', ') + '. Each URI must be a valid http:// or https:// URL.';
            }
            return null;
        }

        function validateResourceUris() {
            var uris = resourceTextarea.value.trim().split('\n').filter(function(line) {
                return line.trim();
            });

            if (uris.length === 0) {
                return null;
            }

            var errors = [];
            for (var i = 0; i < uris.length; i++) {
                var trimmed = uris[i].trim();

                if (trimmed.length > 2048) {
                    errors.push(trimmed.substring(0, 40) + '... (exceeds maximum length of 2048)');
                    continue;
                }

                if (trimmed.indexOf('#') !== -1) {
                    errors.push(trimmed + ' (must not contain a fragment)');
                    continue;
                }

                try {
                    new URL(trimmed);
                } catch (e) {
                    errors.push(trimmed + ' (must be an absolute URI with a scheme)');
                }
            }

            if (errors.length > 0) {
                return 'Invalid resource URI(s): ' + errors.join('; ') + '.';
            }
            return null;
        }

        function showFieldError(errorEl, textarea, message) {
            if (message) {
                errorEl.textContent = message;
                errorEl.classList.remove('hidden');
                textarea.classList.add('border-vouch-error');
            } else {
                errorEl.classList.add('hidden');
                textarea.classList.remove('border-vouch-error');
            }
        }

        if (redirectTextarea && redirectError) {
            redirectTextarea.addEventListener('blur', function() {
                if (redirectTextarea.value.trim()) {
                    showFieldError(redirectError, redirectTextarea, validateRedirectUris());
                }
            });

            redirectTextarea.addEventListener('input', function() {
                if (redirectTextarea.classList.contains('border-vouch-error')) {
                    clearTimeout(redirectTextarea.validateTimeout);
                    redirectTextarea.validateTimeout = setTimeout(function() {
                        showFieldError(redirectError, redirectTextarea, validateRedirectUris());
                    }, 500);
                }
            });
        }

        if (resourceTextarea && resourceError) {
            resourceTextarea.addEventListener('blur', function() {
                if (resourceTextarea.value.trim()) {
                    showFieldError(resourceError, resourceTextarea, validateResourceUris());
                }
            });

            resourceTextarea.addEventListener('input', function() {
                if (resourceTextarea.classList.contains('border-vouch-error')) {
                    clearTimeout(resourceTextarea.validateTimeout);
                    resourceTextarea.validateTimeout = setTimeout(function() {
                        showFieldError(resourceError, resourceTextarea, validateResourceUris());
                    }, 500);
                }
            });
        }

        // --- FAPI 2.0 edit mode ---

        function isEditFapiSelected() {
            var fapiRadio = document.querySelector('#edit-mode input[name="fapi_profile"]:checked');
            return fapiRadio && fapiRadio.value === 'fapi2_security';
        }

        function updateEditFapiVisibility() {
            if (!editFapiJwksSection) {
                return;
            }
            if (isEditFapiSelected()) {
                editFapiJwksSection.classList.remove('hidden');
            } else {
                editFapiJwksSection.classList.add('hidden');
            }
        }

        function validateEditJwks() {
            if (!editJwksTextarea) {
                return null;
            }
            var value = editJwksTextarea.value.trim();
            if (!value) {
                return null;
            }

            try {
                var parsed = JSON.parse(value);
                if (!parsed.keys || !Array.isArray(parsed.keys) || parsed.keys.length === 0) {
                    return 'JWKS must be a JSON object with a non-empty "keys" array.';
                }
            } catch (e) {
                return 'JWKS must be valid JSON.';
            }

            return null;
        }

        function validateEditJwksUri() {
            if (!editJwksUriInput) {
                return null;
            }
            var value = editJwksUriInput.value.trim();
            if (!value) {
                return null;
            }

            try {
                var url = new URL(value);
                if (url.protocol !== 'https:') {
                    return 'JWKS URI must use https://.';
                }
            } catch (e) {
                return 'JWKS URI must be a valid https:// URL.';
            }

            return null;
        }

        // Toggle FAPI JWKS section in edit mode
        var editFapiRadios = document.querySelectorAll('#edit-mode input[name="fapi_profile"]');
        for (var i = 0; i < editFapiRadios.length; i++) {
            editFapiRadios[i].addEventListener('change', updateEditFapiVisibility);
        }

        // JWKS validation on blur
        if (editJwksTextarea && editJwksError) {
            editJwksTextarea.addEventListener('blur', function() {
                if (editJwksTextarea.value.trim()) {
                    showFieldError(editJwksError, editJwksTextarea, validateEditJwks());
                }
            });
        }

        if (editJwksUriInput && editJwksUriError) {
            editJwksUriInput.addEventListener('blur', function() {
                if (editJwksUriInput.value.trim()) {
                    showFieldError(editJwksUriError, editJwksUriInput, validateEditJwksUri());
                }
            });
        }

        // Validate on submit
        if (editForm) {
            editForm.addEventListener('submit', function(e) {
                var hasError = false;

                if (redirectTextarea && redirectError) {
                    var redirectErr = validateRedirectUris();
                    if (redirectErr) {
                        e.preventDefault();
                        showFieldError(redirectError, redirectTextarea, redirectErr);
                        redirectTextarea.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        redirectTextarea.focus();
                        hasError = true;
                    }
                }

                if (resourceTextarea && resourceError) {
                    var resourceErr = validateResourceUris();
                    if (resourceErr) {
                        e.preventDefault();
                        showFieldError(resourceError, resourceTextarea, resourceErr);
                        if (!hasError) {
                            resourceTextarea.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            resourceTextarea.focus();
                        }
                        hasError = true;
                    }
                }

                // FAPI JWKS validation in edit mode
                if (isEditFapiSelected()) {
                    var jwksErr = validateEditJwks();
                    if (jwksErr) {
                        e.preventDefault();
                        showFieldError(editJwksError, editJwksTextarea, jwksErr);
                        if (!hasError) {
                            editJwksTextarea.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            editJwksTextarea.focus();
                        }
                        hasError = true;
                    }

                    var jwksUriErr = validateEditJwksUri();
                    if (jwksUriErr) {
                        e.preventDefault();
                        showFieldError(editJwksUriError, editJwksUriInput, jwksUriErr);
                        if (!hasError) {
                            editJwksUriInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            editJwksUriInput.focus();
                        }
                        hasError = true;
                    }

                    // At least one of JWKS or JWKS URI must be provided
                    if (editJwksTextarea && editJwksUriInput
                        && !editJwksTextarea.value.trim() && !editJwksUriInput.value.trim()) {
                        e.preventDefault();
                        var msg = 'FAPI 2.0 requires either a JWKS or JWKS URI.';
                        showFieldError(editJwksError, editJwksTextarea, msg);
                        if (!hasError) {
                            editJwksTextarea.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            editJwksTextarea.focus();
                        }
                        hasError = true;
                    }
                }

                if (hasError) {
                    return false;
                }
            });
        }
    });
})();
