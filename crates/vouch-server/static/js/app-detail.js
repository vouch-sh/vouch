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
        var postLogoutTextarea = document.getElementById('post_logout_redirect_uris');
        var postLogoutError = document.getElementById('post-logout-redirect-uri-error');

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
                return t('appcreate-js-redirect-invalid', { uris: invalid.join(', ') });
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
                    errors.push(t('appcreate-js-resource-toolong-uri', { uri: trimmed.substring(0, 40) }));
                    continue;
                }

                if (trimmed.indexOf('#') !== -1) {
                    errors.push(t('appcreate-js-resource-fragment-uri', { uri: trimmed }));
                    continue;
                }

                try {
                    new URL(trimmed);
                } catch (e) {
                    errors.push(t('appcreate-js-resource-scheme-uri', { uri: trimmed }));
                }
            }

            if (errors.length > 0) {
                return t('appcreate-js-resource-invalid', { errors: errors.join('; ') });
            }
            return null;
        }

        // Optional. Rules mirror the server: https://, or loopback http://
        // (localhost / 127.0.0.1 / [::1]), and no fragment component.
        function validatePostLogoutUris() {
            if (!postLogoutTextarea) {
                return null;
            }

            var uris = postLogoutTextarea.value.trim().split('\n').filter(function(line) {
                return line.trim();
            });

            if (uris.length === 0) {
                return null;
            }

            var invalid = [];
            for (var i = 0; i < uris.length; i++) {
                var trimmed = uris[i].trim();
                try {
                    var url = new URL(trimmed);
                    var loopbackHttp = url.protocol === 'http:' &&
                        (url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]');
                    var valid = (url.protocol === 'https:' || loopbackHttp) && !url.hash;
                    if (!valid) {
                        invalid.push(trimmed);
                    }
                } catch (e) {
                    invalid.push(trimmed);
                }
            }

            if (invalid.length > 0) {
                return t('appcreate-js-postlogout-invalid', { uris: invalid.join(', ') });
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

        if (postLogoutTextarea && postLogoutError) {
            postLogoutTextarea.addEventListener('blur', function() {
                if (postLogoutTextarea.value.trim()) {
                    showFieldError(postLogoutError, postLogoutTextarea, validatePostLogoutUris());
                }
            });

            postLogoutTextarea.addEventListener('input', function() {
                if (postLogoutTextarea.classList.contains('border-vouch-error')) {
                    clearTimeout(postLogoutTextarea.validateTimeout);
                    postLogoutTextarea.validateTimeout = setTimeout(function() {
                        showFieldError(postLogoutError, postLogoutTextarea, validatePostLogoutUris());
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
                    return t('appcreate-js-jwks-keys');
                }
            } catch (e) {
                return t('appcreate-js-jwks-json');
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
                    return t('appcreate-js-jwksuri-https');
                }
            } catch (e) {
                return t('appcreate-js-jwksuri-invalid');
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

                if (postLogoutTextarea && postLogoutError) {
                    var postLogoutErr = validatePostLogoutUris();
                    if (postLogoutErr) {
                        e.preventDefault();
                        showFieldError(postLogoutError, postLogoutTextarea, postLogoutErr);
                        if (!hasError) {
                            postLogoutTextarea.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            postLogoutTextarea.focus();
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
                        var msg = t('appcreate-js-fapi-required');
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
