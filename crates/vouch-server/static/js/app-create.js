// Application creation form: redirect URI validation, resource URI validation,
// app type toggling, FAPI 2.0 security profile.

(function() {
    document.addEventListener('DOMContentLoaded', function() {
        var redirectSection = document.getElementById('redirect-uris-section');
        var redirectTextarea = document.getElementById('redirect_uris');
        var redirectError = document.getElementById('redirect-uri-error');
        var resourceTextarea = document.getElementById('resource_uris');
        var resourceError = document.getElementById('resource-uri-error');
        var postLogoutTextarea = document.getElementById('post_logout_redirect_uris');
        var postLogoutError = document.getElementById('post-logout-redirect-uri-error');
        var nameInput = document.getElementById('name');
        var form = document.querySelector('form');
        var securityProfileSection = document.getElementById('security-profile-section');
        var fapiJwksSection = document.getElementById('fapi-jwks-section');
        var jwksTextarea = document.getElementById('jwks');
        var jwksError = document.getElementById('jwks-error');
        var jwksUriInput = document.getElementById('jwks_uri');
        var jwksUriError = document.getElementById('jwks-uri-error');

        // Validate redirect URIs and return error message (or null if valid)
        function validateRedirectUris() {
            var appTypeRadio = document.querySelector('input[name="application_type"]:checked');
            var appType = appTypeRadio ? appTypeRadio.value : 'web';

            // Service type doesn't need redirect URIs
            if (appType === 'service') {
                return null;
            }

            var uris = redirectTextarea.value.trim().split('\n').filter(function(line) {
                return line.trim();
            });

            if (uris.length === 0) {
                return t('appcreate-js-redirect-required');
            }

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

        // Validate resource URIs per RFC 8707 and return error message (or null if valid).
        // Rules: must be an absolute URI (has a scheme), must not contain a fragment (#),
        // max 2048 characters each.
        function validateResourceUris() {
            var uris = resourceTextarea.value.trim().split('\n').filter(function(line) {
                return line.trim();
            });

            // Resource URIs are optional — empty is fine
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

        // Validate post-logout redirect URIs and return error message (or null if valid).
        // Optional field. Rules mirror the server: https://, or loopback http://
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

        // Show/hide a field error and mark the control invalid for assistive tech
        function showFieldError(errorEl, inputEl, message) {
            if (message) {
                errorEl.textContent = message;
                errorEl.classList.remove('hidden');
                inputEl.classList.add('border-vouch-error');
                inputEl.setAttribute('aria-invalid', 'true');
            } else {
                errorEl.classList.add('hidden');
                inputEl.classList.remove('border-vouch-error');
                inputEl.removeAttribute('aria-invalid');
            }
        }

        // Center the offending field; no animation for reduced-motion users
        var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        function scrollToField(el) {
            el.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'center' });
            el.focus();
        }

        // Whether the selected app type is confidential (supports FAPI)
        function isConfidentialType() {
            var appTypeRadio = document.querySelector('input[name="application_type"]:checked');
            var appType = appTypeRadio ? appTypeRadio.value : 'web';
            return appType === 'web' || appType === 'service';
        }

        // Whether FAPI 2.0 is selected
        function isFapiSelected() {
            var fapiRadio = document.querySelector('input[name="fapi_profile"]:checked');
            return fapiRadio && fapiRadio.value === 'fapi2_security';
        }

        // Update security profile section visibility based on app type
        function updateSecurityProfileVisibility() {
            if (isConfidentialType()) {
                securityProfileSection.classList.remove('hidden');
            } else {
                securityProfileSection.classList.add('hidden');
                // Reset to standard when hiding
                var standardRadio = document.querySelector('input[name="fapi_profile"][value=""]');
                if (standardRadio) {
                    standardRadio.checked = true;
                }
                fapiJwksSection.classList.add('hidden');
            }
        }

        // Update JWKS section visibility based on FAPI selection
        function updateFapiJwksVisibility() {
            if (isFapiSelected()) {
                fapiJwksSection.classList.remove('hidden');
            } else {
                fapiJwksSection.classList.add('hidden');
            }
        }

        // Validate JWKS JSON
        function validateJwks() {
            var value = jwksTextarea.value.trim();
            if (!value) {
                return null; // Empty is ok — might use JWKS URI instead
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

        // Validate JWKS URI
        function validateJwksUri() {
            var value = jwksUriInput.value.trim();
            if (!value) {
                return null; // Empty is ok — might use inline JWKS instead
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

        // Hide redirect URIs for service type, show/hide security profile
        var appTypeRadios = document.querySelectorAll('input[name="application_type"]');
        for (var i = 0; i < appTypeRadios.length; i++) {
            appTypeRadios[i].addEventListener('change', function() {
                if (this.value === 'service') {
                    redirectSection.style.display = 'none';
                    redirectTextarea.required = false;
                    showFieldError(redirectError, redirectTextarea, null);
                } else {
                    redirectSection.style.display = 'block';
                    redirectTextarea.required = true;
                    if (redirectTextarea.value.trim()) {
                        showFieldError(redirectError, redirectTextarea, validateRedirectUris());
                    }
                }
                updateSecurityProfileVisibility();
            });
        }

        // Toggle JWKS fields when FAPI radio changes
        var fapiRadios = document.querySelectorAll('input[name="fapi_profile"]');
        for (var i = 0; i < fapiRadios.length; i++) {
            fapiRadios[i].addEventListener('change', updateFapiJwksVisibility);
        }

        // Initial visibility
        updateSecurityProfileVisibility();

        // Validate redirect URIs on blur
        redirectTextarea.addEventListener('blur', function() {
            showFieldError(redirectError, redirectTextarea, validateRedirectUris());
        });

        // Clear redirect error styling when user starts typing
        redirectTextarea.addEventListener('input', function() {
            if (redirectTextarea.classList.contains('border-vouch-error')) {
                clearTimeout(redirectTextarea.validateTimeout);
                redirectTextarea.validateTimeout = setTimeout(function() {
                    showFieldError(redirectError, redirectTextarea, validateRedirectUris());
                }, 500);
            }
        });

        // Validate resource URIs on blur
        resourceTextarea.addEventListener('blur', function() {
            if (resourceTextarea.value.trim()) {
                showFieldError(resourceError, resourceTextarea, validateResourceUris());
            }
        });

        // Clear resource error styling when user starts typing
        resourceTextarea.addEventListener('input', function() {
            if (resourceTextarea.classList.contains('border-vouch-error')) {
                clearTimeout(resourceTextarea.validateTimeout);
                resourceTextarea.validateTimeout = setTimeout(function() {
                    showFieldError(resourceError, resourceTextarea, validateResourceUris());
                }, 500);
            }
        });

        // Validate post-logout redirect URIs on blur
        if (postLogoutTextarea) {
            postLogoutTextarea.addEventListener('blur', function() {
                if (postLogoutTextarea.value.trim()) {
                    showFieldError(postLogoutError, postLogoutTextarea, validatePostLogoutUris());
                }
            });

            // Clear post-logout error styling when user starts typing
            postLogoutTextarea.addEventListener('input', function() {
                if (postLogoutTextarea.classList.contains('border-vouch-error')) {
                    clearTimeout(postLogoutTextarea.validateTimeout);
                    postLogoutTextarea.validateTimeout = setTimeout(function() {
                        showFieldError(postLogoutError, postLogoutTextarea, validatePostLogoutUris());
                    }, 500);
                }
            });
        }

        // Validate JWKS on blur
        jwksTextarea.addEventListener('blur', function() {
            if (jwksTextarea.value.trim()) {
                showFieldError(jwksError, jwksTextarea, validateJwks());
            }
        });

        // Validate JWKS URI on blur
        jwksUriInput.addEventListener('blur', function() {
            if (jwksUriInput.value.trim()) {
                showFieldError(jwksUriError, jwksUriInput, validateJwksUri());
            }
        });

        // Validate form on submit
        form.addEventListener('submit', function(e) {
            var hasError = false;

            if (!nameInput.value.trim()) {
                e.preventDefault();
                nameInput.focus();
                return false;
            }

            var appTypeRadio = document.querySelector('input[name="application_type"]:checked');
            if (!appTypeRadio) {
                e.preventDefault();
                return false;
            }

            var redirectUriError = validateRedirectUris();
            if (redirectUriError) {
                e.preventDefault();
                showFieldError(redirectError, redirectTextarea, redirectUriError);
                scrollToField(redirectTextarea);
                hasError = true;
            }

            var resourceUriError = validateResourceUris();
            if (resourceUriError) {
                e.preventDefault();
                showFieldError(resourceError, resourceTextarea, resourceUriError);
                if (!hasError) {
                    scrollToField(resourceTextarea);
                }
                hasError = true;
            }

            var postLogoutUriError = validatePostLogoutUris();
            if (postLogoutUriError) {
                e.preventDefault();
                showFieldError(postLogoutError, postLogoutTextarea, postLogoutUriError);
                if (!hasError) {
                    scrollToField(postLogoutTextarea);
                }
                hasError = true;
            }

            // FAPI JWKS validation
            if (isFapiSelected()) {
                var jwksErr = validateJwks();
                if (jwksErr) {
                    e.preventDefault();
                    showFieldError(jwksError, jwksTextarea, jwksErr);
                    if (!hasError) {
                        scrollToField(jwksTextarea);
                    }
                    hasError = true;
                }

                var jwksUriErr = validateJwksUri();
                if (jwksUriErr) {
                    e.preventDefault();
                    showFieldError(jwksUriError, jwksUriInput, jwksUriErr);
                    if (!hasError) {
                        scrollToField(jwksUriInput);
                    }
                    hasError = true;
                }

                // At least one of JWKS or JWKS URI must be provided
                if (!jwksTextarea.value.trim() && !jwksUriInput.value.trim()) {
                    e.preventDefault();
                    var msg = t('appcreate-js-fapi-required');
                    showFieldError(jwksError, jwksTextarea, msg);
                    if (!hasError) {
                        scrollToField(jwksTextarea);
                    }
                    hasError = true;
                }
            }

            if (hasError) {
                return false;
            }
        });
    });
})();
