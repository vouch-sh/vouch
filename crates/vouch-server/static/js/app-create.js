// Application creation form: redirect URI validation, resource URI validation, app type toggling.

(function() {
    document.addEventListener('DOMContentLoaded', function() {
        var redirectSection = document.getElementById('redirect-uris-section');
        var redirectTextarea = document.getElementById('redirect_uris');
        var redirectError = document.getElementById('redirect-uri-error');
        var resourceTextarea = document.getElementById('resource_uris');
        var resourceError = document.getElementById('resource-uri-error');
        var nameInput = document.getElementById('name');
        var form = document.querySelector('form');

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
                return 'At least one redirect URI is required.';
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
                return 'Invalid redirect URI(s): ' + invalid.join(', ') + '. Each URI must be a valid http:// or https:// URL.';
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

        // Show/hide redirect URI error
        function showRedirectError(message) {
            if (message) {
                redirectError.textContent = message;
                redirectError.classList.remove('hidden');
                redirectTextarea.classList.add('border-vouch-error');
            } else {
                redirectError.classList.add('hidden');
                redirectTextarea.classList.remove('border-vouch-error');
            }
        }

        // Show/hide resource URI error
        function showResourceError(message) {
            if (message) {
                resourceError.textContent = message;
                resourceError.classList.remove('hidden');
                resourceTextarea.classList.add('border-vouch-error');
            } else {
                resourceError.classList.add('hidden');
                resourceTextarea.classList.remove('border-vouch-error');
            }
        }

        // Hide redirect URIs for service type
        var appTypeRadios = document.querySelectorAll('input[name="application_type"]');
        for (var i = 0; i < appTypeRadios.length; i++) {
            appTypeRadios[i].addEventListener('change', function() {
                if (this.value === 'service') {
                    redirectSection.style.display = 'none';
                    redirectTextarea.required = false;
                    showRedirectError(null);
                } else {
                    redirectSection.style.display = 'block';
                    redirectTextarea.required = true;
                    if (redirectTextarea.value.trim()) {
                        showRedirectError(validateRedirectUris());
                    }
                }
            });
        }

        // Validate redirect URIs on blur
        redirectTextarea.addEventListener('blur', function() {
            showRedirectError(validateRedirectUris());
        });

        // Clear redirect error styling when user starts typing
        redirectTextarea.addEventListener('input', function() {
            if (redirectTextarea.classList.contains('border-vouch-error')) {
                clearTimeout(redirectTextarea.validateTimeout);
                redirectTextarea.validateTimeout = setTimeout(function() {
                    showRedirectError(validateRedirectUris());
                }, 500);
            }
        });

        // Validate resource URIs on blur
        resourceTextarea.addEventListener('blur', function() {
            if (resourceTextarea.value.trim()) {
                showResourceError(validateResourceUris());
            }
        });

        // Clear resource error styling when user starts typing
        resourceTextarea.addEventListener('input', function() {
            if (resourceTextarea.classList.contains('border-vouch-error')) {
                clearTimeout(resourceTextarea.validateTimeout);
                resourceTextarea.validateTimeout = setTimeout(function() {
                    showResourceError(validateResourceUris());
                }, 500);
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
                showRedirectError(redirectUriError);
                redirectTextarea.scrollIntoView({ behavior: 'smooth', block: 'center' });
                redirectTextarea.focus();
                hasError = true;
            }

            var resourceUriError = validateResourceUris();
            if (resourceUriError) {
                e.preventDefault();
                showResourceError(resourceUriError);
                if (!hasError) {
                    resourceTextarea.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    resourceTextarea.focus();
                }
                hasError = true;
            }

            if (hasError) {
                return false;
            }
        });
    });
})();
