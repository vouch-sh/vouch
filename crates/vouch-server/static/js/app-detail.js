// Application detail page: toggle between view and edit modes, validate URIs.

(function() {
    document.addEventListener('DOMContentLoaded', function() {
        var editBtn = document.getElementById('edit-btn');
        var cancelBtn = document.getElementById('cancel-edit-btn');
        var editForm = document.getElementById('edit-mode');
        var redirectTextarea = document.getElementById('redirect_uris');
        var redirectError = document.getElementById('redirect-uri-error');
        var resourceTextarea = document.getElementById('resource_uris');
        var resourceError = document.getElementById('resource-uri-error');

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

                if (hasError) {
                    return false;
                }
            });
        }
    });
})();
