// Shared UI utilities: clipboard copy, confirm dialogs.
// Attach behavior via data-* attributes — no inline handlers needed.

(function() {
    document.addEventListener('DOMContentLoaded', function() {
        // Copy to clipboard: any element with data-copy-text
        document.addEventListener('click', function(event) {
            var btn = event.target.closest('[data-copy-text]');
            if (!btn) return;

            var text = btn.dataset.copyText;
            navigator.clipboard.writeText(text).then(function() {
                var original = btn.textContent;
                btn.textContent = 'Copied!';
                btn.classList.add('text-vouch-success');
                setTimeout(function() {
                    btn.textContent = original;
                    btn.classList.remove('text-vouch-success');
                }, 2000);
            });
        });

        // Confirm dialogs on form submit: forms with data-confirm
        var confirmForms = document.querySelectorAll('form[data-confirm]');
        for (var i = 0; i < confirmForms.length; i++) {
            (function(form) {
                form.addEventListener('submit', function(event) {
                    if (!confirm(form.dataset.confirm)) {
                        event.preventDefault();
                    }
                });
            })(confirmForms[i]);
        }

        // Confirm dialogs on button click: buttons with data-confirm inside forms
        var confirmButtons = document.querySelectorAll('button[data-confirm]');
        for (var j = 0; j < confirmButtons.length; j++) {
            (function(btn) {
                btn.addEventListener('click', function(event) {
                    if (!confirm(btn.dataset.confirm)) {
                        event.preventDefault();
                    }
                });
            })(confirmButtons[j]);
        }
    });
})();
