// Shared UI utilities: clipboard copy, confirm dialogs.
// Attach behavior via data-* attributes — no inline handlers needed.

(function() {
    // Render <time data-localize-time> elements in the viewer's locale and
    // local timezone. The server emits the full UTC instant in the datetime
    // attribute plus a no-JS fallback in the element body; here we upgrade it.
    function localizeTimes() {
        if (!('DateTimeFormat' in Intl)) return;
        var locale = document.documentElement.lang || undefined;
        // Explicit components (not dateStyle/timeStyle, which can't carry
        // timeZoneName) so the rendered time always names its timezone —
        // a bare "13:43" is ambiguous without it. hour12:false forces 24-hour
        // time regardless of the locale's default convention.
        var fmt = new Intl.DateTimeFormat(locale, {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            hour12: false,
            timeZoneName: 'short'
        });
        var els = document.querySelectorAll('time[data-localize-time]');
        for (var i = 0; i < els.length; i++) {
            var iso = els[i].getAttribute('datetime');
            if (!iso) continue;
            var date = new Date(iso);
            if (isNaN(date.getTime())) continue;
            els[i].textContent = fmt.format(date);
        }
    }

    document.addEventListener('DOMContentLoaded', function() {
        localizeTimes();

        // Copy to clipboard: any element with data-copy-text
        document.addEventListener('click', function(event) {
            var btn = event.target.closest('[data-copy-text]');
            if (!btn) return;

            var text = btn.dataset.copyText;
            navigator.clipboard.writeText(text).then(function() {
                // innerHTML is intentional and safe here: there is no
                // user-controlled data in play. We capture innerHTML (not
                // textContent) because icon-only buttons (SVG children, no
                // text) would otherwise be wiped when restored, and we only
                // ever write the hardcoded literal "Copied!". This is exempt
                // from the structural-DOM migration applied elsewhere.
                var original = btn.innerHTML;
                btn.innerHTML = t('common-js-copied');
                btn.classList.add('text-vouch-success');
                setTimeout(function() {
                    btn.innerHTML = original;
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
