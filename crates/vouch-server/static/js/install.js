// Install page: OS tab switching and command text updates.

(function() {
    document.addEventListener('DOMContentLoaded', function() {
        var tabs = document.querySelectorAll('[data-tab]');

        for (var i = 0; i < tabs.length; i++) {
            tabs[i].addEventListener('click', function(event) {
                var tab = event.currentTarget.dataset.tab;

                // Update active tab style and selection state
                var allTabs = document.querySelectorAll('[data-tab]');
                for (var j = 0; j < allTabs.length; j++) {
                    allTabs[j].classList.remove('tab-active');
                    allTabs[j].setAttribute('aria-selected', 'false');
                }
                event.currentTarget.classList.add('tab-active');
                event.currentTarget.setAttribute('aria-selected', 'true');

                // Show/hide tab content
                var allContent = document.querySelectorAll('.tab-content');
                for (var k = 0; k < allContent.length; k++) {
                    allContent[k].classList.add('hidden');
                }
                var tabContent = document.getElementById(tab + '-tab');
                if (tabContent) {
                    tabContent.classList.remove('hidden');
                }

                // Update command names for Windows vs other platforms
                var isWindows = tab === 'windows';
                var cmd = isWindows ? 'vouch.exe' : 'vouch';
                var serverUrlEl = document.querySelector('[data-server-url]');
                var serverUrl = serverUrlEl ? serverUrlEl.dataset.serverUrl : '';

                // Update step 2 command
                var step2Cmd = document.getElementById('step2-command');
                var step2CopyBtn = document.getElementById('step2-copy-btn');
                var enrollCommand = cmd + ' enroll --server ' + serverUrl;
                if (step2Cmd) {
                    step2Cmd.textContent = enrollCommand;
                }
                if (step2CopyBtn) {
                    step2CopyBtn.dataset.copyText = enrollCommand;
                }

                // Update step 3 command
                var step3Cmd = document.getElementById('step3-command');
                if (step3Cmd) {
                    step3Cmd.textContent = cmd + ' login';
                }
            });
        }

        // Arrow-key navigation between tabs (ARIA tabs pattern)
        var tablist = document.querySelector('[role="tablist"]');
        if (tablist) {
            tablist.addEventListener('keydown', function(event) {
                var keys = ['ArrowLeft', 'ArrowRight', 'Home', 'End'];
                if (keys.indexOf(event.key) === -1) return;
                var current = event.target.closest('[data-tab]');
                if (!current) return;
                event.preventDefault();
                var list = Array.prototype.slice.call(tabs);
                var idx = list.indexOf(current);
                if (event.key === 'ArrowLeft') idx = (idx - 1 + list.length) % list.length;
                else if (event.key === 'ArrowRight') idx = (idx + 1) % list.length;
                else if (event.key === 'Home') idx = 0;
                else idx = list.length - 1;
                list[idx].focus();
                list[idx].click();
            });
        }
    });
})();
