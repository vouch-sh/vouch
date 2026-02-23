// Application detail page: toggle between view and edit modes.

(function() {
    document.addEventListener('DOMContentLoaded', function() {
        var editBtn = document.getElementById('edit-btn');
        var cancelBtn = document.getElementById('cancel-edit-btn');

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
    });
})();
