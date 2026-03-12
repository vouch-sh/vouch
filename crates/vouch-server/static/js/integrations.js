// Integrations page: toggle between view and edit modes for IdC config.

(function() {
    document.addEventListener('DOMContentLoaded', function() {
        var editBtn = document.getElementById('idc-edit-btn');
        var viewMode = document.getElementById('idc-view-mode');
        var editMode = document.getElementById('idc-edit-mode');
        var cancelBtn = document.getElementById('idc-cancel-btn');

        function showEditMode() {
            if (viewMode) viewMode.classList.add('hidden');
            if (editMode) editMode.classList.remove('hidden');
        }

        function showViewMode() {
            if (editMode) editMode.classList.add('hidden');
            if (viewMode) viewMode.classList.remove('hidden');
        }

        if (editBtn) {
            editBtn.addEventListener('click', showEditMode);
        }

        if (cancelBtn) {
            cancelBtn.addEventListener('click', showViewMode);
        }

        // Confirm before deleting
        var deleteForm = document.getElementById('idc-delete-form');
        if (deleteForm) {
            deleteForm.addEventListener('submit', function(e) {
                if (!confirm('Remove AWS Identity Center configuration?')) {
                    e.preventDefault();
                }
            });
        }
    });
})();
