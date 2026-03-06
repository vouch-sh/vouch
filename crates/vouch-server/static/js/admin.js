// Confirm dialog for admin forms with data-confirm-message attribute.
// Uses addEventListener instead of inline onsubmit to comply with CSP.
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("form[data-confirm-message]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (!confirm(form.getAttribute("data-confirm-message"))) {
        e.preventDefault();
      }
    });
  });
});
