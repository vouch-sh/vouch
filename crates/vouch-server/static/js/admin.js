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

  // Prevent clicks on the action cluster (toggle/edit/delete) from
  // toggling the surrounding <details> policy row.
  document.querySelectorAll(".policy-row-actions").forEach(function (actions) {
    actions.addEventListener("click", function (e) {
      e.stopPropagation();
    });
  });

  // Copy button for SCIM token display
  var copyBtn = document.getElementById("btn-copy-token");
  if (copyBtn) {
    copyBtn.addEventListener("click", function () {
      var tokenEl = document.getElementById("new-token-value");
      if (tokenEl && navigator.clipboard) {
        navigator.clipboard.writeText(tokenEl.textContent).then(function () {
          copyBtn.textContent = t("common-js-copied");
          // Announce via the sr-only live region in base.html.
          var copyStatus = document.getElementById("copy-status");
          if (copyStatus) copyStatus.textContent = t("common-js-copied");
          setTimeout(function () {
            copyBtn.textContent = t("common-copy");
            if (copyStatus) copyStatus.textContent = "";
          }, 2000);
        });
      }
    });
  }
});
