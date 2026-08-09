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

  // Prevent toggle form clicks from toggling the <details> parent
  document.querySelectorAll(".policy-toggle-form").forEach(function (form) {
    form.addEventListener("click", function (e) {
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
          setTimeout(function () { copyBtn.textContent = t("common-copy"); }, 2000);
        });
      }
    });
  }

  // Policy editor on the posture policies page
  var playground = document.getElementById("policy-playground");
  if (!playground) return;

  var btnNew = document.getElementById("btn-new-policy");
  var btnCancel = document.getElementById("btn-cancel-policy");
  var btnSave = document.getElementById("btn-save-policy");
  var policyForm = document.getElementById("policy-form");
  var editIdInput = document.getElementById("policy-edit-id");
  var nameInput = document.getElementById("policy-name");
  var descInput = document.getElementById("policy-description");
  var exprInput = document.getElementById("policy-expression");
  var playgroundTitle = document.getElementById("playground-title");
  var validationBox = document.getElementById("policy-validation");
  var validEl = document.getElementById("policy-valid");
  var invalidEl = document.getElementById("policy-invalid");
  var errorMsg = document.getElementById("policy-error-msg");
  var testResult = document.getElementById("policy-test-result");

  var debounceTimer = null;
  var isValid = false;

  function samplePosture() {
    return {
      type: "device_posture",
      posture_version: 1,
      os: "macos",
      os_version: "26.3.1",
      os_distribution: "macos",
      os_build: "25d2128",
      arch: "aarch64",
      disk_encryption_enabled: true,
      disk_encryption_technology: "filevault",
      firewall_enabled: true,
      firewall_technology: "application firewall",
      screen_lock_enabled: true,
      screen_lock_idle_timeout_secs: 300,
      secure_boot_enabled: true,
      sip_enabled: true,
      tpm_present: true,
      auto_update_enabled: true,
      auto_update_technology: "softwareupdate",
      uptime_secs: 86400,
      access_control_enforcing: true,
      access_control_technology: "gatekeeper",
      edr: ["crowdstrike"],
      mdm: ["jamf"],
      elevated: false,
      tty: true,
      parent_process: "zsh",
      cli_version: "2026.3.11",
    };
  }

  function showPlayground(title) {
    playgroundTitle.textContent = title;
    playground.classList.remove("hidden");
    playground.scrollIntoView({ behavior: "smooth", block: "nearest" });
    nameInput.focus();
  }

  function hidePlayground() {
    playground.classList.add("hidden");
    policyForm.reset();
    editIdInput.value = "";
    policyForm.action = "/admin/policies/custom";
    validationBox.classList.add("hidden");
    validEl.classList.add("hidden");
    invalidEl.classList.add("hidden");
    btnSave.disabled = true;
    isValid = false;
    testResult.textContent = "";
  }

  btnNew.addEventListener("click", function () {
    hidePlayground();
    showPlayground(t("admin-policies-playground-title"));
  });

  btnCancel.addEventListener("click", function () {
    hidePlayground();
  });

  // Edit buttons
  document.querySelectorAll(".btn-edit-policy").forEach(function (btn) {
    btn.addEventListener("click", function () {
      hidePlayground();
      editIdInput.value = btn.dataset.id;
      nameInput.value = btn.dataset.name;
      descInput.value = btn.dataset.description;
      exprInput.value = btn.dataset.expression;
      policyForm.action = "/admin/policies/custom/" + btn.dataset.id;
      showPlayground(t("admin-js-edit-policy-title"));
      validateExpression(btn.dataset.expression);
    });
  });

  // Seed the editor from a built-in policy. Creates a new custom policy
  // rather than editing the built-in, which is code-defined.
  document.querySelectorAll(".btn-copy-policy").forEach(function (btn) {
    btn.addEventListener("click", function () {
      hidePlayground();
      editIdInput.value = "";
      nameInput.value = t("admin-js-copy-of", { name: btn.dataset.name });
      descInput.value = btn.dataset.description;
      exprInput.value = btn.dataset.expression;
      policyForm.action = "/admin/policies/custom";
      showPlayground(t("admin-policies-playground-title"));
      validateExpression(btn.dataset.expression);
      playground.scrollIntoView({ behavior: "smooth", block: "center" });
      nameInput.focus();
    });
  });

  // Debounced policy validation
  exprInput.addEventListener("input", function () {
    clearTimeout(debounceTimer);
    var expr = exprInput.value.trim();
    if (!expr) {
      validationBox.classList.add("hidden");
      btnSave.disabled = true;
      isValid = false;
      return;
    }
    debounceTimer = setTimeout(function () {
      validateExpression(expr);
    }, 300);
  });

  function validateExpression(expr) {
    var body = {
      policy_text: expr,
      test_posture: samplePosture(),
    };
    fetch("/api/v1/org/policies/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body),
    })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        validationBox.classList.remove("hidden");
        if (data.valid) {
          validEl.classList.remove("hidden");
          invalidEl.classList.add("hidden");
          isValid = true;
          btnSave.disabled = false;
          if (data.test_result) {
            var pass = data.test_result.pass;
            // A history-dependent policy's verdict reflects an empty test
            // history, so the server sends a note instead of letting a bare
            // pass/fail be misread as a check of the policy's logic.
            if (data.test_result.reads_history) {
              testResult.textContent = t("admin-js-policy-history-note");
              testResult.className = "ml-1 text-gray-400";
            } else {
              testResult.textContent = pass
                ? t("admin-js-policy-passes")
                : t("admin-js-policy-fails");
              testResult.className = "ml-1 " + (pass
                ? "text-green-400"
                : "text-yellow-400");
            }
          } else {
            testResult.textContent = "";
          }
        } else {
          validEl.classList.add("hidden");
          invalidEl.classList.remove("hidden");
          errorMsg.textContent = data.error || t("admin-js-policy-invalid");
          isValid = false;
          btnSave.disabled = true;
          testResult.textContent = "";
        }
      })
      .catch(function () {
        validationBox.classList.add("hidden");
        isValid = false;
        btnSave.disabled = true;
      });
  }

  // Prevent form submit if expression is not validated
  policyForm.addEventListener("submit", function (e) {
    if (!isValid) {
      e.preventDefault();
    }
  });
});
