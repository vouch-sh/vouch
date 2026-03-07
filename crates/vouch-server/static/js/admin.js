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
          copyBtn.textContent = "Copied!";
          setTimeout(function () { copyBtn.textContent = "Copy"; }, 2000);
        });
      }
    });
  }

  // CEL Playground for posture policies page
  var playground = document.getElementById("cel-playground");
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
  var validationBox = document.getElementById("cel-validation");
  var validEl = document.getElementById("cel-valid");
  var invalidEl = document.getElementById("cel-invalid");
  var errorMsg = document.getElementById("cel-error-msg");
  var testResult = document.getElementById("cel-test-result");

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
    showPlayground("New Custom Policy");
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
      showPlayground("Edit Custom Policy");
      validateExpression(btn.dataset.expression);
    });
  });

  // Debounced CEL validation
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
      cel_expression: expr,
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
            testResult.textContent = pass
              ? "\u2014 passes against test device"
              : "\u2014 fails against test device";
            testResult.className = "ml-1 " + (pass
              ? "text-green-400"
              : "text-yellow-400");
          } else {
            testResult.textContent = "";
          }
        } else {
          validEl.classList.add("hidden");
          invalidEl.classList.remove("hidden");
          errorMsg.textContent = data.error || "Invalid expression";
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
