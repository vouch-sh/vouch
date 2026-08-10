// Guided policy builder for /admin/policies.
//
// The builder reads its field/operator/event catalog from the server via a
// data attribute (labels arrive pre-translated), clones <template> rows
// from the page (so Tailwind's content scan sees every class — the only
// class this file toggles is "hidden"), and asks the server to generate
// and validate policy text from the assembled rule. The server is the only
// place text is generated; this file never composes Dogwood syntax.
document.addEventListener("DOMContentLoaded", function () {
  var catalogEl = document.getElementById("policy-catalog");
  var playground = document.getElementById("policy-playground");
  if (!catalogEl || !playground) return;

  var catalog;
  try {
    catalog = JSON.parse(catalogEl.dataset.catalog);
  } catch (e) {
    return;
  }

  var btnNew = document.getElementById("btn-new-policy");
  var btnCancel = document.getElementById("btn-cancel-policy");
  var btnSave = document.getElementById("btn-save-policy");
  var btnAddCheck = document.getElementById("btn-add-check");
  var btnAddOsFloor = document.getElementById("btn-add-osfloor");
  var btnEditText = document.getElementById("btn-edit-text");
  var policyForm = document.getElementById("policy-form");
  var specInput = document.getElementById("policy-builder-spec");
  var nameInput = document.getElementById("policy-name");
  var descInput = document.getElementById("policy-description");
  var exprInput = document.getElementById("policy-expression");
  var previewEl = document.getElementById("policy-preview");
  var previewLabel = document.getElementById("preview-label");
  var ruleHint = document.getElementById("rule-hint");
  var playgroundTitle = document.getElementById("playground-title");
  var builderSection = document.getElementById("builder-section");
  var builderRows = document.getElementById("builder-rows");
  var builderPolarity = document.getElementById("builder-polarity");
  var windowCapNote = document.getElementById("window-cap-note");
  var loginRecencyNote = document.getElementById("login-recency-note");
  var decisionIssue = document.getElementById("decision-issue");
  var decisionExchange = document.getElementById("decision-exchange");
  var modeDevice = document.getElementById("mode-device");
  var modeHistory = document.getElementById("mode-history");
  var validationBox = document.getElementById("policy-validation");
  var validEl = document.getElementById("policy-valid");
  var invalidEl = document.getElementById("policy-invalid");
  var errorMsg = document.getElementById("policy-error-msg");
  var testResult = document.getElementById("policy-test-result");
  var shapePreview = document.getElementById("policy-shape-preview");

  var tplDevice = document.getElementById("tpl-device-row");
  var tplOsFloor = document.getElementById("tpl-osfloor-row");
  var tplHistory = document.getElementById("tpl-history-row");

  var debounceTimer = null;
  var isValid = false;
  // Monotonic token for validate round-trips: a response is applied only
  // if no newer validate started (or cleared state) after it was sent, so
  // a slow early response can never overwrite the fields a later edit
  // produced.
  var validateSeq = 0;
  // "builder" or "text" — text is the escape hatch and a one-way door.
  var editorMode = "builder";
  var maxWindowSecs = catalog.max_window_hours * 3600;
  var unitSecs = { s: 1, m: 60, h: 3600, d: 86400 };

  function fieldByName(name) {
    for (var i = 0; i < catalog.fields.length; i++) {
      if (catalog.fields[i].name === name) return catalog.fields[i];
    }
    return null;
  }

  function eventLabel(key) {
    for (var i = 0; i < catalog.events.length; i++) {
      if (catalog.events[i].key === key) return catalog.events[i].label;
    }
    return key;
  }

  // Mirrors the server's version encoding for the inline hint only; the
  // authoritative encoding happens server-side during generation.
  function semverNum(version) {
    var parts = version.split(".");
    if (parts.length > 3) return null;
    var nums = [];
    for (var i = 0; i < parts.length; i++) {
      if (!/^\d+$/.test(parts[i])) return null;
      nums.push(parseInt(parts[i], 10));
    }
    while (nums.length < 3) nums.push(0);
    return nums[0] * 1000000 + nums[1] * 1000 + nums[2];
  }

  function addOption(select, value, label) {
    var opt = document.createElement("option");
    opt.value = value;
    opt.textContent = label;
    select.appendChild(opt);
  }

  function populateFieldSelect(select) {
    var groups = {};
    for (var i = 0; i < catalog.fields.length; i++) {
      var f = catalog.fields[i];
      if (!groups[f.group]) {
        groups[f.group] = document.createElement("optgroup");
        groups[f.group].label = catalog.groups[f.group] || f.group;
        select.appendChild(groups[f.group]);
      }
      var opt = document.createElement("option");
      opt.value = f.name;
      opt.textContent = f.name;
      groups[f.group].appendChild(opt);
    }
  }

  function populateEventSelect(select) {
    for (var i = 0; i < catalog.events.length; i++) {
      addOption(select, catalog.events[i].key, catalog.events[i].label);
    }
  }

  function populateOpSelect(select, kind) {
    select.textContent = "";
    var ops = catalog.operators[kind] || [];
    for (var i = 0; i < ops.length; i++) {
      addOption(select, ops[i].op, ops[i].label);
    }
  }

  // Show the one value control the field's kind needs.
  function updateDeviceRowControls(row) {
    var field = fieldByName(row.querySelector(".row-field").value);
    if (!field) return;
    populateOpSelect(row.querySelector(".row-op"), field.kind);
    var valueSelect = row.querySelector(".row-value-select");
    var valueText = row.querySelector(".row-value-text");
    var valueNumber = row.querySelector(".row-value-number");
    var valueVersion = row.querySelector(".row-value-version");
    var hint = row.querySelector(".row-hint");
    valueSelect.classList.add("hidden");
    valueText.classList.add("hidden");
    valueNumber.classList.add("hidden");
    valueVersion.classList.add("hidden");
    hint.textContent = "";
    if (field.kind === "bool") {
      valueSelect.textContent = "";
      addOption(valueSelect, "true", "true");
      addOption(valueSelect, "false", "false");
      valueSelect.classList.remove("hidden");
    } else if (field.kind === "text_enum" || field.kind === "string_set") {
      valueSelect.textContent = "";
      for (var i = 0; i < field.values.length; i++) {
        addOption(valueSelect, field.values[i], field.values[i]);
      }
      valueSelect.classList.remove("hidden");
    } else if (field.kind === "long" || field.kind === "build_num") {
      valueNumber.classList.remove("hidden");
    } else if (field.kind === "version_num") {
      valueVersion.classList.remove("hidden");
      updateVersionHint(row);
    } else {
      valueText.classList.remove("hidden");
    }
  }

  function updateVersionHint(row) {
    var hint = row.querySelector(".row-hint");
    var version = row.querySelector(".row-value-version").value.trim();
    var num = version ? semverNum(version) : null;
    hint.textContent = num === null ? "" : t("admin-js-version-encodes", { num: String(num) });
  }

  function addDeviceRow() {
    var row = tplDevice.content.firstElementChild.cloneNode(true);
    populateFieldSelect(row.querySelector(".row-field"));
    updateDeviceRowControls(row);
    builderRows.appendChild(row);
    return row;
  }

  function addOsFloorRow() {
    var row = tplOsFloor.content.firstElementChild.cloneNode(true);
    builderRows.appendChild(row);
    return row;
  }

  function updateHistoryRowControls(row) {
    var shape = row.querySelector(".row-shape").value;
    row.querySelector(".row-count-wrap").classList.toggle("hidden", shape !== "count_at_least");
    row.querySelector(".row-cancel-wrap").classList.toggle("hidden", shape !== "not_since");
  }

  function addHistoryRow() {
    var row = tplHistory.content.firstElementChild.cloneNode(true);
    populateEventSelect(row.querySelector(".row-event"));
    populateEventSelect(row.querySelector(".row-cancel"));
    updateHistoryRowControls(row);
    builderRows.appendChild(row);
    updateHistoryRemoveVisibility();
    return row;
  }

  // A history rule carries one condition (Dogwood's guidance: combinations
  // are separate policies), so the sole row has no remove button. Legacy
  // multi-condition specs still render removable rows until trimmed to one.
  function updateHistoryRemoveVisibility() {
    if (checksMode() !== "history") return;
    var rows = builderRows.querySelectorAll(".builder-row");
    rows.forEach(function (row) {
      row.querySelector(".row-remove").classList.toggle("hidden", rows.length <= 1);
    });
  }

  function checksMode() {
    return modeHistory.checked ? "history" : "device";
  }

  function decisionValue() {
    return decisionExchange.checked ? "exchange_token" : "issue_token";
  }

  // Clamp a window to the server's cap so the request never round-trips
  // just to learn the limit; the note explains why the value moved.
  function clampWindow(amountInput, unitSelect) {
    var amount = parseInt(amountInput.value, 10);
    if (!(amount > 0)) return null;
    var unit = unitSelect.value;
    var max = Math.floor(maxWindowSecs / unitSecs[unit]);
    if (amount > max) {
      amount = max;
      amountInput.value = String(max);
      windowCapNote.classList.remove("hidden");
    }
    return { amount: amount, unit: unit };
  }

  function collectDeviceCondition(row) {
    if (row.dataset.row === "os_floor") {
      var floors = [];
      var enables = row.querySelectorAll(".floor-enable");
      for (var i = 0; i < enables.length; i++) {
        if (!enables[i].checked) continue;
        var os = enables[i].dataset.os;
        var min = row.querySelector('.floor-min[data-os="' + os + '"]').value.trim();
        if (!min) return null;
        floors.push({ os: os, min: min });
      }
      if (floors.length === 0) return null;
      return { kind: "os_floor", floors: floors };
    }
    var field = fieldByName(row.querySelector(".row-field").value);
    if (!field) return null;
    var op = row.querySelector(".row-op").value;
    var value;
    if (field.kind === "bool") {
      value = row.querySelector(".row-value-select").value === "true";
    } else if (field.kind === "text_enum" || field.kind === "string_set") {
      value = row.querySelector(".row-value-select").value;
      if (!value) return null;
    } else if (field.kind === "long" || field.kind === "build_num") {
      var num = parseInt(row.querySelector(".row-value-number").value, 10);
      if (isNaN(num)) return null;
      value = num;
    } else if (field.kind === "version_num") {
      value = row.querySelector(".row-value-version").value.trim();
      if (!value) return null;
    } else {
      value = row.querySelector(".row-value-text").value;
      if (!value) return null;
    }
    return { kind: "field", field: field.name, op: op, value: value };
  }

  function collectHistoryCondition(row) {
    var shape = row.querySelector(".row-shape").value;
    var event = row.querySelector(".row-event").value;
    var window = clampWindow(
      row.querySelector(".row-window-amount"),
      row.querySelector(".row-window-unit")
    );
    if (!window) return null;
    if (shape === "count_at_least") {
      var threshold = parseInt(row.querySelector(".row-threshold").value, 10);
      if (!(threshold > 0)) return null;
      return { shape: shape, event: event, window: window, threshold: threshold };
    }
    if (shape === "not_since") {
      return {
        shape: shape,
        anchor: event,
        cancelled_by: row.querySelector(".row-cancel").value,
        window: window,
      };
    }
    return { shape: shape, event: event, window: window };
  }

  // The assembled RuleSpec, or null while any row is incomplete.
  function collectSpec() {
    var rows = builderRows.querySelectorAll(".builder-row");
    if (rows.length === 0) return null;
    var conditions = [];
    for (var i = 0; i < rows.length; i++) {
      var condition =
        checksMode() === "device"
          ? collectDeviceCondition(rows[i])
          : collectHistoryCondition(rows[i]);
      if (!condition) return null;
      conditions.push(condition);
    }
    return {
      decision: decisionValue(),
      body: { kind: checksMode(), conditions: conditions },
    };
  }

  function renderShapePreview(spec) {
    shapePreview.textContent = "";
    if (!spec || spec.body.kind !== "history") return;
    for (var i = 0; i < spec.body.conditions.length; i++) {
      var c = spec.body.conditions[i];
      var w = c.window.amount + c.window.unit;
      var line = document.createElement("div");
      if (c.shape === "happened_within") {
        line.textContent = t("admin-js-preview-happened", { event: eventLabel(c.event), window: w });
      } else if (c.shape === "not_happened_within") {
        line.textContent = t("admin-js-preview-not-happened", { event: eventLabel(c.event), window: w });
      } else if (c.shape === "count_at_least") {
        line.textContent = t("admin-js-preview-count", {
          event: eventLabel(c.event),
          window: w,
          n: String(c.threshold),
          m: String(c.threshold - 1),
        });
      } else if (c.shape === "not_since") {
        line.textContent = t("admin-js-preview-not-since", {
          anchor: eventLabel(c.anchor),
          cancel: eventLabel(c.cancelled_by),
          window: w,
        });
      }
      shapePreview.appendChild(line);
    }
    if (spec.body.conditions.length > 1) {
      var note = document.createElement("div");
      note.textContent = t("admin-js-preview-all");
      shapePreview.appendChild(note);
    }
  }

  // Login-recency conditions on token issuance are a trap: the login being
  // evaluated is not yet in the history the rule reads (its audit event is
  // written after the policy gate), so "did not happen" locks users out
  // and "happened" is a login cooldown. Warn, but let the admin proceed —
  // a cooldown may be intended.
  function updateLoginRecencyNote(spec) {
    var text = "";
    if (spec && spec.decision === "issue_token" && spec.body.kind === "history") {
      for (var i = 0; i < spec.body.conditions.length; i++) {
        var c = spec.body.conditions[i];
        if (
          (c.shape === "not_happened_within" && c.event === "login_success") ||
          (c.shape === "not_since" && c.anchor === "login_success")
        ) {
          text = loginRecencyNote.dataset.lockout;
          break;
        }
        if (c.shape === "happened_within" && c.event === "login_success") {
          text = loginRecencyNote.dataset.cooldown;
        }
      }
    }
    loginRecencyNote.textContent = text;
    loginRecencyNote.classList.toggle("hidden", !text);
  }

  function clearValidation() {
    validateSeq++;
    validationBox.classList.add("hidden");
    validEl.classList.add("hidden");
    invalidEl.classList.add("hidden");
    testResult.textContent = "";
    shapePreview.textContent = "";
    isValid = false;
    btnSave.disabled = true;
  }

  function validate() {
    var body;
    var spec = null;
    if (editorMode === "builder") {
      spec = collectSpec();
      updateLoginRecencyNote(spec);
      if (!spec) {
        previewEl.textContent = "";
        specInput.value = "";
        clearValidation();
        return;
      }
      body = { rule: spec };
    } else {
      updateLoginRecencyNote(null);
      var expr = exprInput.value.trim();
      if (!expr) {
        clearValidation();
        return;
      }
      body = { policy_text: expr, decision: decisionValue() };
    }
    var seq = ++validateSeq;
    fetch("/api/v1/org/policies/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body),
    })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        if (seq !== validateSeq) return;
        validationBox.classList.remove("hidden");
        if (data.valid) {
          validEl.classList.remove("hidden");
          invalidEl.classList.add("hidden");
          isValid = true;
          btnSave.disabled = false;
          if (editorMode === "builder") {
            previewEl.textContent = data.policy_text;
            exprInput.value = data.policy_text;
            specInput.value = JSON.stringify(spec);
          }
          renderShapePreview(spec);
          if (data.test_result) {
            // A history-dependent verdict reflects an empty test history,
            // so the shape lines above carry the explanation instead of a
            // bare pass/fail the admin would misread.
            if (data.test_result.reads_history) {
              testResult.textContent = t("admin-js-policy-history-note");
              testResult.className = "ml-1 text-gray-400";
            } else {
              testResult.textContent = data.test_result.pass
                ? t("admin-js-policy-passes")
                : t("admin-js-policy-fails");
              testResult.className = "ml-1 " + (data.test_result.pass
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
          if (editorMode === "builder" && data.policy_text) {
            previewEl.textContent = data.policy_text;
          }
          isValid = false;
          btnSave.disabled = true;
          testResult.textContent = "";
          shapePreview.textContent = "";
        }
      })
      .catch(function () {
        if (seq !== validateSeq) return;
        clearValidation();
      });
  }

  function schedule() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(validate, 300);
  }

  function setEditorMode(mode) {
    editorMode = mode;
    var builder = mode === "builder";
    builderSection.classList.toggle("hidden", !builder);
    previewEl.classList.toggle("hidden", !builder);
    exprInput.classList.toggle("hidden", builder);
    btnEditText.classList.toggle("hidden", !builder);
    ruleHint.classList.toggle("hidden", builder);
    previewLabel.textContent = builder
      ? previewLabel.dataset.preview
      : previewLabel.dataset.text;
  }

  function setChecksMode(mode) {
    modeDevice.checked = mode === "device";
    modeHistory.checked = mode === "history";
    builderPolarity.textContent = builderPolarity.dataset[mode];
    btnAddCheck.classList.toggle("hidden", mode === "history");
    btnAddOsFloor.classList.toggle("hidden", mode !== "device");
    builderRows.textContent = "";
    windowCapNote.classList.add("hidden");
    loginRecencyNote.classList.add("hidden");
  }

  // Device state only exists at token issuance; exchange forces history.
  function applyDecisionConstraints() {
    var exchange = decisionExchange.checked;
    modeDevice.disabled = exchange;
    if (exchange && checksMode() === "device") {
      setChecksMode("history");
      addHistoryRow();
    }
  }

  function resetEditor(title) {
    policyForm.reset();
    policyForm.action = "/admin/policies/custom";
    playgroundTitle.textContent = title;
    specInput.value = "";
    previewEl.textContent = "";
    exprInput.value = "";
    decisionIssue.checked = true;
    modeDevice.disabled = false;
    clearValidation();
  }

  function showPlayground() {
    playground.classList.remove("hidden");
    playground.scrollIntoView({ behavior: "smooth", block: "nearest" });
    nameInput.focus();
  }

  function hidePlayground() {
    playground.classList.add("hidden");
    resetEditor(t("admin-policies-playground-title"));
  }

  // Rebuild builder rows from a stored spec; false when the spec's shape
  // is unrecognized (older format, hand-tampered) — caller falls back to
  // the text editor.
  function populateFromSpec(spec) {
    if (!spec || !spec.body || !spec.body.conditions) return false;
    decisionExchange.checked = spec.decision === "exchange_token";
    decisionIssue.checked = !decisionExchange.checked;
    if (spec.body.kind !== "device" && spec.body.kind !== "history") return false;
    setChecksMode(spec.body.kind);
    applyDecisionConstraints();
    for (var i = 0; i < spec.body.conditions.length; i++) {
      var c = spec.body.conditions[i];
      var row;
      if (spec.body.kind === "device") {
        if (c.kind === "os_floor") {
          row = addOsFloorRow();
          var enables = row.querySelectorAll(".floor-enable");
          for (var j = 0; j < enables.length; j++) enables[j].checked = false;
          for (var k = 0; k < c.floors.length; k++) {
            var enable = row.querySelector('.floor-enable[data-os="' + c.floors[k].os + '"]');
            var min = row.querySelector('.floor-min[data-os="' + c.floors[k].os + '"]');
            if (!enable || !min) return false;
            enable.checked = true;
            min.value = c.floors[k].min;
          }
        } else if (c.kind === "field") {
          if (!fieldByName(c.field)) return false;
          row = addDeviceRow();
          row.querySelector(".row-field").value = c.field;
          updateDeviceRowControls(row);
          row.querySelector(".row-op").value = c.op;
          var kind = fieldByName(c.field).kind;
          if (kind === "bool") {
            row.querySelector(".row-value-select").value = String(c.value);
          } else if (kind === "text_enum" || kind === "string_set") {
            row.querySelector(".row-value-select").value = c.value;
          } else if (kind === "long" || kind === "build_num") {
            row.querySelector(".row-value-number").value = String(c.value);
          } else if (kind === "version_num") {
            row.querySelector(".row-value-version").value = c.value;
            updateVersionHint(row);
          } else {
            row.querySelector(".row-value-text").value = c.value;
          }
        } else {
          return false;
        }
      } else {
        row = addHistoryRow();
        row.querySelector(".row-shape").value = c.shape;
        updateHistoryRowControls(row);
        if (c.shape === "not_since") {
          row.querySelector(".row-event").value = c.anchor;
          row.querySelector(".row-cancel").value = c.cancelled_by;
        } else {
          row.querySelector(".row-event").value = c.event;
          if (c.shape === "count_at_least") {
            row.querySelector(".row-threshold").value = String(c.threshold);
          }
        }
        row.querySelector(".row-window-amount").value = String(c.window.amount);
        row.querySelector(".row-window-unit").value = c.window.unit;
      }
    }
    return true;
  }

  btnNew.addEventListener("click", function () {
    hidePlayground();
    resetEditor(t("admin-policies-playground-title"));
    setEditorMode("builder");
    setChecksMode("device");
    addDeviceRow();
    showPlayground();
  });

  btnCancel.addEventListener("click", hidePlayground);

  document.querySelectorAll(".btn-edit-policy").forEach(function (btn) {
    btn.addEventListener("click", function () {
      hidePlayground();
      resetEditor(t("admin-js-edit-policy-title"));
      nameInput.value = btn.dataset.name;
      descInput.value = btn.dataset.description;
      policyForm.action = "/admin/policies/custom/" + btn.dataset.id;
      var opened = false;
      if (btn.dataset.builderSpec) {
        try {
          var spec = JSON.parse(btn.dataset.builderSpec);
          setEditorMode("builder");
          opened = populateFromSpec(spec);
        } catch (e) {
          opened = false;
        }
      }
      if (!opened) {
        builderRows.textContent = "";
        setEditorMode("text");
        exprInput.value = btn.dataset.expression;
      }
      showPlayground();
      validate();
    });
  });

  // Seed the editor from a built-in policy. Creates a new custom policy
  // rather than editing the built-in, which is code-defined. Built-in text
  // is not builder-representable in general, so this opens as text.
  document.querySelectorAll(".btn-copy-policy").forEach(function (btn) {
    btn.addEventListener("click", function () {
      hidePlayground();
      resetEditor(t("admin-policies-playground-title"));
      nameInput.value = t("admin-js-copy-of", { name: btn.dataset.name });
      descInput.value = btn.dataset.description;
      setEditorMode("text");
      exprInput.value = btn.dataset.expression;
      if (btn.dataset.expression.indexOf('Vouch::Action::"ExchangeToken"') !== -1) {
        decisionExchange.checked = true;
      }
      showPlayground();
      validate();
    });
  });

  // One-way door: the builder can generate text, but never lifts edited
  // text back into rows.
  btnEditText.addEventListener("click", function () {
    if (editorMode !== "builder") return;
    if (!confirm(t("admin-js-edit-as-text-confirm"))) return;
    exprInput.value = previewEl.textContent;
    specInput.value = "";
    setEditorMode("text");
    validate();
  });

  btnAddCheck.addEventListener("click", function () {
    if (checksMode() === "device") {
      addDeviceRow();
    } else {
      addHistoryRow();
    }
    schedule();
  });

  btnAddOsFloor.addEventListener("click", function () {
    addOsFloorRow();
    schedule();
  });

  decisionIssue.addEventListener("change", function () {
    applyDecisionConstraints();
    schedule();
  });
  decisionExchange.addEventListener("change", function () {
    applyDecisionConstraints();
    schedule();
  });
  modeDevice.addEventListener("change", function () {
    setChecksMode("device");
    addDeviceRow();
    schedule();
  });
  modeHistory.addEventListener("change", function () {
    setChecksMode("history");
    addHistoryRow();
    schedule();
  });

  builderRows.addEventListener("change", function (e) {
    var row = e.target.closest(".builder-row");
    if (!row) return;
    if (e.target.classList.contains("row-field")) {
      updateDeviceRowControls(row);
    }
    if (e.target.classList.contains("row-shape")) {
      updateHistoryRowControls(row);
    }
    schedule();
  });

  builderRows.addEventListener("input", function (e) {
    var row = e.target.closest(".builder-row");
    if (row && e.target.classList.contains("row-value-version")) {
      updateVersionHint(row);
    }
    schedule();
  });

  builderRows.addEventListener("click", function (e) {
    var remove = e.target.closest(".row-remove");
    if (!remove) return;
    var row = remove.closest(".builder-row");
    if (row) {
      row.remove();
      updateHistoryRemoveVisibility();
      schedule();
    }
  });

  exprInput.addEventListener("input", function () {
    if (editorMode !== "text") return;
    if (!exprInput.value.trim()) {
      clearValidation();
      return;
    }
    schedule();
  });

  policyForm.addEventListener("submit", function (e) {
    if (!isValid) {
      e.preventDefault();
    }
  });
});
