(function () {
  const input = document.querySelector("#password-input");
  const visibilityToggle = document.querySelector("#visibility-toggle");
  const clearButton = document.querySelector("#clear-button");
  const lengthInput = document.querySelector("#password-length");
  const lengthSlider = document.querySelector("#password-length-slider");
  const lengthOutput = document.querySelector("#password-length-output");
  const generateButton = document.querySelector("#generate-button");
  const copyButton = document.querySelector("#copy-button");
  const characterTypeInputs = Array.from(document.querySelectorAll('input[name="character-type"]'));
  const avoidLookalikesInput = document.querySelector("#avoid-lookalikes");
  const actionStatus = document.querySelector("#action-status");
  const themeToggle = document.querySelector("#theme-toggle");
  const themeLabel = document.querySelector("#theme-label");
  const strengthLabel = document.querySelector("#strength-label");
  const strengthDescription = document.querySelector("#strength-description");
  const entropyValue = document.querySelector("#entropy-value");
  const meter = document.querySelector(".strength-meter");
  const meterSegments = Array.from(document.querySelectorAll(".meter-segment"));
  const suggestionList = document.querySelector("#suggestion-list");
  const insightList = document.querySelector("#insight-list");
  const checklistItems = Array.from(document.querySelectorAll("[data-check]"));
  const findingLabels = {
    commonPassword: "Matches a common password or a simple variation.",
    dictionaryWord: "Contains a word from the checker's small local dictionary.",
    sequence: "Contains a predictable alphabet, number, or keyboard sequence.",
    repeatedPattern: "Repeats a character or short pattern."
  };

  const descriptions = {
    Weak: "This password is easy to guess. Change it before using it for an account.",
    Fair: "Some effort would be needed to guess it, but a few improvements would help.",
    Good: "A solid start. A little more length and uniqueness can make it stronger.",
    Strong: "This looks difficult to guess. Keep it unique and never reuse it.",
    "Very strong": "This long password looks very difficult to guess. Keep it unique and never reuse it."
  };

  function renderSuggestions(suggestions) {
    suggestionList.replaceChildren();
    for (const suggestion of suggestions) {
      const item = document.createElement("li");
      item.textContent = suggestion;
      suggestionList.append(item);
    }
  }

  function renderInsights(result, hasPassword) {
    insightList.replaceChildren();
    const findings = hasPassword
      ? Object.keys(findingLabels).filter(function (finding) {
        return result.findings[finding];
      })
      : [];
    const messages = !hasPassword
      ? ["Enter a password to check for common patterns."]
      : findings.length > 0
        ? findings.map(function (finding) {
          return findingLabels[finding];
        })
        : ["No common patterns were detected by this local checker."];

    for (const message of messages) {
      const item = document.createElement("li");
      item.textContent = message;
      insightList.append(item);
    }
    insightList.closest(".pattern-insights").dataset.hasFindings = String(findings.length > 0);
  }

  function renderResult(result, hasPassword) {
    const score = result.score;
    const label = hasPassword ? result.label : "Waiting";
    strengthLabel.textContent = label;
    strengthLabel.dataset.strength = hasPassword ? label : "";
    entropyValue.textContent = hasPassword ? result.entropyBits + " bits" : "— bits";
    strengthDescription.textContent = hasPassword
      ? descriptions[label]
      : "Enter a password to see a private, on-device assessment.";

    meter.dataset.strength = hasPassword ? label : "";
    meter.setAttribute("aria-valuenow", hasPassword ? String(score) : "0");
    for (const [index, segment] of meterSegments.entries()) {
      segment.classList.toggle("is-filled", hasPassword && index < score);
    }

    for (const item of checklistItems) {
      item.classList.toggle("is-met", hasPassword && result.checks[item.dataset.check]);
    }
    renderSuggestions(result.suggestions);
    renderInsights(result, hasPassword);
  }

  function update() {
    const value = input.value;
    renderResult(PasswordAudit.analyzePassword(value), value.length > 0);
    copyButton.disabled = value.length === 0;
  }

  input.addEventListener("input", function () {
    actionStatus.textContent = "";
    update();
  });

  function getGeneratorOptions() {
    const options = {
      avoidLookalikes: avoidLookalikesInput.checked
    };
    for (const option of characterTypeInputs) {
      options[option.value] = option.checked;
    }
    return options;
  }

  function updateGeneratorAvailability() {
    const hasCharacterType = characterTypeInputs.some(function (option) {
      return option.checked;
    });
    generateButton.disabled = !hasCharacterType;
    if (!hasCharacterType) {
      actionStatus.textContent = "Select at least one character type to generate a password.";
    } else if (actionStatus.textContent.startsWith("Select at least one character type")) {
      actionStatus.textContent = "";
    }
  }

  for (const option of characterTypeInputs) {
    option.addEventListener("change", updateGeneratorAvailability);
  }

  avoidLookalikesInput.addEventListener("change", function () {
    actionStatus.textContent = avoidLookalikesInput.checked
      ? "Look-alike characters will be excluded from generated passwords."
      : "";
  });

  function syncLengthControls(source) {
    if (source === lengthSlider) {
      lengthInput.value = lengthSlider.value;
    } else if (lengthInput.valueAsNumber >= 8 && lengthInput.valueAsNumber <= 30) {
      lengthSlider.value = String(lengthInput.valueAsNumber);
    }
    lengthOutput.value = lengthInput.value || lengthSlider.value;
    lengthOutput.textContent = lengthOutput.value;
    lengthInput.setCustomValidity("");
    actionStatus.textContent = "";
  }

  lengthInput.addEventListener("input", function () {
    syncLengthControls(lengthInput);
  });
  lengthSlider.addEventListener("input", function () {
    syncLengthControls(lengthSlider);
  });

  lengthInput.addEventListener("change", function () {
    if (lengthInput.valueAsNumber < 8 || lengthInput.valueAsNumber > 30) {
      lengthInput.setCustomValidity("Choose a length from 8 to 30 characters.");
    } else {
      lengthInput.setCustomValidity("");
      syncLengthControls(lengthInput);
    }
  });

  visibilityToggle.addEventListener("click", function () {
    const isVisible = input.type === "text";
    input.type = isVisible ? "password" : "text";
    visibilityToggle.textContent = isVisible ? "Show" : "Hide";
    visibilityToggle.setAttribute("aria-pressed", String(!isVisible));
    visibilityToggle.setAttribute("aria-label", isVisible ? "Show password" : "Hide password");
    input.focus();
  });

  clearButton.addEventListener("click", function () {
    input.value = "";
    actionStatus.textContent = "";
    update();
    input.focus();
  });

  generateButton.addEventListener("click", function () {
    if (!lengthInput.reportValidity()) {
      return;
    }
    try {
      input.value = PasswordAudit.generatePassword(lengthInput.valueAsNumber, getGeneratorOptions());
      actionStatus.textContent = "Secure password generated. Copy it or review its strength below.";
      update();
      input.focus();
    } catch (error) {
      actionStatus.textContent = error instanceof Error
        ? error.message
        : "Unable to generate a password.";
    }
  });

  copyButton.addEventListener("click", async function () {
    if (input.value.length === 0) {
      return;
    }

    try {
      if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
        throw new Error("Clipboard access is unavailable. Select the password and copy it manually.");
      }
      await navigator.clipboard.writeText(input.value);
      actionStatus.textContent = "Password copied to the clipboard.";
    } catch (error) {
      actionStatus.textContent = error instanceof Error
        ? error.message
        : "Could not copy the password. Select it and copy it manually.";
    }
  });

  themeToggle.addEventListener("click", function () {
    const nextTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = nextTheme;
    const switchToDark = nextTheme === "light";
    themeLabel.textContent = switchToDark ? "Dark mode" : "Light mode";
    themeToggle.setAttribute("aria-label", switchToDark ? "Switch to dark mode" : "Switch to light mode");
    themeToggle.querySelector(".theme-icon").textContent = switchToDark ? "☾" : "☀";
    document.querySelector('meta[name="theme-color"]').content = nextTheme === "dark" ? "#0b1220" : "#f5f8fc";
  });

  window.addEventListener("pagehide", function () {
    input.value = "";
    update();
  });

  syncLengthControls(lengthSlider);
  updateGeneratorAvailability();
})();
