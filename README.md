# Password Strength Checker

A privacy-first password auditing project with a browser interface and a standalone Python CLI. Both evaluate length and character variety, estimate entropy, flag common passwords and predictable patterns, and suggest improvements. The Python CLI runs locally and does not save or transmit the assessed password.

![Password Strength Checker shield icon](assets/shield-check.svg)

| Component          | File                                     | What it does                                                                                                                                                     |
| ------------------ | ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Python CLI          | `password_checker.py`                    | Hidden-terminal-input checker with in-memory dictionary and pattern checks, entropy metrics, and actionable feedback                                             |
| Python tests        | `test_password_checker.py`               | Tests the CLI assessment logic with Python's built-in `unittest`                                                                                                  |
| Password checker   | `src/password-audit.js`                  | Checks password length and character classes, detects selected common passwords and predictable patterns, estimates entropy, and creates improvement suggestions |
| Browser interface  | `index.html`, `styles.css`, `src/app.js` | Provides the responsive checker, show/hide and clear controls, theme switch, and password generator                                                              |
| Password generator | `src/app.js`                             | Generates a random password with the browser's cryptographic random-number generator and configurable character types                                            |
| Automated tests    | `tests/password-audit.test.js`           | Tests the password-audit logic with Node's built-in test runner                                                                                                  |

---

## 1. Requirements

- A modern browser with JavaScript enabled.
- Python 3.10 or later for the standalone CLI and its tests.
- [Node.js](https://nodejs.org/) 18 or later only if you want to run the browser checker's test suite.

## 2. Install

Download or clone the project files and open the project folder. There are no packages to install.

## 3. Quick start

Open `index.html` in a modern browser.

1. Type or paste a password to see its local assessment.
2. To create a password, choose a length and character options, then select **Generate password**.
3. Use **Copy** only when you want to copy the generated password.
4. Select **Clear password** when finished.

No server, account, or internet connection is required to use the checker. The page has no external runtime dependencies.

### Standalone Python CLI

From the project directory, run:

```powershell
python -B password_checker.py
```

Enter the password at the hidden prompt. The CLI prints the assessment but never prints the password itself. For machine-readable output, run `python -B password_checker.py --json`; the JSON includes metrics and recommendations, not the password. Do not pass a password as a command-line argument, where it could be exposed in shell history or process listings.

The CLI uses only the Python standard library. Its assessment does not read or write password files, contact a network, or load a password list from disk. Curated common-password and common-word lists are constants held in memory. Use Python's `-B` option as shown to prevent bytecode-cache writes. If the terminal cannot hide input, the CLI aborts instead of falling back to visible input.

### Optional: use a local web server

Open a terminal in the project folder and run:

```powershell

python -m http.server 8000 --bind 127.0.0.1

```
Then visit `http://localhost:8000/` in your browser. Stop the server with `Ctrl+C` when finished.

## 4. Features

- **Private by design:** analysis runs locally in the browser. The app does not save, log, or transmit the password and makes no network requests.
- **Useful feedback:** checks length and character classes, detects a curated set of common passwords and dictionary words, and flags repeated characters, repeated chunks, keyboard walks, and alphabetic or numeric sequences.
- **Transparent pattern checks:** shows which detectable patterns were found, or confirms that this limited local checker found none.
- **Entropy estimate:** displays an approximate upper-bound estimate with deductions for common and predictable patterns.
- **Secure password generator:** creates a random password from 8 to 64 characters. Choose which character types to include and optionally exclude look-alike characters such as `I`, `l`, `1`, `O`, and `0`. It uses the browser's cryptographic random-number generator.
- **Generator guardrails:** choose at least one character type; length and selection errors are validated before generation.
- **Adjustable length:** enter a value from 8 to 64 or drag the synchronized length slider.
- **Copy on request:** copy a password using the Copy button. The app never copies automatically and reports when clipboard access is unavailable.
- **Light and dark themes:** switch themes with the header button. The choice lasts for the current page session and is not stored.
- **Responsive interface:** works on desktop and mobile, with show/hide and clear controls.
- **No runtime dependencies:** plain HTML, CSS, and JavaScript; works offline.

## 5. Run the tests

Run the Python unit tests with:

```powershell
python -B -m unittest -v test_password_checker.py
```

To run the existing browser checker tests, install Node.js 18 or later, open a terminal in the project folder, and run:

```powershell
npm test
```

The test suite uses only Node.js built-ins; there are no packages to install.

## 6. How the assessment works

The checkers evaluate the entered password locally and report length, character classes, detected patterns, estimated strength, and suggestions. The Python CLI reports two distinct entropy measures.

**Empirical Shannon entropy** uses the observed frequency of each character:

```text
H = -Σ P(xᵢ) log₂ P(xᵢ)
```

Here, `P(xᵢ)` is the fraction of the password made up of character `xᵢ`. The CLI reports `H` in bits per character and `H × password length` as the empirical entropy for the sample. This describes the characters present; it does not prove that the password was randomly generated.

The separate **estimated search-space entropy** starts with:

```text
password length × log₂(estimated character pool size)
```

The pool approximation uses 26 lowercase letters, 26 uppercase letters, 10 digits, and 33 symbols for each class present; a non-ASCII character adds an approximate 100-character pool. The estimate is capped downward when common words/passwords, sequences, leetspeak substitutions, or repetition are found. These caps and pool estimates are heuristics, not measurements of actual randomness and not guarantees of security.

The Python CLI labels estimates below 28 bits **Weak**, 28–59 bits **Moderate**, and 60 bits or more **Strong**. Recommendations state the suggested minimum length at the detected pool size and identify missing character classes or specific patterns to replace. The browser interface uses its own scoring and labels:

| Estimated strength | Label  |
| ------------------ | ------ |
| Below 28 bits      | Weak   |
| 28–39 bits         | Fair   |
| 40–59 bits         | Good   |
| 60 bits or more    | Strong |

Browser passwords from 21 to 30 characters are labeled **Very strong** based on length, regardless of the entropy estimate or detected patterns.

For the browser checker, common passwords and predictable patterns can cap the displayed rating. Its checklist considers a password of at least 8 characters to meet its length requirement. Suggestions may recommend 14 or more characters for extra protection; this is guidance, not the checklist minimum.

Real password entropy depends on how the password was created. Human choices are usually less random than this character-pool formula assumes; a long, unique password generated by a reputable password manager is preferable.

## 7. Privacy notes

- The password is processed in volatile page memory for as long as it is entered.
- The app does not use cookies, local storage, analytics, network requests, or a backend.
- Generated passwords use the browser's cryptographic random-number generator. Copying is an explicit action; after copying, the password remains on the device clipboard until another value replaces it.
- Generator character selections and the look-alike exclusion are applied only when generating; they are not saved.
- The light/dark theme switch changes only the current page and is not saved.
- The clear button removes the value from the input. The app also clears it when the page is hidden or unloaded.
- As with any browser page, JavaScript cannot promise secure erasure of every copy from device memory. For maximum caution, use a password manager's built-in strength checks rather than entering an active account password into a website.
- **Python CLI:** input is requested using Python's hidden terminal prompt. The CLI's assessment code performs no password/file I/O and makes no network calls; results omit the password. It holds the input only while the process runs and does not securely erase memory, which Python and the operating system cannot guarantee.

## 8. Project layout

```text
.
├── assets/
│   └── shield-check.svg
├── src/
│   ├── app.js
│   └── password-audit.js
├── password_checker.py
├── test_password_checker.py
├── tests/
│   └── password-audit.test.js
├── index.html
├── package.json
├── README.md
└── styles.css
```

## 9. Limitations

This tool is educational. Its common-password and dictionary lists are intentionally small and are not an exhaustive breach corpus. It does not check whether a password has appeared in a data breach, and it does not replace a password manager, multi-factor authentication, or an organization's security policy.
