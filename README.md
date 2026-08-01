# 🔐 Password Strength Analyzer

A desktop GUI app (built with Python's `tkinter`) that analyzes password strength in real time — checking entropy, common leaked passwords, sequential/repeated patterns, and reuse of personal info like your name or date of birth — then suggests stronger alternatives generated with a cryptographically secure RNG.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

## Preview
<img width="960" height="600" alt="Screenshot 2026-08-01 104546" src="https://github.com/user-attachments/assets/e6ba0edf-e0c9-44b9-a661-9734b13b591b" />
<img width="960" height="600" alt="Screenshot 2026-08-01 104710" src="https://github.com/user-attachments/assets/bc00d9fa-7b31-4b44-81aa-6a5cb9e4bf9a" />


## Features
- **Real-time analysis** — strength updates as you type, no submit button needed
- **Entropy estimation** — practical entropy in bits, scaled down for detected weaknesses
- **Leak detection** — flags passwords found in a curated common/breached password list
- **Pattern detection** — catches sequential runs (`1234`, `abcd`), repeated characters (`aaaa`), and leetspeak-obfuscated weak words (`P@ssw0rd` → `password`)
- **Personal info reuse checks** — warns if the password contains parts of your name or date of birth (both optional, entirely local — nothing is sent anywhere)
- **Smart suggestions** — strips out the exact weak substrings it found and rebuilds a stronger password from what's left, rather than just appending random characters
- **Secure password generator** — one-click 12-character password using Python's `secrets` module (CSPRNG, not `random`)
- **Show/hide + copy to clipboard** — with a small "Copied!" confirmation

## Why this exists

Most "password strength" widgets just check length and character classes. This one adds the checks that actually matter for real-world security: leaked-password lookups, personal-info reuse, and pattern detection — while keeping everything 100% local and offline.

## Installation

No external dependencies — everything used (`tkinter`, `secrets`, `string`, `math`, `re`) is part of the Python standard library.

```bash
git clone https://github.com/Archisnan7/password-strength-analyzer.git
cd password-strength-analyzer
python password_strength_analyzer.py
```

**Requirements:** Python 3.8+ with Tk support.
- Windows/macOS: Tk ships with the standard python.org installer.
- Linux: you may need to install it separately, e.g. `sudo apt install python3-tk`.

## Usage

1. Run the app.
2. (Optional) Enter your name and date of birth — used only to flag reuse in your password, never stored or transmitted.
3. Type a password into the field to see live strength, entropy, and suggestions.
4. Click **Generate Key** for a random secure password, or use one of the suggested alternatives.
5. Click the copy icon to copy the password to your clipboard.

## How scoring works

Each password starts at a base score and gains points for:
- Length ≥ 8 characters
- Containing uppercase, lowercase, digits, and special characters

...and loses points for:
- Matching a known weak pattern (`123`, `password`, `qwerty`, etc.), including leetspeak variants
- Sequential runs (`1234`, `abcd`) or repeated character runs (`aaaa`)
- Containing part of the provided name or date of birth
- Matching a known commonly-leaked password (auto-scores 0)

| Score | Strength |
|-------|----------|
| 0–2   | Weak     |
| 3–4   | Medium   |
| 5+    | Strong   |

> **Note:** The common-password list and pattern list are small, static, offline demo lists. A production tool should check against a real breach dataset (e.g. the [HaveIBeenPwned k-anonymity API](https://haveibeenpwned.com/API/v3#PwnedPasswords)) instead.

## Project structure

```
password-strength-analyzer/
├── password_strength_analyzer.py   # Main application (GUI + logic)
├── tests/
│   └── test_evaluate_password.py   # Unit tests for the scoring logic
├── screenshots/
│   └── demo.png                    # App screenshot for README
├── .github/
│   └── workflows/
│       └── ci.yml                  # GitHub Actions: lint + test on push
├── requirements.txt                # (empty — stdlib only, kept for convention)
├── .gitignore
└── LICENSE
```

## Running tests

```bash
python -m unittest discover tests
```

## Roadmap / ideas for contributions

- [ ] Swap the static leaked-password list for the HaveIBeenPwned API (k-anonymity, so the full password is never sent)
- [ ] Add a CLI mode (`--check "mypassword"`) for scripting/CI use, separate from the GUI
- [ ] Localization / i18n for suggestion text
- [ ] Configurable scoring weights
- [ ] Package as a standalone executable (PyInstaller) for non-technical users

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security note

This tool is for **educational and personal use**. Password strength checking happens entirely offline — no password, name, or DOB you enter is ever transmitted or logged. Do not rely on this alone for enterprise password policy enforcement.

## License

MIT — see [LICENSE](LICENSE).
