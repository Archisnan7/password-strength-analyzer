# Contributing

Thanks for considering a contribution! This is a small, single-file learning/utility project, so the bar is low but a few conventions keep it maintainable.

## Getting started

1. Fork the repo and clone your fork.
2. No dependencies to install (standard library only). If Tk isn't available on Linux: `sudo apt install python3-tk`.
3. Run the app: `python password_strength_analyzer.py`
4. Run tests: `python -m unittest discover tests`

## Guidelines

- **Keep GUI code and logic separate where possible.** Pure functions (`evaluate_password`, `name_reuse_found`, `dob_reuse_found`, etc.) should stay independent of Tkinter widgets so they remain unit-testable without a display.
- **Match the existing style.** 4-space indentation, snake_case for functions/variables, docstring-style comment headers above each function block.
- **Add/update tests** in `tests/test_evaluate_password.py` for any change to scoring or detection logic.
- **No new third-party dependencies** unless discussed in an issue first — part of the point of this project is that it runs anywhere Python + Tk does, with nothing else to install.
- **Don't commit real personal data** in tests or examples — use obviously fake names/dates.

## Reporting bugs / suggesting features

Please open an issue with:
- What you expected to happen
- What actually happened
- Steps to reproduce (for bugs) or a short rationale (for feature requests)

## Pull requests

- Keep PRs focused — one feature/fix per PR is easier to review.
- Make sure `python -m unittest discover tests` passes before opening the PR.
- Update the README if you add or change user-facing behavior.
