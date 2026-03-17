# Contributing Guidelines

NOTE: Contribution implies licensing under the terms of [LICENSE](LICENSE) (AGPL-3).

## Pull Request Checklist

- Confirm the PR is against the `main` branch.
- Ensure commit messages follow the [conventional commits] style.
- Ensure commit messages adequately explain the reasons for the changes.
- Ensure changes are consistent with the project's [design philosophy]: precision over recall, conjunctive detection rules, fail-open for external APIs.
- Ensure that tests were added or that the manual testing process followed is described in the PR.
- Run the [tests](#running-tests).
- All source files must include `from __future__ import annotations` (project convention).

## Writing Good Commit Messages

- Keep the first line short but informative.
- Provide explanation of why the change is being made in the commit message body.
- Prefer copying relevant information into the commit body over linking to it.
- Consider whether your commit message includes enough detail for someone to be able to understand it in the future.

## Branching Workflow

- New branches are created from `main`.
- When complete, new branches are merged to `main` via pull request.

## Running Tests

```bash
# Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Run all tests
python3 -m pytest tests/ -v

# Run a single test file
python3 -m pytest tests/test_rules.py -v

# Run a single test class or method
python3 -m pytest tests/test_rules.py::TestSeedPhraseRule -v
```

Live integration tests (`tests/test_known_bad.py`) are excluded from CI. Run manually:

```bash
python3 -m pytest tests/test_known_bad.py -v -s
```

## Adding a New HTML Detection Rule

1. Create `src/rules/your_rule.py` implementing the `Rule` ABC from `src/rules/base.py`
2. The rule **must** require 2+ independent signals (conjunctive logic) — single-signal rules are not accepted
3. Add a toggle to `Settings` in `src/config.py` (e.g., `rule_your_rule: bool = True`) and read the env var in `load_settings()`
4. Register the rule in `RuleEngine.__init__()` in `src/rules/engine.py`
5. Add test cases in `tests/test_rules.py` with HTML fixtures in `tests/fixtures.py`
6. Add the toggle to `.env.example` and document in `README.md`

## Adding a New Content Scanner

Content scanners handle non-HTML content types (images, PDFs, video, etc.) via the pluggable Tier 2 scanning architecture.

1. Create `src/scanners/your_scanner.py` implementing the `ContentScanner` ABC from `src/scanners/base.py`
2. Implement the three required members:
   - `name` property — unique scanner identifier (e.g., `"csam-detection"`)
   - `supported_content_types` property — set of MIME patterns (e.g., `{"image/*", "video/*"}`)
   - `evaluate()` async method — scan content and return a `ContentScannerResult`
3. Add a toggle to `Settings` in `src/config.py` (e.g., `scanner_your_scanner: bool = False`) and read the env var in `load_settings()`
4. Register the scanner in `build_app()` in `src/server.py`, gated by the toggle
5. Add unit tests in `tests/test_scanners.py` and integration tests in `tests/test_scanner_content_routing.py`
6. Add the toggle to `.env.example` and document in `README.md`

See `src/scanners/example_image_scanner.py` for a reference implementation.

## Design Constraints

- **Precision over recall**: Incorrectly blocking legitimate content is worse than missing malicious content. Every detection requires 2+ independent signals.
- **ML never auto-blocks**: The XGBoost classifier can only escalate CLEAN to SUSPICIOUS, never to MALICIOUS.
- **Fail-open for external APIs**: External service errors (Safe Browsing, peer feeds, content scanner APIs) must never affect scanning or block legitimate content.
- **Feature vector is frozen**: The 17 features in `src/ml/features.py` cannot change without retraining the model.
- **`from __future__ import annotations`**: Required in all source files.

[conventional commits]: https://www.conventionalcommits.org/en/v1.0.0/
[design philosophy]: ./CLAUDE.md
