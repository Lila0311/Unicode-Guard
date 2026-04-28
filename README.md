# Unicode Guard

Unicode Guard is a lightweight detector for Unicode confusion attacks in source
code review and CI/CD pipelines. It implements the proposal's architecture:
one reusable rule-based engine, a local GUI, and CI-friendly command-line entry.

## Rule Basis

The rules are based on:

- Unicode UTS #39, especially identifier security profiles, confusable
  detection, mixed-script detection, restriction-level ideas, and mixed-number
  guidance.
- Unicode UTS #55, especially source-code handling guidance for bidi controls,
  invisible/default-ignorable characters, confusability diagnostics, and
  normalization visibility.
- Practical behavior from established tooling such as ICU SpoofChecker,
  compiler Trojan Source mitigations, and repository review warnings.

Implemented checks:

- `BIDI_CONTROL`: directional marks, embeddings, overrides, and isolates that
  can reorder displayed source.
- `BIDI_UNCLOSED`, `BIDI_UNPAIRED_PDF`, `BIDI_UNPAIRED_PDI`: malformed bidi
  stacks.
- `INVISIBLE_FORMAT`: zero-width spaces, joiners, soft hyphen, BOM, and other
  format controls.
- `VARIATION_SELECTOR`: variation selectors that can alter glyph rendering.
- `SUSPICIOUS_WHITESPACE`: non-ASCII spaces and line separators.
- `IDENTIFIER_NOT_NFC` and `IDENTIFIER_NFKC_CHANGES`: normalization hazards.
- `IDENTIFIER_MIXED_SCRIPT`: high-risk script mixtures inside one identifier.
- `IDENTIFIER_CONFUSABLE_ASCII`: identifier skeletons that resemble ASCII.
- `IDENTIFIER_COLLISION`: two different identifiers with the same visual
  skeleton in one file.

## Quick Start

Run the test suite:

```bash
python -m unittest discover
```

Scan a file or directory:

```bash
python -m unicode_guard path/to/source --fail-on HIGH
```

Emit JSON for CI annotations or dashboards:

```bash
python -m unicode_guard path/to/source --json
```

Write cleaned review copies with bidi controls, invisible controls, variation
selectors, and unusual whitespace removed or normalized:

```bash
python -m unicode_guard path/to/source --write-clean cleaned
```

Start the local GUI:

```bash
python -m unicode_guard.gui
```

On Windows, you can also double-click `run_gui.bat`.

## CI Integration

Example configurations are included in:

- `ci/gitlab-ci.yml`
- `ci/external-project-github-actions.yml`

The CLI exits with status `1` when any finding is at or above `--fail-on`.
The recommended CI setting is `--fail-on HIGH`, which blocks bidi attacks,
invisible controls, dangerous mixed-script identifiers, and skeleton collisions
while allowing lower-risk warnings to be reviewed manually.

For this repository, the GitHub workflow scans selected project paths because
`examples/` intentionally contains malicious demo samples. For another project,
use `ci/external-project-github-actions.yml`, replace `YOUR_USERNAME` with the
GitHub account that hosts Unicode Guard, and keep:

```bash
unicode-guard . --fail-on HIGH
```

The `.` means "scan the whole repository."

The active workflow for this repository is:

- `.github/workflows/unicode-guard.yml`

The `ci/` folder contains reusable templates and deliverables.

## Evaluation

Evaluation materials are included in:

- `samples/internal/`: project-authored mixed clean/attack samples.
- `samples/external_poc/`: public/adapted PoC samples, including selected
  Trojan Source PoC files under the MIT License.
- `samples/real_clean/`: clean samples for false-positive observation.
- `evaluate_samples.py`: evaluation summary script.

Run:

```bash
python evaluate_samples.py
```

Report-oriented notes, source references, and wording guidance are collected in
`REPORT_MATERIALS.md`.

## Notes and Limits

This project intentionally ships without mandatory third-party runtime
dependencies. It packages Unicode's official UTS #39 `confusables.txt` data and
uses it to strengthen ASCII-facing identifier skeleton detection. The detector
is still rule-based and lightweight; larger real-world evaluation would be
needed before making broad accuracy claims.
