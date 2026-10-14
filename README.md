# Package hash provenance at an AI-agent install boundary

A hash check can accept changed package bytes if its expected hash was just calculated from those same changed bytes. This lab exercises **real pip**, using three authored, inert local wheels and three install policies. No AI model runs, no external package is downloaded and no fixture package is imported.

## Hypothesis and threat model

Assume a coding agent has selected a dependency whose supplier can replace the archive while preserving its name and version. The experiment supplies those replacement bytes directly. The harness, pip and original saved hash are trusted. This is a test of package installation policy, not proof of agent persuasion, repository compromise or malicious code execution.

Hypothesis: an original saved SHA-256 rejects a changed same-name/version archive, while version-only installation and a hash newly derived from the changed archive accept it. An ordinary unchanged archive must still install under every policy.

The counterfactual matters: writing a hash-bearing requirements file after obtaining untrusted bytes can preserve those bytes without establishing their trustworthiness.

## Setup and reproduction

Requires Python 3.11+ with pip already available. Recorded runtime: Python **3.13.5**, pip **25.1.1**, macOS. No additional Python packages are required. This is not a claim about every pip version or platform.

```sh
python3 experiment.py
python3 validate.py
```

The second command runs eight focused tests, reruns all nine installations, and writes artifacts/checks.json, run.json and evidence.md. Every run uses automatically cleaned temporary directories. A different Python/pip version changes recorded metadata and may change behavior; inspect the diff instead of assuming equivalence. Source code uses only the standard library and your installed pip.

For each installation the harness executes the following, using absolute paths inside its temporary directory:

```text
<PYTHON> -I -m pip install --no-index --find-links <wheelhouse> --no-deps --only-binary=:all: --no-compile --no-cache-dir --disable-pip-version-check --target <installed> -r <requirements.txt>
```

Both hash policies append `--require-hashes`. Version only uses `hash-fixture==1.0`. Saved hash adds the SHA-256 of the original wheel; Fresh hash instead adds the SHA-256 of the current wheel. The exact per-row requirements and commands are in [run.json](artifacts/run.json). `--no-index`, a generated local wheelhouse and no dependencies make this an offline test. No source distributions, build hooks, entry points or `.pth` files exist in the fixtures.

## Results

One run for each of three authored variants and three policies: nine installations. These are deterministic fixture observations, not population accuracy or attack-success rates.

| Supplied archive, all version 1.0 | Version only | Saved hash | Fresh hash |
|---|---|---|---|
| Original, value 42 | Installed 42 | Installed 42 | Installed 42 |
| Changed data, value 99 | Installed 99 | Hash mismatch, no installed files | Installed 99 |
| Ordinary metadata edit, value 42 | Installed 42 | Hash mismatch, no installed files | Installed 42 |

Eight tests passed with zero failures/errors. The rejection rows have pip exit 1, an explicit hash-mismatch message, no installed value and an empty target file inventory. Acceptance rows have exit 0 and the expected data. No rejected operation installs the original package instead.

Artifacts: [exact rows and logs](artifacts/run.json), [evidence summary](artifacts/evidence.md), [test record](artifacts/checks.json). Full temporary paths and Python executable paths are normalized; exit codes, values, hashes and pip output content are otherwise retained. The harness reads `value.txt` without importing the package.

## Technical walkthrough

1. Construct a deterministic wheel containing an empty `__init__.py`, a text value, standard metadata and a correct RECORD. Save the original archive digest. No payload executes.
2. Construct two alternate wheels with the same package name/version. One changes only the data value (and its RECORD entry); one changes the ordinary Summary metadata (and its RECORD entry).
3. Reuse each archive's exact bytes across all three installation policies, each with a fresh target and requirements file.
4. Under Saved hash, keep the original expected digest. Under Fresh hash, compute an expected digest from the currently supplied archive. Both use identical pip hash-verification options.
5. Invoke pip with a minimal explicit environment. Inherited tokens, proxy settings and pip options are not passed; PIP_CONFIG_FILE disables configuration files. `-I` ignores Python environment injection and user site packages. This is hygiene, not a verified OS sandbox.
6. Inspect the installed file inventory and text value. A process error only counts as the expected rejection if the explicit mismatch is present and no files were installed. Ordinary controls rule out a broken installer being mistaken for protection.

The original digest was `12c71d7584f59035cc39aacce65f1c23ce5b0615ccf8ecf28662af7d9564b2d4`; the changed-data digest was `1651d3823eb121e9bb2c69492b8e1037102872e964e3f9a78cfa9ae0b2b413a1`. Comparing changed data with the first value rejects it. Comparing it with the second succeeds. The hash algorithm is functioning in both cases.

The benign metadata twin is deliberate: Saved hash refuses even an ordinary wording edit. Content identity is not a maliciousness classifier. It requires a trustworthy process for approving new bytes.

## Source grounding

- [Trail of Bits, Package managers have an integrity problem](https://blog.trailofbits.com/2026/10/14/package-managers-have-an-integrity-problem/) studies package integrity under a malicious repository and motivates asking where the expected hash originates. This lab does not reproduce its multi-manager results or network harness.
- [pip secure-install documentation](https://pip.pypa.io/en/stable/topics/secure-installs/) specifies local requirement hashes and hash-checking mode. This experiment uses an existing pip capability, not a proposed patch or newly discovered pip vulnerability.

The independent contribution here is the contained three-policy comparison, particularly deriving a fresh expected digest from replaced bytes. The AI-agent connection is an engineering application: an automated installer must preserve the trusted expected value rather than treating successful verification of a newly learned value as package approval.

## Limits

- No autonomous agent, public registry, network interception, signatures, real package, malware, secret or external destination is exercised.
- A local wheelhouse stands in for attacker-supplied archive bytes. Network transport and repository metadata handling are not reproduced.
- No package is imported. Installed text is the sink; execution of changed code is not measured.
- One package, three chosen archives, one pip version/platform. No generalized prevalence or reliability estimate.
- Dependencies are absent and disabled. Complete transitive dependency verification needs separate tests.
- Trusted acquisition of the original digest is assumed. If an attacker can replace that record too, it is no longer an independent reference. Signed approvals, authorization and storage isolation are not implemented here.
- Hash agreement does not establish that the originally approved code was safe. Wheel RECORD consistency is maintained in every fixture; the check is against the entire archive digest.
- No concurrent mutation or check-to-use race is tested. The archives stay fixed during each pip invocation.

For an agent installer, keep approved archive hashes in a protected input, require their verification before installation, and fail when that input is absent or mismatched. Do not automatically turn a mismatch into a new trusted hash; separately review and authorize a new package baseline.
