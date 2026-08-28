# Release quality harness

This tracked directory is the source of truth for release-critical customer
workflows and their evidence contracts. A trigger, command dispatch, panel open,
HTTP success, or other intermediate result never counts as the authoritative
customer outcome.

The permanent inputs are:

- `critical-workflows.json`: customer journeys, risk classes, required test
  layers, named automated evidence, and designated live fixtures.
- `action-contracts.json`: producer provenance, consumer acceptance, freshness,
  canonical arguments, and rendered WebView wiring.
- `defect-taxonomy.json` and `finding.schema.json`: finding vocabulary,
  lifecycle, deterministic/live state, evidence, and escape analysis.
- `mutation-baseline.json`: measured high-risk mutation populations and policy.
- `release-checklist.md`: the human and CI release-qualification contract.

Generated output belongs under ignored `.quality/`. Run-specific findings and
live evidence belong under ignored `internal_docs/quality/`. Do not track or
upload a qualification profile, credential handoff, or secret-bearing log.

## Two qualification lanes

The deterministic/hermetic lane is CI-safe and uses an isolated, empty
credential profile. It runs unit and contract tests, real Extension Host tests,
mutation analysis, architecture/security/package gates, and signed-out
black-box UI smoke. The extension may call VS Code `SecretStorage` and receive
no credential; that is normal product behavior.

The authenticated release-qualification lane proves real rendered and
Cloudsmith outcomes against designated test resources. The production extension
uses its normal `SecretStorage` and authentication paths. Locally, it reuses the
dedicated persistent profile. CI uses a dedicated least-privileged non-human
test identity and the test-only bootstrap described below; that identity scope
and the GitHub environment policy require separate administrative confirmation.

The approved automated credential path is deliberately narrow: the secret-
bearing runner consumes its step-scoped input, writes the value once to the
creator-owned `0700`/`0600` one-use handoff, and the same-ID bootstrap consumes
that handoff into the production `SecretStorage` path. The environment entry
and handoff are deleted, mutable byte buffers are zeroed, and short-lived string
references are released at their defined boundary. This transient machine
transport and normal product storage are not
qualification evidence and must never be uploaded or reported.

Outside that reviewed path, agents, operators, UI drivers, other harness code,
logs, reports, artifacts, and reviewers must never inspect, extract, print,
copy, serialize, replay, hash, or otherwise expose a credential value from user
input, the handoff, SecretStorage, Keychain, or profile files. Local
authentication entry is a one-time manual handoff only when the dedicated local
session is absent or expired. Automation resumes after the user confirms
completion; it never observes password, API-key, or MFA entry.

Passing deterministic gates does not attest the authenticated lane. Team-test
readiness requires both lanes and a fresh, source-bound live attestation for
every workflow whose `liveFixture.required` value is `true`.

## Everyday and release commands

Run candidate packaging, black-box UI, mutation, and qualification commands
with the exact Node.js version declared by `.node-version`. Their production
entrypoints check that pin before invalidating prior evidence, and canonical
packaging rejects every other runtime because Node's compression implementation
participates in the byte identity of the VSIX. Quality gates and packaging also
require npm 10.9.8 from that exact Node.js distribution, as declared by
`.npm-version`; `.npm-integrity` binds the complete official npm installation
with separate exact POSIX and Windows fingerprints. PATH-provided or standalone
npm installations are not qualification toolchains. Each launcher first copies
the validated installation into a creator-private snapshot, executes only that
snapshot, and revalidates every snapshot and source file/directory identity
after the child exits. Windows additionally binds `COMSPEC` and npm's script
shell to the exact `%SystemRoot%\\System32\\cmd.exe`; the Windows CI row runs a
real package preflight rather than relying on platform-simulated unit fixtures.

The integrity pins are derived only from the official Node 22.23.2 platform
archives after their archive digests match Node's published `SHASUMS256.txt`.
For each extracted archive, run `npmInstallationFingerprint()` from
`scripts/quality/canonical-node-runtime.js` against the distribution-owned npm
package root (`lib/node_modules/npm` on POSIX and `node_modules/npm` on Windows),
confirm the complete entry counts and bytes, and commit the resulting POSIX or
Windows content digest. Never derive a pin from a global, Homebrew, or standalone
npm installation.

```bash
npm run quality:impact -- --base origin/main
npm run quality:fast
# implement and run every layer selected by the impact report
npm run quality:full
```

For release qualification:

```bash
npm run quality:secrets
npm run test:ui:smoke
npm run quality:qualification:prepare
npm run quality:qualification:launch
npm run quality:release
```

`quality:release` composes the deterministic gates, executes signed-out
black-box UI smoke, validates the authenticated attestation, and runs the full
history secret scan. A missing authenticated attestation or an open external
security finding remains a blocker; neither is disguised as deterministic
failure. The release profile never deletes fast/full profile receipts. If those
trees are present, release exposure accepts them only when they are complete,
canonical, current-source, current-plan, and byte-stable; stale, partial, unsafe,
or changed trees fail closed.

## Secret-exposure gates

The repository pins Gitleaks and emits a deliberately restricted report that
contains only rule ID, file, line range, and commit. It excludes matched values,
fingerprints, entropy, author data, and commit messages.

```bash
npm run quality:secrets             # Git-visible current source + generated/VSIX surfaces
npm run quality:secrets:artifacts   # generated quality evidence and every discovered VSIX
npm run quality:secrets:evidence    # refresh safe post-gate evidence
npm run quality:secrets:history     # all reachable Git refs/history
```

The fast gate runs the current-source scan. Full runs the artifact scan after
packaging. Release runs the history scan as a finalizer so an existing history
blocker cannot suppress otherwise safe qualification work, but still prevents
release readiness. Allowlists must be narrow and justified; never weaken the
gate merely to make historical exposure disappear.

## Candidate preparation and profile ownership

The canonical persistent local qualification root is exactly:

```text
$HOME/.cloudsmith-vscode-qualification/
  home/
  user-data/
  extensions/
```

The harness canonicalizes the root, requires a private ownership marker and
real non-symlink directories, and never touches the user's normal VS Code
profile. CI and signed-out UI runs create creator-bound, private temporary
profiles with `home/`, `settings/`, and `extensions/`; cleanup refuses a profile
the current process did not create. Use `npm run quality:qualification:reset`
only to remove the validated dedicated local profile when an intentional clean
reauthentication is needed.

Nested non-auth tooling propagates cleanup refusal across process boundaries
through a pre-created empty parent receipt. A child opens that receipt with
no-follow semantics, verifies its complete non-secret file identity, and writes
only through the verified descriptor. The parent then quarantines the complete
boundary instead of recursively deleting a child quarantine. The receipt
contains no runtime output, credential, or digest, and a pathname substitution
cannot redirect the write into a foreign tree.

Preparation, packaging, installation, and signed-out/CI execution keep their
private synthetic home. The interactive local launch starts the exact app
executable as a cold process and restores only the canonical OS account
`HOME`/`USERPROFILE` identity so VS Code can use its normal OS-backed
SecretStorage keyring; explicit user-data, extension, XDG, `APPDATA`, and
`LOCALAPPDATA` paths remain qualification-owned. A launch that exits during its
bounded ownership probe fails closed instead of forwarding to an already
running qualification process. The harness never selects the insecure `basic`
password store and never reads the keyring or qualification-profile contents.
Do not invoke the product's explicit Cloudsmith CLI credential-import action in
this profile because restoring the account home also restores its normal CLI
lookup locations. A same-process SecretStorage write/read is intermediate
evidence; the authenticated lane must still prove persistence through window
reload and a full cold restart.

`quality:qualification:prepare` owns the complete candidate lifecycle:

1. invalidate stale candidate evidence;
2. safely remove only Git-proven untracked/ignored `.DS_Store` and `._*` files;
3. bind the exact branch source SHA and complete working-tree fingerprint;
4. invoke the canonical package command and accept only its exact emitted VSIX;
5. verify sidecars, archive contents, source identity, and SHA-256;
6. install verified private bytes with the app-bundled VS Code CLI into the
   isolated extensions directory;
7. verify the one installed extension ID and version; and
8. write ignored `.quality/qualification/candidate.json` before launch.

The local current-product lane additionally replaces
`.quality/qualification/live-candidate.{json,vsix}` only after verification
succeeds. Authenticated CI writes its separate ephemeral-profile proof to
`.quality/qualification/authenticated-candidate.{json,vsix}`. Each dedicated
receipt and byte-stable VSIX copy is invalidated before its lane attempts
preparation, so deletion, partial preparation, source drift, or artifact drift
cannot reuse a prior live PASS. The local and CI profile identities and receipt
fingerprints intentionally differ; validation requires their immutable
source/VSIX/extension/install/current-VS-Code identities to match exactly.
Candidate receipt schema v3 also binds the exact Node version, npm version,
full npm-installation fingerprint, and producer platform to the repository's
reviewed toolchain pins.

On macOS, the no-argument prepare and launch commands first resolve
`command -v code`, canonicalize it to a real app-bundled CLI, and then fall back
to `/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code`.
They verify the selected CLI reports the exact current qualification pin. A
missing, replaced, non-bundled, or different-version app fails closed; other
platforms must pass an exact VS Code executable explicitly.

After junk cleanup, preparation reruns `verify:polish` before source capture or
packaging. The receipt binds capture time, branch, value-blind clean/dirty Git
status, source SHA/fingerprint, extension version, relative and absolute VSIX
paths and SHA-256, VS Code executable/CLI/version, profile paths, and installed
identity. Qualification refuses a development path or a stale same-version
VSIX. Local authenticated qualification uses the current tested VS Code pin
(`1.134.0`). ExTester `8.24.0` uses its maximum supported stable VS Code pin
(`1.131.0`) in a separate ephemeral profile.

## Authenticated CI bootstrap

The authenticated job declares the `cloudsmith-release-qualification` GitHub
environment and uses a dedicated non-human Cloudsmith test credential. Workflow
source alone cannot prove that environment reviewer, branch, or deployment
protection rules are configured; confirm those repository settings separately.
Candidate preparation and exact validation run in a credential-free step. Only
the following minimal direct-Node product step receives the Actions secret; it
deletes the environment entry before any child process and transfers the value
only through a private owner-only temporary handoff. A narrowly scoped test-only
companion extension shares the production extension ID only for the bootstrap
launch. The handoff is created immediately before seed, stored under the
production `SecretStorage` key using the production credential envelope, and
deleted by the bootstrap host before it exits. The production candidate then
launches from the same ephemeral profile and reads `SecretStorage` normally.
The cross-step candidate-session receipt accepts cleanup only when the `csvq-`
profile is a direct child of the canonical real `RUNNER_TEMP` (when configured)
or `os.tmpdir()` base; a self-fingerprinted arbitrary parent is insufficient.

The product verifier launches current VS Code (`1.134.0`) directly with no
extension-development path and a private loopback DevTools endpoint. It drives
the rendered Command Palette, invokes `Cloudsmith: Set default workspace`, and
accepts success only when the forced production workspace picker contains an
enabled selectable row whose description is exactly
`dl-technology-consulting`. It dismisses the picker without mutating the
setting. Input values, messages, disabled rows, non-exact descriptions, and
other Quick Input surfaces cannot satisfy the proof. DevTools returns only
bounded booleans to the harness; arbitrary DOM text, child stdout, and child
stderr are never returned. Linux/macOS launches use an owned detached process
group and require proof that the complete group exited after graceful close,
`SIGTERM`, or `SIGKILL`; Windows fails closed unless a Job Object-backed tree
adapter is supplied. The launch does not disable the Chromium sandbox.

The bootstrap is excluded from the VSIX, has no production bypass, and fails
closed when the secret or designated fixture workspace is missing/wrong.
Immediately after the product verifier returns on either success or failure,
the harness attempts `SecretStorage` deletion before any exposure scan. Handoff,
current-worktree scan, external log/artifact scan, runtime-log deletion, and
profile deletion are then attempted independently so one cleanup failure cannot
suppress another; process-tree and credential-cleanup failures take precedence.
When owned process-tree exit is unproven, in-run profile deletion is withheld,
cannot be recorded as passed, and the authenticated session receipt remains for
the workflow's always-run cleanup retry. This prevents a surviving process from
recreating a supposedly cleaned profile after consuming its retry ownership.
If credential deletion fails after full process-tree exit was proven, the
harness captures a one-use profile-metadata proof and removes the profile before
the longer external scans; those scans consume the proof without reopening the
deleted profile. A failed early profile removal is retried after the scans.

Before computing any post-auth source fingerprint, the harness scans the current
Git-visible worktree value-blind and compares an in-memory, content-free Git
path/status snapshot. A finding or drift prevents the fingerprint entirely.
Generated logs are redirected to a separate private harness-owned directory,
then those logs, generated evidence, and the exact raw/expanded candidate VSIX
are scanned before the log root and profile are deleted. Every scanner process
uses a new private `HOME`, `USERPROFILE`, XDG, application-data, and temporary
root. The profile boundary is checked through path and permission metadata only:
no profile file, SecretStorage database, or Keychain content is read.

The authenticated exposure receipt must contain the exact generated-evidence,
candidate-VSIX, runtime-log, and profile-metadata-only components. Final release
PASS validation loads and binds `.quality/secrets/authenticated-ci.json`; a
missing, crossed, or non-passing exposure receipt fails closed. Only the
dedicated candidate proof (receipt plus its byte-stable, scanned VSIX copy) and
value-blind authentication/exposure receipts may be uploaded; no CI profile,
runtime-log directory, credential handoff, matched secret, or secret-derived
digest is retained. QH-010 remains open until credential rotation or revocation
is separately confirmed, even when every non-destructive qualification check
passes.

The ephemeral CI candidate proof is distinct from the persistent local
`live-candidate` proof used for final Computer Use qualification. Release
validation reconciles them only through immutable source, VSIX, extension,
installed identity/version, and current-VS-Code fields; ephemeral profile roots
and receipt fingerprints are not interchangeable with the local proof.

## Black-box UI and false-green proof

The ExTester runner packages and verifies its exact candidate, installs it in
an isolated signed-out profile, and records executed test names rather than a
source-declared count. It first executes an intentionally wrong selector probe
and requires the precise expected failure. It then resets user data and runs the
real suite in a fresh profile. The final receipt binds the exact candidate
receipt, source, VSIX hash, extension version, ExTester version, VS Code version,
platform, architecture, launch attempt, and every passing test.

The signed-out palette proof requires the authentication-setup command to be
enabled and both Connect and Clear stored credentials to be absent, not merely
disabled.

This ExTester lane has a bounded limitation: it does not independently
instrument the inactivity of VS Code's built-in authentication providers. Its
signed-out conclusion therefore relies on the creator-owned empty profile plus
the observed signed-out production command terminals above. The wrong-selector
probe, profile reset, and executed-test receipt protect that stated boundary;
they do not turn it into authenticated acceptance, which remains a separate
qualification lane.

Black-box smoke supplements rather than replaces deterministic contract and
Extension Host coverage. Material fixes outside the configured Stryker scope
still require a reversible false-green proof at the escaped boundary.

## Findings and readiness

Every finding has one primary domain:

```text
product | test-harness | ci | release-evidence | security-environment |
documentation | external-platform
```

`deterministicStatus` is `failing`, `fixed`, or `not-applicable`.
`liveStatus` is `not-required`, `pending`, `blocked`, `verified`, or `failed`.
Lifecycle `status` is separate. `releaseBlocking` is derived from severity,
domain, criticality, lifecycle, deterministic state, and required live state;
callers may not override it. Reports publish separate counts by domain,
severity, deterministic state, and live state so harness/evidence defects are
not mislabeled as product bugs.

A deterministic fix with pending or blocked required live verification remains
unverified. Schema-v5 live attestations and schema-v3 derived status bind each
live PASS to the exact local qualification receipt fingerprint, stable VSIX
SHA-256, extension and installed ID/version, source SHA/fingerprint, VS Code
version, and a one-way identity of the non-secret profile `{mode, root}`
metadata. The authenticated-CI receipt separately binds its own ephemeral CI
candidate/profile and is written as passed only after the production connected
workspace verifier and value-blind SecretStorage/profile cleanup lifecycle
succeeds. Local and CI proof must agree on immutable product identity, without
falsely equating their receipt or profile identities. Missing, crossed, stale,
or mismatched candidate proof fails closed.
Every required workflow has exactly one `PASS`, `FAIL`, `PARTIAL`, or `BLOCKED`
matrix row; blank rows are invalid. No credential or profile content enters
these receipts.

## Permanent change flow

For a feature:

1. run impact analysis and name each affected workflow/action contract;
2. update the tracked contract when the customer journey changes;
3. prove producer to consumer to authoritative outcome, including negative,
   default, stale, provenance, and canonical-identity cases;
4. run every selected layer, mutation/false-green proof, and applicable live
   fixture; and
5. record independent review and rerun material corrections.

For a bug, additionally freeze the finding before production edits, add a
red-before-green regression at the escaped boundary, prove root cause, kill the
old behavior, update deterministic/live status separately, and retain escape
analysis in the ignored ledger. Raw test count and command dispatch are never
release evidence.
