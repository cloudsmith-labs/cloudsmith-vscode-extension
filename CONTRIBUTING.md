# Contributing to the Cloudsmith VS Code Extension

Thank you for your interest in contributing. This repository has a strict,
evidence-based quality model; the sections below describe the required
toolchain, test layers, and release process.

## Toolchain (required, exact)

Local development and packaging require the exact pinned toolchain:

- **Node.js `22.23.2`** (`.node-version`)
- **npm `10.9.8`** (`.npm-version`)

Install Node 22.23.2 with your preferred version manager (nvm, mise, volta,
fnm, or the official distribution). The bundled npm in that Node release is
already 10.9.8.

Several gates verify the canonical runtime and refuse other versions:

- `npm test`, `npm run check`, `npm run package`, `npm run test:ui:smoke`,
  and the mutation gates assert the exact Node pin.
- `test:ui:smoke` also asserts the canonical npm installation. A
  `UI_TOOL_RUNTIME_UNSUPPORTED` failure means the Node/npm pin does not
  match; a `UI_TOOL_UNSUPPORTED` failure means the pinned ExTester/VS Code
  contract does not match.
- macOS/Windows editor junk (`.DS_Store`, `Thumbs.db`, `*.swp`, `*~`) does
  not fail the polish gate when it is `.gitignore`d; junk that Git would
  track or that could enter a package still fails closed.

Install dependencies with lifecycle scripts disabled:

```bash
npm ci --ignore-scripts --no-audit --no-fund
```

## Everyday commands

```bash
npm run lint                 # ESLint, zero warnings allowed
npm run syntax               # syntax validation of all JavaScript
npm run build                # validates runtime source and assets; emits nothing
npm run verify:architecture  # production architecture + command parity
npm run verify:polish        # docs/media/settings polish gate
npm run verify:version       # package.json vs lockfile vs CHANGELOG
npm run check                # all of the above (also vscode:prepublish)
npm test                     # lint + node suite + Extension Host suites
```

## Quality harness

The repository uses layered, contract-based qualification rather than raw
coverage. Before feature or bug-fix work, run the impact analysis and keep
the affected workflow contracts green:

```bash
npm run quality:impact -- --base origin/main   # required before implementation
npm run quality:fast                           # fast deterministic gate
npm run quality:full                           # full deterministic gate
npm run test:node                              # mocha unit/contract suite
npm run test:vscode -- --label core            # Extension Host: core lane
npm run test:vscode -- --label smoke           # Extension Host: smoke lane
npm run test:mutation:changed -- --base origin/main
npm run test:mutation:core
npm run test:ui:smoke                          # ExTester signed-out UI lane
npm run package && npm run package:verify      # reproducible VSIX + verify
npm run audit:runtime && npm run audit:dev     # dependency audit gates
```

Notes:

- `npm run test:ui:smoke` downloads and launches a real VS Code build
  against the exact verified VSIX; it is heavy and is normally exercised
  in CI.
- `npm test` runs the node suite plus the configured Extension Host
  lanes in a real Extension Development Host.
- Dependency audit exceptions live in
  `scripts/release/audit-exceptions.json`; they are time-boxed (max 90
  days) and must name an exact GHSA, owner, rationale, and review date.
  Exceptions are rejected when a fix path exists.

## Protected files

Do not modify the following files unless your task explicitly names them
as in scope:

- `util/cloudsmithAPI.js`
- `util/credentialManager.js`
- `util/connectionManager.js`
- `util/ssoAuthManager.js`

Report issues found in them instead of editing them.

## Code conventions

- JavaScript only, CommonJS `require()`/`module.exports` everywhere.
- Zero runtime dependencies; only VS Code APIs, native `fetch`, and the
  Node standard library.
- Every new non-test source file starts with
  `// Copyright 2026 Cloudsmith Ltd. All rights reserved.`
- No stubs, TODO placeholders, or dead code; one canonical pattern per
  operation.

## Pull requests

- Branch from `main` with a conventional prefix: `fix/`, `feat/`,
  `docs/`, `chore/`, `refactor/`, `test/`, `ci/`, `build/`, `perf/`,
  `security/`, `deps/`, `release/`.
- Use conventional commit messages (`fix:`, `deps:`, `test:`, …).
- Keep PR bodies to a `### Summary` and `### Validation` section.
- Run `npm run lint` and `npm test` (plus every gate your impact report
  lists) before pushing.
- Copilot and CodeQL reviews are secondary reviewers; address or
  disposition their findings before merge.

## Releasing

Release qualification is a pre-merge gate: it runs on the exact candidate
SHA as the head of a **draft** pull request. `main` only receives the
candidate after the acceptance artifact passes `npm run quality:release`.

1. Confirm `package.json`, `package-lock.json`, and the top `CHANGELOG.md`
   heading all carry the release version (`npm run verify:version`).
2. Run the complete deterministic gate:
   `npm run check`, `npm test`, `npm run test:mutation:core`,
   `npm run test:ui:smoke`, `npm run quality:full`,
   `npm run package && npm run package:verify`.
3. Push the candidate as a draft pull request and wait for CI
   (`main.yml`, CodeQL, signed-out packaged UI) to go green on its head
   SHA, including the reproducible VSIX artifact.
4. Collect the remote CI proof while the draft PR is still open — the
   collector requires a draft PR whose head branch and SHA match the
   checkout:
   `npm run quality:remote-ci:collect -- --pr <N> --main-run <run-id> --codeql-run <run-id>`
   (writes `internal_docs/quality/remote-ci.json`, `remote-ci-api.json`,
   and the `.quality/remote-ci/signed-out-ui` bundle).
5. Run **both** required authenticated qualification lanes against the
   exact packaged candidate — the release policy requires
   `authenticated-local` *and* `authenticated-ci`; neither substitutes
   for the other:
   - `authenticated-local`: `npm run quality:qualification:prepare` and
     `npm run quality:qualification:launch` in the dedicated persistent
     local profile. On Linux and Windows automatic VS Code discovery is
     unavailable — pass the pinned install explicitly, e.g.
     `npm run quality:qualification:prepare -- --vscode-executable <path>`
     (and `--vscode-cli <path>` where the CLI is separate).
   - `authenticated-ci`: dispatch `deep-quality.yml` on the candidate SHA;
     its `authenticated-production-ui` job runs in the
     `cloudsmith-release-qualification` environment and uploads the
     `authenticated-ui-evidence-<sha>-<attempt>` artifact.
6. Capture the authenticated-local observation under
   `internal_docs/quality/` and aggregate the candidate lane store:
   `node scripts/quality/aggregate-candidate-lanes.js --authenticated-evidence internal_docs/quality/<observation>.json`
   (writes `internal_docs/quality/current-candidate-lanes.json`).
7. Author the schema-v7 acceptance artifact
   `internal_docs/quality/current-candidate-acceptance.json` bound to the
   candidate SHA and tracked readiness policy, with
   `readinessTarget: "release"`, the exact evidence paths (remote CI
   receipt and signed-out UI bundle, findings ledger, and both
   authenticated qualification receipts), `operatorId`, `completedAt`
   inside the 24-hour readiness window, zero open release blockers, and
   `checklistConfirmed`. Then run `npm run quality:release`.
8. Merge the draft pull request, then tag the **qualified candidate
   SHA** — the pre-merge PR head, not the merge or squash commit — as
   `vX.Y.Z`. The VSIX provenance, remote CI receipt, and acceptance
   artifact all bind that SHA; `package:verify --current-source` rejects
   the artifact at any other commit. Check out the candidate SHA and
   verify the tag against it:
   `git checkout <candidate-sha> && GITHUB_REF_NAME=vX.Y.Z npm run verify:version -- --release`
   (the release check reads the tag name from `GITHUB_REF_NAME`, which CI
   sets automatically).
9. Download the CI-verified VSIX artifact built on the candidate SHA and
   publish that exact file —
   `vsce publish --packagePath <vsix>` to the Visual Studio Marketplace and
   `ovsx publish <vsix>` to the Open VSX Registry under the `Cloudsmith`
   publisher. Do not let either publisher repackage the working tree. Then
   create the GitHub release with the VSIX, checksums, and provenance
   sidecars attached.

## License

By contributing, you agree that your contributions will be licensed under
the [Apache License 2.0](LICENSE).
