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
npm run build                # produces out/ builds
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

Releases are cut from `main` only after the full deterministic and
authenticated qualification matrix is green on the exact candidate SHA.

1. Confirm `package.json`, `package-lock.json`, and the top `CHANGELOG.md`
   heading all carry the release version (`npm run verify:version`).
2. Run the complete deterministic gate:
   `npm run check`, `npm test`, `npm run test:mutation:core`,
   `npm run test:ui:smoke`, `npm run quality:full`,
   `npm run package && npm run package:verify`.
3. Ensure the CI `Deterministic build candidate` workflow is green on the
   exact SHA, including the reproducible VSIX artifact.
4. Run the authenticated qualification lanes (`deep-quality.yml` /
   `npm run quality:qualification:*` locally) and `npm run quality:release`.
5. Tag the release commit as `vX.Y.Z` — `npm run verify:version -- --release`
   asserts the tag matches `HEAD`.
6. Publish the CI-verified VSIX to the Visual Studio Marketplace
   (`vsce publish`) and the Open VSX Registry (`ovsx publish`) under the
   `Cloudsmith` publisher, then create the GitHub release with the VSIX,
   checksums, and provenance sidecars attached.

## License

By contributing, you agree that your contributions will be licensed under
the [Apache License 2.0](LICENSE).
