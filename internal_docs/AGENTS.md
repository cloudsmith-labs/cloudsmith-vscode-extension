# AGENTS.md - Cloudsmith VS Code Extension

## Project Overview

This is a VS Code extension (`cloudsmith-vsc`) that provides package intelligence, security remediation, and developer productivity features for the Cloudsmith artifact management platform. It is JavaScript-only (CommonJS modules), has zero runtime dependencies, and uses the Cloudsmith REST API v1 and v2.

## Git Workflow

Codex is authorized to use the local terminal and Git/GitHub tooling directly to create branches, commit changes, push branches, and open pull requests when completing development work.

Git operations should be performed in the normal local repository context rather than through a restricted or sandboxed Git workflow.

### Branches

* **DO** create a dedicated branch for each logical unit of work.
* Branch names must describe the work itself and use an appropriate conventional prefix.
* Keep branch names concise, lowercase, and hyphen-separated.
* Create branches under the developer's normal local Git identity and GitHub account.
* **DO NOT** include `codex`, `openai`, `ai`, `agent`, or similar references in branch names.
* **DO NOT** create branch names or metadata that imply the work was authored by Codex or another automated system.

Use the most appropriate prefix from the following:

* `fix/...` - bug fixes and behavioral corrections
* `feat/...` - new product functionality or capabilities
* `docs/...` - documentation-only changes
* `chore/...` - repository maintenance and general housekeeping
* `refactor/...` - structural changes that should not intentionally alter behavior
* `test/...` - test-suite additions, test infrastructure, or test-only changes
* `ci/...` - CI/CD workflow and automation changes
* `build/...` - build system, packaging, compilation, or build-tooling changes
* `perf/...` - performance and scalability improvements
* `security/...` - security hardening where security is the primary purpose of the change
* `deps/...` - dependency upgrades, dependency cleanup, or dependency-policy changes
* `release/...` - release preparation, versioning, publishing, or artifact-management changes

Prefer the prefix that best communicates the **primary purpose** of the branch rather than creating compound prefixes.

Examples:

* `fix/transactional-dependency-scan`
* `fix/atomic-credential-replacement`
* `feat/workspace-trust-support`
* `docs/update-extension-development-guide`
* `chore/remove-legacy-paths`
* `refactor/typed-api-transport`
* `refactor/canonical-package-model`
* `test/dependency-resolution-coverage`
* `ci/extension-validation-gate`
* `build/reproducible-vsix`
* `perf/bounded-repository-pagination`
* `security/generated-install-commands`
* `deps/update-vscode-test-tooling`
* `release/prepare-2-3-0`

Use `fix/` for a security issue when the work is fundamentally correcting a specific defect. Use `security/` when the primary scope is broader security hardening or establishment of a security boundary.

Similarly, use `chore/` for general maintenance, while `ci/`, `build/`, `deps/`, and `release/` should be preferred when one of those areas is specifically the purpose of the work.

### Commits

* **DO** stage and commit completed work after reviewing the diff and running required validation.
* Keep commits logically scoped to the work being performed.
* Use clear conventional commit messages where appropriate.

Examples:

* `fix: make dependency scans transactional`

* `feat: add workspace trust enforcement`

* `refactor: introduce typed API transport`

* `test: add dependency scan cancellation coverage`

* `ci: validate extension package in pull requests`

* `build: add reproducible VSIX packaging`

* `perf: bound repository search concurrency`

* `security: harden generated install commands`

* `docs: update extension development workflow`

* Commits must use the developer's configured Git identity.

* **DO NOT** add Codex, OpenAI, AI-generated, agent-generated, or similar attribution to commit messages, authorship, co-author trailers, or metadata unless explicitly required by another repository policy.

* **DO NOT** rewrite unrelated history or modify commits outside the scope of the current task.

* **DO NOT** force-push unless explicitly required and safe to do so.

### Pushes

* **DO** push the completed branch to the normal repository remote after validation succeeds.
* Push only the branch associated with the current task.
* Do not push unrelated local branches or changes.
* Confirm the intended remote and branch before pushing.

### Pull Requests

* **DO** open a pull request for completed work when the task calls for submitting, finalizing, or completing an implementation.
* Pull requests must be opened under the developer's normal GitHub account.
* **DO NOT** mention Codex, OpenAI, AI assistance, agents, automated authorship, or similar attribution in the PR title or description unless another repository policy explicitly requires disclosure.
* **DO NOT** automatically merge a pull request unless explicitly instructed.

PR titles should be concise and describe the primary change.

Examples:

* `fix: make dependency scanning transactional`
* `security: harden generated install commands`
* `refactor: introduce typed Cloudsmith API transport`
* `perf: add bounded repository pagination`
* `ci: add extension validation gate`
* `build: make VSIX packaging reproducible`

PR descriptions should be concise, clear, and useful for future engineering and audit review.

Use the following structure unless the repository has a required PR template:

### Summary

* Briefly describe the primary change.
* List the material implementation changes as concise bullets.
* Call out meaningful user-visible behavior changes.
* Reference relevant audit finding IDs, roadmap milestones, or issues when applicable.

### Validation

* `npm run lint`
* `npm test`
* List any additional build, package, integration, security, or manual validation performed.

### Descriptions

* Do *NOT* reference the relevant audit finding IDs or project milestone when applicable.
* Do *NOT* note any intentionally deferred work discovered during implementation.
* Do *NOT* Clearly distinguish deferred work from incomplete requirements of the current milestone.

PR descriptions should explain **what changed and why** without becoming a detailed chronological account of the implementation process.

The summary should be useful to someone reviewing repository history months or years later.

Example:

### Summary

* Added transactional dependency scan state management.
* Preserved previous successful scan results after cancellation or failure.
* Consolidated first-run and repeat scan behavior.
* Added operation IDs to prevent superseded scans from publishing stale results.
* Added regression coverage for failure, cancellation, retry, and successful rescan behavior.

### Validation

* `npm run lint`
* `npm test`

### Validation Before Commit and PR

Before committing, pushing, or opening a pull request:

* **DO** review `git diff`.
* **DO** review `git status`.
* **DO** verify the current branch and intended remote.
* **DO** run `npm run lint`.
* **DO** run `npm test`.
* **DO** run any additional milestone-specific validation required by the repository, `internal_docs/AGENTS.md`, or the applicable project plan.
* **DO** remove accidental build artifacts, temporary files, generated files, local configuration, or unrelated changes.
* **DO** confirm that the branch contains only changes relevant to the current task.
* **DO** inspect the final commit diff before pushing.

If validation fails:

* investigate failures caused by the current changes;
* fix regressions introduced by the current work;
* clearly distinguish unrelated pre-existing failures;
* do not suppress, skip, or conceal failures merely to produce a green result;
* document any legitimate pre-existing failures in the PR when they remain relevant.

### GitHub and Repository Review

* **DO** use normal terminal-based Git and GitHub tooling, including `git` and `gh`, when appropriate.
* **DO** review relevant existing pull requests, release notes, changelog entries, issues, and recent repository history when they materially affect the task.
* **DO** inspect existing PR discussion or review feedback when working on related changes.
* **DO** check whether another active branch or PR already addresses the same area before creating conflicting work when practical.
* **DO** preserve repository branch-protection, signing, review, and required-check policies.

### Task Interpretation

If asked to **submit**, **save**, **finalize**, **ship**, **complete**, or otherwise finish a development task, interpret that as authorization to:

1. inspect the repository and relevant project instructions;
2. make the required file changes;
3. run required validation;
4. review the resulting diff and repository status;
5. create an appropriately named branch if one has not already been created;
6. stage the intended changes;
7. commit them using the developer's configured Git identity;
8. push the branch to the normal repository remote;
9. open a pull request under the developer's GitHub account;
10. provide a concise, audit-friendly PR description summarizing the changes and validation performed.

Do not automatically merge the pull request.

Do not automatically begin unrelated follow-up work or the next project milestone after opening the pull request unless explicitly requested.

## Protected Files

The following files must NOT be modified unless the task explicitly names them as in-scope. These handle authentication, credential storage, and connection management. Unintended changes to these files can break auth flows or introduce security vulnerabilities.

- `util/cloudsmithAPI.js` — HTTP client, API key handling, redirect validation
- `util/credentialManager.js` — SecretStorage read/write for API keys
- `util/connectionManager.js` — Auth verification and connection state
- `util/ssoAuthManager.js` — SSO and CLI credential import

If you encounter issues in these files while working on an unrelated task, **report the issue but do not modify the file.** Changes to protected files require explicit authorization in the task prompt.

## Repository Structure

```
cloudsmith-vscode-extension/
├── extension.js                         # Entry point, all command registrations
├── package.json                         # Extension manifest (commands, menus, settings, views)
├── models/                              # Tree node classes (TreeItem providers)
│   ├── packageNode.js                   # Individual package display with permissibility icons
│   ├── packageDetailsNode.js            # Leaf nodes for package metadata
│   ├── packageGroupsNode.js             # Package group display
│   ├── repositoryNode.js                # Repository with filter, upstream, entitlement support
│   ├── workspaceNode.js                 # Workspace tree items
│   ├── searchResultNode.js              # Search result items
│   ├── dependencyHealthNode.js          # Dependency health status items
│   ├── promotionStatusNode.js           # Cross-repo promotion status
│   ├── upstreamIndicatorNode.js         # Upstream proxy/cache indicator
│   ├── entitlementNode.js               # Entitlement token display
│   ├── repoMetricsNode.js              # Storage/bandwidth metrics
│   ├── loadMoreNode.js                  # Pagination "load more" item
│   ├── vulnerabilityNode.js             # Individual CVE tree item
│   ├── vulnerabilitySummaryNode.js      # Collapsible vuln summary under packages
│   ├── licenseNode.js                   # License detail tree item
│   └── helpNode.js                      # Help & feedback links
├── views/                               # TreeDataProviders and WebView panels
│   ├── cloudsmithProvider.js            # Main workspace/repo tree provider
│   ├── searchProvider.js                # Package search results provider
│   ├── dependencyHealthProvider.js      # Dependency scanning provider
│   ├── helpProvider.js                  # Help links provider
│   ├── vulnerabilityProvider.js         # CVE detail WebView panel
│   ├── upstreamPreviewProvider.js       # Upstream resolution preview WebView
│   └── promotionProvider.js             # Package promotion logic
├── util/                                # Shared utilities
│   ├── cloudsmithAPI.js                 # HTTP client (v1 + v2 endpoints)
│   ├── connectionManager.js             # Auth verification
│   ├── credentialManager.js             # SecretStorage for API keys
│   ├── ssoAuthManager.js               # SSO + CLI credential import
│   ├── searchQueryBuilder.js            # Cloudsmith query syntax builder (use for ALL query construction)
│   ├── paginatedFetch.js               # Paginated API responses
│   ├── installCommandBuilder.js         # Format-native install commands
│   ├── licenseClassifier.js             # License risk classification
│   ├── manifestParser.js               # Dependency manifest parsing
│   ├── transitiveResolver.js            # CLI-based transitive dep resolution
│   ├── versionResolver.js              # Find safe (non-quarantined) versions
│   ├── remediationHelper.js             # Find safe alternative versions
│   ├── upstreamChecker.js              # Upstream resolution + policy simulation
│   ├── diagnosticsPublisher.js          # Inline editor vulnerability diagnostics
│   ├── recentSearches.js               # Search history persistence
│   ├── recentPackages.js               # Recent package snapshot persistence
│   └── filterState.js                   # Shared repo filter state (module singleton)
├── test/                                # Unit and integration tests
│   ├── extension.test.js
│   ├── searchQueryBuilder.test.js
│   ├── installCommandBuilder.test.js
│   ├── licenseClassifier.test.js
│   ├── manifestParser.test.js
│   ├── recentSearches.test.js
│   ├── versionResolver.test.js
│   └── integration/                     # Live API integration tests
│       ├── setup.js
│       ├── search.test.js
│       ├── vulnerabilities.test.js
│       ├── installCommand.test.js
│       ├── licenseClassifier.test.js
│       └── manifestParser.test.js
└── media/                               # Icons, logos, screenshots
```

## Reference Documents

- All reference documents can be found in the internal_docs folder.
- **ux-copy-guidelines.md** — Authoritative customer-facing copy and product-presentation guidance. Agents and reviewers must read and follow it whenever a task creates or modifies customer-facing UI.
- **ARCHITECTURE.md** — File-by-file breakdown of the original codebase and data flow.
- **API_REFERENCE.md** — Core API endpoints: search, packages, upstreams, search syntax.
- **API_REFERENCE_V2.md** — Vulnerability, license, dependency, and install command endpoints.
- **API_REFERENCE_V3.md** — Policy simulation, decision logs, copy/move/tag, entitlements, quota/metrics.
- **IMPLEMENTATION.md** — Phases 1-4: search, permissibility, upstream awareness, filtering.
- **IMPLEMENTATION_V2.md** — Phases 5-8: vulnerability remediation, dep health, install commands, license.
- **IMPLEMENTATION_V3.md** — Phases 9-13: upstream dry-run, promotion, quarantine trace, entitlements, metrics.
- **IMPLEMENTATION_V4.md** — V4 refinements: code quality fixes, install cmd improvements, vuln filter, upstream inspect, workspace restructure.

## Code Conventions

- CommonJS `require()` / `module.exports` everywhere. No ES modules, no TypeScript.
- All tree nodes follow the pattern: constructor(data, context) → getTreeItem() → getChildren()
- `contextValue` on tree items drives which context menu commands appear (defined in package.json menus).
- `CloudsmithAPI.get()` returns parsed JSON on success or an error message STRING on failure. All callers must check `typeof result === 'string'` before using results.
- `CloudsmithAPI.getV2()` is identical but uses `https://api.cloudsmith.io/v2/` base URL.
- Zero runtime dependencies. Only native `fetch`, VS Code APIs, and Node.js standard library.
- Shared mutable state uses module singletons (e.g., `filterState.js`) not context property injection.
- All user input interpolated into Cloudsmith query syntax must be escaped via `SearchQueryBuilder` (in `util/searchQueryBuilder.js`). Never build query strings with raw string interpolation.
- All API payloads must use the exact casing documented in the API reference (e.g., `"add"` not `"Add"` for tag actions, `"{owner}/{repo}"` format for copy/move destinations).
- API redirect handling uses `redirect: 'manual'` with explicit host and protocol validation before following. Never allow credentials to be sent to untrusted hosts or over plaintext HTTP.
- All new non-test source files must include a copyright header as the first line: `// Copyright 2026 Cloudsmith Ltd. All rights reserved.` — do not add this to test files.

## Code Quality and Cleanup

These rules apply to ALL code changes, not just new features:

- **No partial implementations or stubs.** Every function written must be complete and functional. Do not leave `// TODO` placeholders, empty function bodies, or placeholder return values. If a feature cannot be fully implemented in the current scope, do not create the skeleton — note it in your report instead.
- **No function duplication.** Do not create `foo()`, `foo1()`, `foo2()` or `fooNew()` variants. When adding new behavior, update the existing function. If the signature needs to change, update all call sites in the same change. If a function needs to handle a new case, add the case to the existing function rather than creating a parallel copy.
- **Remove dead code.** If a change makes a function, import, variable, or code path unreachable or unused, delete it in the same change. Do not leave orphaned code for "future use." This includes: unused `require()` imports, functions that are no longer called, variables that are assigned but never read, and `else` branches that can no longer be reached.
- **Clean up adjacent code.** When modifying a function or file, fix any immediately visible issues in the surrounding code: inconsistent naming, redundant checks, copy-paste artifacts, misleading comments, or patterns that contradict the conventions in this document. Do not leave known problems next to new code.
- **One way to do things.** If the codebase has two patterns for the same operation (e.g., two different ways to build a query, two different ways to check API errors), consolidate to one pattern as part of the change. Do not introduce a third pattern.

## Data Flow Rules

When passing data between API responses, node constructors, command handlers, and utility functions:

- **Preserve all fields needed downstream.** If a command handler needs `checksum_sha256`, `cdn_url`, or `filename`, the node constructor must capture those fields from the API response. If data is serialized for persistence (e.g., `recentPackages.js`), include all fields that downstream consumers expect.
- **Property names must match exactly at every handoff.** If a constructor reads `this.slugPerm = data.slug_perm`, the caller must pass `slug_perm`, not `slug_perm_raw` or `identifier`. Trace the full path: API response → node constructor → command handler → utility function.
- **Collection keys must be unique across realistic inputs.** Maps, Sets, or dedup keys must include enough context to prevent collisions. Examples: `${format}:${name}` not just `name` for cross-format lookups; `${workspace}:${name}:${version}:${repository}` not just `${name}:${version}:${repository}` for cross-workspace dedup.
- **State must be scoped and cleared correctly.** If a provider caches state (e.g., `currentRepo` on the search provider), it must be reset when scope changes. A repo-scoped search followed by a workspace-wide search must not retain the prior repo context.

## Pre-Submission Validation

After making changes and before reporting completion, run this checklist:

### 1. Automated Checks
- Run `npm run lint` — must pass with no new errors.
- Run `npm test` — must pass with no regressions.

### 2. Property Name Alignment
For every modified function, constructor, or module boundary, verify that property names the caller sends match exactly what the receiver reads. Trace the full data flow from API response through every intermediate layer to the final consumer.

### 3. Collection Key Uniqueness
For every Map, Set, or dedup key, verify the key is unique across all realistic inputs. If data can come from multiple formats, workspaces, namespaces, or repos, the key must include enough context to prevent collisions.

### 4. Defensive Field Access
When checking boolean fields from API responses, account for `undefined`. Use `field !== false` rather than `field === true` if the field may be absent and the safe default is truthy. Be consistent with how the same field is checked elsewhere in the codebase.

### 5. Protocol and Host Validation
Any code that follows redirects, constructs URLs, or sends credentials must validate both the protocol (`https:`) and the hostname before transmitting sensitive data.

### 6. Graceful Handling of Missing Data
When matching or filtering records, consider what happens when optional fields (version, license, checksum, etc.) are null, undefined, or empty strings. Fall back to a reasonable behavior (name-only match, omit the field, show "Unknown") rather than failing silently or producing incorrect results.

### 7. State Scope Verification
When a provider or utility caches state that is scoped (repo, workspace, format), verify that state is cleared or reset when the scope changes. A repo-scoped operation followed by a workspace-scoped operation must not retain stale scope context.

### 8. End-to-End Data Pipeline
For any feature that reads API data and passes it through multiple layers (API → node → command handler → utility), verify the full pipeline by tracing a concrete example. Confirm that every field needed at the end of the pipeline is captured at each intermediate step, including serialization/deserialization boundaries.

## How to Run Tests

```bash
npm install
npm run lint
npm test

# Integration tests (require live API key)
CLOUDSMITH_TEST_API_KEY=xxx npm test
```

## Known Architectural Quirk

The original codebase had a double-wrapping bug where `getChildren()` in `repositoryNode.js` and `workspaceNode.js` re-wrapped already-constructed node instances. This has been fixed but `packageDetailsNode.js` still handles both single-wrapped `{id, value}` and double-wrapped `{label: {id, value}}` formats defensively.

## Key API Endpoints

- v1: `https://api.cloudsmith.io/v1/` — packages, repos, namespaces, vulnerabilities, entitlements, quota, metrics
- v2: `https://api.cloudsmith.io/v2/` — EPM policies, policy actions, decision logs, policy simulation
