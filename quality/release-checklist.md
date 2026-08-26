# Release qualification checklist

The deterministic release gate and authenticated live qualification are both
required. Passing the first does not imply the second happened.

## Candidate identity

- [ ] Baseline and candidate SHA recorded.
- [ ] Extension, VS Code, Electron, Node, OS, and architecture recorded.
- [ ] Workspace, repositories, project fixtures, and credential kind recorded
      without reading or recording a secret.

## Deterministic gates

- [ ] `npm run quality:impact -- --base origin/main`
- [ ] `npm run quality:full`
- [ ] `npm run test:mutation:changed`
- [ ] `npm run test:ui:smoke`
- [ ] `npm run test:zero-guard`
- [ ] `npm run package:verify`
- [ ] No open deterministic gate failure or meaningful mutation survivor in
      changed high-risk code.

## Live authoritative outcomes

- [ ] Activation and three reloads settle truthfully.
- [ ] Authentication state and supported credential modes remain truthful.
- [ ] Both designated repositories publish packages/groups or an explicit
      empty, partial, failed/retry, or cancelled package terminal.
- [ ] Search first page, Load More, exhaustion, duplicate-only continuation,
      and supersession settle within bounds.
- [ ] Every registered resolver family reaches a terminal scan and preserves
      format-native qualifiers.
- [ ] Direct, Flat, Tree, filters, cancellation, rescan, and supersession do
      not publish stale or false-complete state.
- [ ] Dependency, Compliance, Vulnerability, and Quarantine surfaces agree.
- [ ] Every enabled Quarantine and Vulnerability WebView action reaches its
      advertised final outcome.
- [ ] Find safe version fails closed on repository scope and proves a positive
      in-scope candidate when a fixture exists.
- [ ] Show and Copy install guidance agree and target Cloudsmith for every
      supported format without secrets.
- [ ] Upstream inventory and preview are truthful; optional metadata failure
      does not hide primary package content.
- [ ] Pull-through success is counted only after exact presence and refreshed
      Dependency Health coverage.
- [ ] Promotion reaches preflight and stops before mutation unless a disposable
      fixture is explicitly authorized.
- [ ] Settings, Help, documentation navigation, keyboard operation, zoom,
      focus, cancellation, and progress teardown are checked.
- [ ] Visible enabled actions were enumerated and none silently no-op.

## Findings and review

- [ ] First-pass findings were frozen before product fixes.
- [ ] Every P0/P1/core P2 has escape analysis, red-before-green regression,
      false-green or mutation proof, live verification, and fixed SHA.
- [ ] Independent quality, Extension Host, provenance, async, identity,
      security, UX/accessibility, and mutation reviewers completed review.
- [ ] Blocking and in-scope Recommended review findings are resolved and
      material corrections were re-reviewed.
- [ ] Final full qualification was rerun from activation, not only failed rows.

## Verdict

- [ ] No P0, P1, unresolved core P2, dead enabled action, false success/clean/
      complete behavior, deterministic gate failure, or required evidence gap.
- [ ] Verdict is exactly `TEAM-TEST READY`, `NOT TEAM-TEST READY`, or
      `TEAM-TEST READY WITH KNOWN NON-BLOCKING RISKS`.
