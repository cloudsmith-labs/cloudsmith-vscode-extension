# Release quality contracts

This directory is the tracked source of truth for release-critical customer
workflows. It distinguishes a trigger, intermediate success, and the
authoritative customer outcome. A trigger or intermediate result never counts
as functional success.

The source files are intentionally small and machine-readable:

- `critical-workflows.json` maps customer journeys to production areas, risk
  classes, required layers, named automated evidence, and live fixtures.
- `action-contracts.json` records producer provenance, consumer acceptance,
  freshness ownership, canonical arguments, and scripted WebView wiring.
- `defect-taxonomy.json` defines severity, lifecycle, evidence, and escape
  analysis vocabulary.
- `finding.schema.json` validates the ignored local finding registry.
- `mutation-baseline.json` records the measured high-risk mutation baseline
  and enforcement policy.
- `release-checklist.md` is the human release-qualification contract.

Generated output belongs in `.quality/` and is ignored. Audit findings and
live evidence belong in `internal_docs/quality/` and are also ignored.

## Everyday flow

```bash
npm run quality:impact -- --base origin/main
npm run quality:fast
# implement and run the commands named by the impact report
npm run quality:full
```

For a release-affecting change:

```bash
npm run quality:release
```

`quality:release` runs deterministic and black-box gates. It does not claim
that authenticated Cloudsmith qualification happened. The separate live
matrix in `release-checklist.md` must be completed with safe designated
fixtures before a release verdict can be issued.

## Contract rules

1. Every user-visible journey has one authoritative outcome.
2. Every release-critical workflow names automated evidence at its escaped or
   highest-risk boundary.
3. Cross-surface actions declare producer provenance and consumer acceptance.
4. Scripted WebViews declare rendered message, parser contract, handler branch,
   and real target.
5. Changed production files must map to at least one workflow.
6. Test counts are diagnostic only; contract/layer evidence determines
   readiness.
7. A bug regression is effective only when reintroducing the old behavior
   makes the new test fail.
8. A test's declared evidence layer must agree with the runner inventory that
   executes it; standalone tests cannot claim Extension Host evidence.
9. Passing test receipts must bind the current source, exact suite, and a
   nonempty structured Mocha record containing no failed or pending tests.
10. A passing changed-mutation receipt hashes the exact summary artifact;
    report generation requires that hash and independently revalidates the
    mutation summary against the tracked baseline.

## Generated evidence

The gate runner and focused tools write deterministic or run-scoped artifacts
under `.quality/`:

```text
.quality/impact.json
.quality/gates/*.json
.quality/mutation/*.json
.quality/ui/**
.quality/report.json
.quality/report.md
```

These files are evidence inputs, not tracked product source.

## Mutation scope

Core mutation covers the small domain capability/projector modules in full.
It also covers bounded line ranges around the release-critical pure logic in
the install renderer, vulnerability presentation projector, and upstream
scheduler, plus the complete external-navigation helper. The ranges are
intentional: they keep the gate focused on deterministic customer-truth logic
whose tests run without VS Code or credentials. A changed source file selects
its owning range, and an incremental Stryker report is filtered back to only
the selected range before scores are evaluated. Missing, zero-mutant,
uncovered, timeout, runtime-error, compile-error, and unclassified-survivor
results fail closed.
