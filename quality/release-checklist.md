# Release qualification checklist

The deterministic/hermetic and authenticated release-qualification lanes are
both required. Passing one never implies that the other ran.

## Candidate and profile identity

- [ ] Branch, candidate SHA/fingerprint, extension version, platform, and
      architecture recorded.
- [ ] Exact source SHA/fingerprint to VSIX path/SHA-256 to installed extension
      ID/version binding recorded by the candidate receipt.
- [ ] Candidate preparation, canonical packaging, black-box UI, mutation, and
      quality-gate entrypoints ran with the exact Node.js runtime declared by
      `.node-version`; a mismatch failed before invalidating prior evidence.
- [ ] Quality-gate and packaging npm children ran under the exact Node.js
      executable with npm from that runtime distribution, matching
      `.npm-version` and the platform-specific `.npm-integrity` fingerprint;
      conflicting PATH, local-bin, or standalone npm entries were rejected.
- [ ] Local qualification uses exactly
      `$HOME/.cloudsmith-vscode-qualification/{user-data,extensions}` and not a
      normal VS Code profile.
- [ ] Local authenticated profile was reused, or the user completed one-time
      authentication outside all agent/UI observation.
- [ ] Expected designated test workspace and repositories recorded without a
      credential value.
- [ ] CI uses an ephemeral creator-owned profile and dedicated non-human,
      least-privileged qualification identity.
- [ ] Cross-step CI cleanup accepted only a `csvq-` profile directly beneath
      the canonical real `RUNNER_TEMP`/platform temporary base, not an arbitrary
      self-fingerprinted parent.
- [ ] The workflow declares `cloudsmith-release-qualification`; required
      reviewers, deployment branches, and other GitHub environment protections
      were confirmed in repository settings rather than inferred from YAML.
- [ ] Exact authenticated candidate preparation/validation ran in a
      credential-free step; only the minimal direct-Node bootstrap/product step
      received the step-scoped Actions secret, with no npm lifecycle boundary.
- [ ] Ephemeral authenticated-CI evidence and persistent local live-candidate
      evidence remain separate; only immutable product/source/VSIX/current-
      VS-Code identity is reconciled across them.

## Security boundary and durable exposure

- [ ] The only automated credential-value transport was the reviewed owner-only
      one-use handoff into the same-ID bootstrap and normal production
      `SecretStorage`; its environment entry and handoff were deleted, mutable
      byte buffers were zeroed, and transient string references were released
      at their defined boundary.
- [ ] Outside that approved transport/storage path, no operator-visible,
      agent-readable, durable, logged, reported, or uploaded surface inspected,
      printed, copied, serialized, replayed, hashed, or exposed a credential or
      SecretStorage/Keychain value.
- [ ] Production extension used its normal authentication and SecretStorage
      path; no production test bypass was added.
- [ ] The local interactive launch preserved the real OS account home identity
      for the OS-backed keyring while user-data, extensions, XDG, and
      application-data remained qualification-owned; no insecure basic
      password-store fallback was enabled.
- [ ] The canonical launcher started the exact app executable as a cold process
      and rejected forwarded reuse of an existing qualification process; the
      explicit CLI credential-import action was not used.
- [ ] The connected state survived the required reload protocol; a
      same-process SecretStorage reread was not treated as persistence proof,
      and a full cold restart restored the connected state.
- [ ] `npm run quality:secrets` passed for Git-visible current content.
- [ ] `npm run quality:secrets:artifacts` passed for generated evidence and
      raw/expanded VSIX contents.
- [ ] `npm run quality:secrets:history` passed or every value-blind location is
      recorded as an explicit open security blocker.
- [ ] PR/issue/review text, Actions logs, and Actions artifacts were scanned
      with authenticated tooling, or each unavailable surface is marked
      `PARTIAL` without a false clean claim.
- [ ] Credential rotation/revocation is separately confirmed before QH-010 or
      an equivalent credential-exposure finding is closed; until confirmation,
      QH-010 remains open without blocking other non-destructive qualification.
- [ ] Test bootstrap is excluded from the VSIX; `SecretStorage` deletion was
      attempted immediately after the product verifier and before exposure
      scans, and handoff/log cleanup was attempted independently on every
      outcome. Profile cleanup was attempted only after owned process-tree exit
      was proven.
- [ ] When owned process-tree exit was unproven, in-run profile cleanup was not
      invoked or recorded as passed, and `authenticated-session.json` retained
      ownership for the workflow's always-run cleanup retry.
- [ ] When `SecretStorage` deletion failed after process-tree exit was proven,
      the profile was removed before long scans and the external scan consumed
      only its one-use metadata proof; failed early removal was retried.
- [ ] Authenticated CI used current VS Code with no development path, observed
      `dl-technology-consulting` through the rendered production workspace
      selection surface, and returned no arbitrary DOM or child-process output.
- [ ] Every owned bootstrap and product process tree was proven exited; the
      Linux/macOS detached process group (or Windows Job Object adapter) failed
      closed on timeout, thrown proof, or incomplete cleanup. No sandbox-
      disabling launch flag was used.
- [ ] The current Git-visible worktree passed a value-blind scan and its
      content-free path/status state was unchanged before any post-auth source
      fingerprint was computed.
- [ ] Authenticated generated evidence, raw/expanded VSIX, and the separate
      private runtime-log directory passed the value-blind scan before cleanup;
      every scanner used private HOME/XDG/application-data/temp roots, and the
      profile itself was checked by metadata only and never read.

## Deterministic and black-box gates

- [ ] `npm run quality:impact -- --base origin/main`
- [ ] `npm run quality:fast`
- [ ] `npm run quality:full`
- [ ] `npm run test:mutation:changed`
- [ ] `npm run test:zero-guard`
- [ ] `npm run package:verify`
- [ ] `npm run test:ui:smoke` executed more than zero tests against its exact
      packaged candidate.
- [ ] The intentionally wrong ExTester selector failed for the expected reason,
      user data was reset, and the restored suite passed.
- [ ] No deterministic gate failure, evidence-binding failure, meaningful
      changed-code survivor, uncovered mutant, timeout, or false-green remains.

## Authenticated authoritative outcomes

- [ ] Fresh schema-v6 attestation binds the exact local candidate receipt,
      stable VSIX bytes, installed identity/version, source, dedicated local
      profile identity, exact findings bytes, independent review, and all
      required evidence.
- [ ] Authenticated CI binds its distinct ephemeral-profile candidate receipt;
      local and CI receipts agree on immutable source, VSIX, extension/install,
      development-path, and current VS Code identity without equating profile
      roots or receipt fingerprints.
- [ ] Final PASS loaded `.quality/secrets/authenticated-ci.json` and validated
      its exact generated-evidence, candidate-VSIX, runtime-log, and profile-
      metadata-only components against the authenticated candidate receipt.
- [ ] Every candidate-observed workflow row, including `PARTIAL` and `BLOCKED`,
      names the exact candidate receipt fingerprint independently of outcome;
      only a genuinely not-executed row uses `candidateProvenance: not-observed`
      with a null receipt.
- [ ] Workflow outcome disposition distinguishes partial evidence,
      defect-blocked, not-authorized, external-precondition, not-executed, and
      authoritative failure without treating them as interchangeable.
- [ ] Every manifest workflow with `liveFixture.required: true` has one nonblank
      `PASS`, `FAIL`, `PARTIAL`, or `BLOCKED` row.
- [ ] Activation/reload and authentication state settle truthfully.
- [ ] Designated repositories publish primary packages before supplementary
      metadata settles, with explicit empty/partial/failed/cancelled terminals.
- [ ] Search first page, Load More, exhaustion, duplicate-only continuation,
      retained actions, and supersession settle within bounds.
- [ ] Every registered resolver family has authoritative deterministic or
      Extension Host evidence for canonical parsing, identity, provenance, and
      bounded terminals; live fixtures are required only for resolver claims
      that materially depend on real registry, package-manager, or Cloudsmith
      protocol semantics.
- [ ] Direct/Flat/Tree, filters, cancellation, rescan, coverage/enrichment, and
      supersession do not publish stale or false-complete state.
- [ ] Dependency, Compliance, Vulnerability, Quarantine, and detail surfaces
      agree on canonical current truth.
- [ ] Show/Copy install guidance agree and target Cloudsmith for every current
      supported format without secrets.
- [ ] Every currently enabled Quarantine/Vulnerability rendered action reaches
      its advertised final outcome; stale panel replacement is safe.
- [ ] Upstream inventory/preview are truthful and supplementary failure does
      not hide primary content.
- [ ] Pull-through is successful only after exact target presence and refreshed
      Dependency Health coverage.
- [ ] Promotion reaches preflight/cancel only; no final mutation occurs without
      separate authorization.
- [ ] Settings and Help render on required VS Code versions.
- [ ] Keyboard, focus, cancel, zoom, labels, and progress teardown checked;
      VoiceOver is `PARTIAL` when reliable speech evidence is unavailable.

## Findings and independent review

- [ ] Pending product set derived from the current ledger, not a historical
      hard-coded list.
- [ ] Finding counts reported separately by primary domain, severity,
      deterministic state, and live state.
- [ ] `releaseBlocking` re-derived from policy and matches every stored record.
- [ ] New live escapes frozen before product edits and assigned stable QH IDs.
- [ ] Every P0/P1/core P2 product fix has root-cause evidence, red-before-green,
      escaped-boundary regression, mutation/false-green proof, and targeted live
      re-verification.
- [ ] Product truth, test effectiveness/mutation, async lifecycle, security,
      and VS Code UI/accessibility reviewers completed independent review.
- [ ] Blocking and in-scope Recommended findings resolved and material changes
      re-reviewed.

## Final gate and verdict

- [ ] Local deterministic/security gates are green, no unresolved code-security
      blocker exists, and the branch diff is reviewed before push.
- [ ] The validated task branch was pushed and a draft PR opened or updated
      without requiring final TEAM-TEST readiness as a push precondition.
- [ ] Branch protection, required-status rules, bypass rules, and repository
      governance were not changed.
- [ ] `npm run quality:release` completed against the final candidate; a history
      or QH-010 blocker is reported as open rather than bypassed.
- [ ] The release-profile run preserved any prior fast/full receipt trees and
      accepted them only when complete, canonical, current-source,
      current-plan, and byte-stable; every unsafe or changed gate-tree entry was
      rejected.
- [ ] Authoritative remote CI completed on the exact pushed SHA, followed by
      only the highest-risk affected live requalification needed for that final
      candidate, before a ready verdict.
- [ ] Fresh schema-v2 `internal_docs/quality/remote-ci.json` binds the draft PR,
      exact task-branch SHA, the authoritative PR workflow run, and every exact
      required job—including core mutation and signed-out packaged UI—with a
      successful terminal conclusion, while its exact
      `remote-ci-api.json` evidence preserves the reviewed bounded GitHub API
      responses; missing, stale, crossed, superseded, cancelled, skipped,
      failed, or incomplete CI blocks readiness.
- [ ] The final targeted live qualification and independent review postdate the
      last authoritative remote-CI completion time.
- [ ] No P0, P1 product, core P2 product, dead enabled action, false
      success/clean/complete, required live failure, deterministic failure,
      evidence-invalidating CI defect, or unresolved security blocker remains.
- [ ] Verdict is exactly `TEAM-TEST READY`, `NOT TEAM-TEST READY`, or
      `TEAM-TEST READY WITH RISKS`.
