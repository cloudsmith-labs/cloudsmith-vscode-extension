// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  AUTHENTICATED_CANDIDATE_ARTIFACT,
  AUTHENTICATED_CANDIDATE_RECEIPT,
  IMMUTABLE_EXTENSION_ARTIFACT_KEYS,
  IMMUTABLE_CANDIDATE_KEYS,
  LIVE_CANDIDATE_ARTIFACT,
  LIVE_CANDIDATE_RECEIPT,
  candidateBindingFromReceipt,
  profileRootIdentity,
  validateAuthenticatedExecutionReceipt,
  validateCandidateBinding,
  validateEquivalentCandidateProduct,
  validateEquivalentExtensionArtifact,
} = require("../scripts/quality/candidate-binding");
const { fingerprint } = require("../scripts/quality/evidence");
const {
  writeAuthenticatedCandidateProof,
  writeLiveCandidateProof,
} = require("../scripts/quality/prepare-qualification");

const SOURCE = Object.freeze({ sha: "1".repeat(40), fingerprint: "2".repeat(64) });

suite("live qualification candidate binding", () => {
  const roots = [];

  teardown(() => {
    while (roots.length > 0) fs.rmSync(roots.pop(), { recursive: true, force: true });
  });

  test("derives only exact public candidate and profile-root identity metadata", () => {
    const fixture = candidateFixture(roots);
    const binding = candidateBindingFromReceipt(fixture.receipt, {
      root: fixture.root,
      source: SOURCE,
      artifactPath: fixture.artifactPath,
    });

    validateCandidateBinding(binding);
    assert.strictEqual(binding.receiptFingerprint, fixture.receipt.fingerprint);
    assert.strictEqual(binding.installedExtensionId, binding.extensionId);
    assert.strictEqual(binding.installedExtensionVersion, binding.extensionVersion);
    assert.strictEqual(
      binding.profileRootIdentity,
      profileRootIdentity("ci", "/private/ephemeral-profile")
    );
    assert.strictEqual(JSON.stringify(binding).includes("/private/ephemeral-profile"), false);
  });

  test("rejects stale receipt fingerprints, sources, and stable VSIX proof bytes", () => {
    const fixture = candidateFixture(roots);
    assert.throws(
      () => candidateBindingFromReceipt({ ...fixture.receipt, fingerprint: "f".repeat(64) }),
      /fingerprint/u
    );
    assert.throws(
      () => candidateBindingFromReceipt(fixture.receipt, {
        source: { ...SOURCE, fingerprint: "f".repeat(64) },
      }),
      /stale or mismatched/u
    );
    fs.writeFileSync(fixture.artifactPath, "wrong");
    assert.throws(
      () => candidateBindingFromReceipt(fixture.receipt, {
        artifactPath: fixture.artifactPath,
      }),
      /VSIX proof is stale or mismatched/u
    );
  });

  test("rejects a repository VSIX whose out ancestor redirects outside", function () {
    if (process.platform === "win32") this.skip();
    const fixture = candidateFixture(roots);
    const outside = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "candidate-binding-outside-",
    )));
    roots.push(outside);
    const externalArtifact = path.join(
      outside,
      "development",
      "cloudsmith-vsc-2.3.0.vsix",
    );
    fs.mkdirSync(path.dirname(externalArtifact));
    fs.writeFileSync(externalArtifact, fixture.bytes);
    fs.rmSync(path.join(fixture.root, "out"), { recursive: true });
    fs.symlinkSync(outside, path.join(fixture.root, "out"), "dir");

    assert.throws(
      () => candidateBindingFromReceipt(fixture.receipt, {
        root: fixture.root,
        source: SOURCE,
        artifactPath: fixture.receipt.artifact.absoluteVsixPath,
      }),
      /VSIX proof is stale or mismatched/u,
    );
  });

  test("rejects a mismatched proof size before reading or hashing its bytes", () => {
    const fixture = candidateFixture(roots);
    fs.writeFileSync(fixture.artifactPath, Buffer.concat([
      fixture.bytes,
      Buffer.from("extra"),
    ]));
    const originalReadFileSync = fs.readFileSync;
    let proofRead = false;
    fs.readFileSync = (...args) => {
      if (args[0] === fixture.artifactPath) proofRead = true;
      return originalReadFileSync(...args);
    };
    try {
      assert.throws(
        () => candidateBindingFromReceipt(fixture.receipt, {
          artifactPath: fixture.artifactPath,
        }),
        /VSIX proof is stale or mismatched/u,
      );
    } finally {
      fs.readFileSync = originalReadFileSync;
    }
    assert.strictEqual(proofRead, false);
  });

  test("rejects non-canonical or oversized VSIX metadata even with a valid receipt hash", () => {
    const fixture = candidateFixture(roots);
    const base = { ...fixture.receipt };
    delete base.fingerprint;
    for (const artifact of [
      { ...base.artifact, vsixPath: "out/development/other.vsix" },
      { ...base.artifact, archiveBytes: 12 * 1024 * 1024 + 1 },
      { ...base.artifact, entryCount: 1251 },
    ]) {
      const changed = { ...base, artifact };
      assert.throws(
        () => candidateBindingFromReceipt({
          ...changed,
          fingerprint: fingerprint(changed),
        }),
        /VSIX provenance/u,
      );
    }
  });

  test("rejects missing repository, timestamp, and absolute artifact bindings", () => {
    const fixture = candidateFixture(roots);
    const base = { ...fixture.receipt };
    delete base.fingerprint;
    const badRepositoryBase = {
      ...base,
      repository: { ...base.repository, status: "clean" },
    };
    assert.throws(
      () => candidateBindingFromReceipt({
        ...badRepositoryBase,
        fingerprint: fingerprint(badRepositoryBase),
      }),
      /repository state/u,
    );
    const badTimestampBase = { ...base, capturedAt: "2026-08-27T00:00:00Z" };
    assert.throws(
      () => candidateBindingFromReceipt({
        ...badTimestampBase,
        fingerprint: fingerprint(badTimestampBase),
      }),
      /fields are invalid/u,
    );
    const badArtifactBase = {
      ...base,
      artifact: { ...base.artifact, absoluteVsixPath: "/wrong/candidate.vsix" },
    };
    assert.throws(
      () => candidateBindingFromReceipt({
        ...badArtifactBase,
        fingerprint: fingerprint(badArtifactBase),
      }, { root: fixture.root }),
      /absolute path is stale or mismatched/u,
    );
    assert.throws(
      () => candidateBindingFromReceipt(fixture.receipt, {
        repositoryState: {
          ...fixture.receipt.repository,
          branch: "different-branch",
        },
      }),
      /repository state is stale or mismatched/u,
    );
  });

  test("accepts authenticated proof only after the exact successful verifier lifecycle", () => {
    const fixture = candidateFixture(roots);
    const binding = candidateBindingFromReceipt(fixture.receipt, { source: SOURCE });
    const receipt = authenticatedReceipt(binding);

    assert.strictEqual(
      validateAuthenticatedExecutionReceipt(receipt, binding, SOURCE),
      receipt
    );
    const failedBase = { ...receipt, status: "failed", reasonCode: "connected-workspace-mismatch" };
    delete failedBase.fingerprint;
    const failed = { ...failedBase, fingerprint: fingerprint(failedBase) };
    assert.throws(
      () => validateAuthenticatedExecutionReceipt(failed, binding, SOURCE),
      /not passed/u
    );

    const wrongBoundaryBase = {
      ...receipt,
      credentialBoundary: {
        ...receipt.credentialBoundary,
        transport: "untrusted-transport",
      },
    };
    delete wrongBoundaryBase.fingerprint;
    const wrongBoundary = {
      ...wrongBoundaryBase,
      fingerprint: fingerprint(wrongBoundaryBase),
    };
    assert.throws(
      () => validateAuthenticatedExecutionReceipt(wrongBoundary, binding, SOURCE),
      /lifecycle proof/u,
    );
  });

  test("matches immutable product identity without conflating local and CI profiles", () => {
    const fixture = candidateFixture(roots);
    const ciCandidate = candidateBindingFromReceipt(fixture.receipt, { source: SOURCE });
    const homeDirectory = path.join(fixture.root, "qualification-home");
    fs.mkdirSync(homeDirectory);
    const localRoot = path.join(homeDirectory, ".cloudsmith-vscode-qualification");
    const localBase = { ...fixture.receipt };
    delete localBase.fingerprint;
    localBase.profile = {
      mode: "local",
      persistent: true,
      root: localRoot,
      testResourcesDir: localRoot,
      userDataDir: path.join(localRoot, "user-data"),
      extensionsDir: path.join(localRoot, "extensions"),
    };
    const localReceipt = { ...localBase, fingerprint: fingerprint(localBase) };
    const localCandidate = candidateBindingFromReceipt(localReceipt, {
      source: SOURCE,
      homeDirectory,
    });

    assert.strictEqual(validateEquivalentCandidateProduct(localCandidate, ciCandidate), true);
    assert.notStrictEqual(localCandidate.receiptFingerprint, ciCandidate.receiptFingerprint);
    assert.notStrictEqual(localCandidate.profileRootIdentity, ciCandidate.profileRootIdentity);
    assert.throws(
      () => validateEquivalentCandidateProduct(localCandidate, {
        ...ciCandidate,
        vsixSha256: "f".repeat(64),
      }),
      /same immutable product artifact/u,
    );
  });

  test("matches one immutable extension artifact across different VS Code runtimes", () => {
    const fixture = candidateFixture(roots);
    const liveCandidate = candidateBindingFromReceipt(fixture.receipt, { source: SOURCE });
    const signedOutCandidate = {
      ...liveCandidate,
      vscodeVersion: "1.131.0",
    };

    assert.strictEqual(
      validateEquivalentExtensionArtifact(liveCandidate, signedOutCandidate),
      true,
    );
    assert.deepStrictEqual(
      IMMUTABLE_EXTENSION_ARTIFACT_KEYS,
      IMMUTABLE_CANDIDATE_KEYS.filter(key => key !== "vscodeVersion"),
    );
    assert.throws(
      () => validateEquivalentCandidateProduct(liveCandidate, signedOutCandidate),
      /same immutable product artifact/u,
    );
    assert.throws(
      () => validateEquivalentExtensionArtifact(liveCandidate, {
        ...signedOutCandidate,
        vsixSha256: "f".repeat(64),
      }),
      /same immutable extension artifact/u,
    );
  });

  test("requires the producer's canonical local root without constraining CI roots", () => {
    const fixture = candidateFixture(roots);
    const homeDirectory = path.join(fixture.root, "synthetic-home");
    fs.mkdirSync(homeDirectory);
    const canonicalRoot = path.join(homeDirectory, ".cloudsmith-vscode-qualification");
    const localBase = { ...fixture.receipt };
    delete localBase.fingerprint;
    localBase.profile = {
      mode: "local",
      persistent: true,
      root: canonicalRoot,
      testResourcesDir: canonicalRoot,
      userDataDir: path.join(canonicalRoot, "user-data"),
      extensionsDir: path.join(canonicalRoot, "extensions"),
    };
    const localReceipt = { ...localBase, fingerprint: fingerprint(localBase) };

    assert.strictEqual(
      candidateBindingFromReceipt(localReceipt, { source: SOURCE, homeDirectory }).profileMode,
      "local",
    );
    const redirectedRoot = path.join(homeDirectory, "other-qualification-profile");
    const redirectedBase = {
      ...localBase,
      profile: {
        ...localBase.profile,
        root: redirectedRoot,
        testResourcesDir: redirectedRoot,
        userDataDir: path.join(redirectedRoot, "user-data"),
        extensionsDir: path.join(redirectedRoot, "extensions"),
      },
    };
    assert.throws(
      () => candidateBindingFromReceipt({
        ...redirectedBase,
        fingerprint: fingerprint(redirectedBase),
      }, { source: SOURCE, homeDirectory }),
      /local profile root is not canonical/u,
    );
    assert.strictEqual(
      candidateBindingFromReceipt(fixture.receipt, {
        source: SOURCE,
        homeDirectory: path.join(fixture.root, "not-a-home"),
      }).profileMode,
      "ci",
    );
  });

  test("rejects drift in every immutable candidate field", () => {
    const fixture = candidateFixture(roots);
    const candidate = candidateBindingFromReceipt(fixture.receipt, { source: SOURCE });
    const coherentDrifts = [
      {
        fields: ["extensionId", "installedExtensionId"],
        values: {
          extensionId: "Other.cloudsmith-vsc",
          installedExtensionId: "Other.cloudsmith-vsc",
        },
      },
      {
        fields: ["extensionVersion", "installedExtensionVersion"],
        values: {
          extensionVersion: "2.3.1",
          installedExtensionVersion: "2.3.1",
        },
      },
      { fields: ["sourceFingerprint"], values: { sourceFingerprint: "a".repeat(64) } },
      { fields: ["sourceSha"], values: { sourceSha: "b".repeat(40) } },
      { fields: ["vscodeVersion"], values: { vscodeVersion: "1.134.1" } },
      { fields: ["vsixSha256"], values: { vsixSha256: "c".repeat(64) } },
    ];
    const structurallyBoundDrifts = [
      { fields: ["developmentPath"], values: { developmentPath: true } },
    ];
    assert.deepStrictEqual(
      [...new Set([...coherentDrifts, ...structurallyBoundDrifts]
        .flatMap(testCase => testCase.fields))].sort(),
      [...IMMUTABLE_CANDIDATE_KEYS].sort(),
    );
    for (const { fields, values } of coherentDrifts) {
      assert.throws(
        () => validateEquivalentCandidateProduct(candidate, {
          ...candidate,
          ...values,
        }),
        /same immutable product artifact/u,
        `Immutable candidate drift was accepted for ${fields.join(", ")}.`,
      );
    }
    for (const { fields, values } of structurallyBoundDrifts) {
      assert.throws(
        () => validateEquivalentCandidateProduct(candidate, {
          ...candidate,
          ...values,
        }),
        /binding fields are invalid/u,
        `Structurally immutable candidate drift was accepted for ${fields.join(", ")}.`,
      );
    }
  });

  test("writes a dedicated current-lane receipt and immutable-byte-equivalent VSIX proof", () => {
    const fixture = candidateFixture(roots);
    const result = writeLiveCandidateProof(fixture.root, fixture.receipt, fixture.bytes);

    assert.deepStrictEqual(result, {
      artifactPath: LIVE_CANDIDATE_ARTIFACT,
      receiptPath: LIVE_CANDIDATE_RECEIPT,
    });
    assert.deepStrictEqual(
      fs.readFileSync(path.join(fixture.root, LIVE_CANDIDATE_ARTIFACT)),
      fixture.bytes
    );
    assert.strictEqual(
      JSON.parse(fs.readFileSync(path.join(fixture.root, LIVE_CANDIDATE_RECEIPT), "utf8"))
        .fingerprint,
      fixture.receipt.fingerprint
    );
    assert.throws(
      () => writeLiveCandidateProof(fixture.root, fixture.receipt, Buffer.from("wrong")),
      /do not match/u
    );

    assert.deepStrictEqual(
      writeAuthenticatedCandidateProof(fixture.root, fixture.receipt, fixture.bytes),
      {
        artifactPath: AUTHENTICATED_CANDIDATE_ARTIFACT,
        receiptPath: AUTHENTICATED_CANDIDATE_RECEIPT,
      },
    );
    assert.deepStrictEqual(
      fs.readFileSync(path.join(fixture.root, AUTHENTICATED_CANDIDATE_ARTIFACT)),
      fixture.bytes,
    );
  });
});

function candidateFixture(roots) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "candidate-binding-")));
  roots.push(root);
  fs.writeFileSync(path.join(root, "package.json"), `${JSON.stringify({
    publisher: "Cloudsmith",
    name: "cloudsmith-vsc",
    version: "2.3.0",
  })}\n`);
  const bytes = Buffer.from("verified candidate bytes");
  const artifactPath = path.join(root, "candidate.vsix");
  fs.writeFileSync(artifactPath, bytes);
  const repositoryArtifactPath = path.join(
    root,
    "out",
    "development",
    "cloudsmith-vsc-2.3.0.vsix",
  );
  fs.mkdirSync(path.dirname(repositoryArtifactPath), { recursive: true });
  fs.writeFileSync(repositoryArtifactPath, bytes);
  const base = {
    schemaVersion: 2,
    status: "passed",
    capturedAt: "2026-08-27T00:00:00.000Z",
    source: SOURCE,
    repository: {
      branch: "test/candidate-binding",
      dirty: true,
      status: "dirty",
    },
    extension: {
      id: "Cloudsmith.cloudsmith-vsc",
      publisher: "Cloudsmith",
      name: "cloudsmith-vsc",
      version: "2.3.0",
    },
    vscode: { version: "1.134.0", executable: "/bounded/code", cli: "/bounded/cli" },
    profile: {
      mode: "ci",
      persistent: false,
      root: "/private/ephemeral-profile",
      testResourcesDir: "/private/ephemeral-profile",
      userDataDir: "/private/ephemeral-profile/settings",
      extensionsDir: "/private/ephemeral-profile/extensions",
    },
    artifact: {
      vsixPath: "out/development/cloudsmith-vsc-2.3.0.vsix",
      absoluteVsixPath: repositoryArtifactPath,
      sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
      archiveBytes: bytes.length,
      entryCount: 10,
      sourceSha: SOURCE.sha,
      sourceFingerprint: SOURCE.fingerprint,
    },
    installation: { status: "passed", id: "Cloudsmith.cloudsmith-vsc", version: "2.3.0" },
    launch: { status: "not-requested", developmentPath: false },
  };
  return {
    artifactPath,
    bytes,
    receipt: { ...base, fingerprint: fingerprint(base) },
    root,
  };
}

function authenticatedReceipt(candidate) {
  const base = {
    schemaVersion: 2,
    status: "passed",
    reasonCode: null,
    source: SOURCE,
    workspace: {
      expected: "dl-technology-consulting",
      observed: "dl-technology-consulting",
      surface: "production-connected-workspace",
    },
    candidate,
    credentialBoundary: {
      storageKey: "cloudsmith-vsc.authToken",
      transport: "creator-bound-0700-0600-handoff",
      valueRecorded: false,
      digestRecorded: false,
    },
    phases: {
      candidate: "prepared",
      handoff: "consumed-before-store-completion",
      seed: "passed",
      productionWorkspaceCheck: "passed",
      secretStorageCleanup: "passed",
      profileCleanup: "passed",
      outputBoundary: "passed",
    },
  };
  return { ...base, fingerprint: fingerprint(base) };
}
