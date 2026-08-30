// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { runMutation } = require("../scripts/quality/run-mutation");

suite("mutation entrypoint lifecycle", () => {
  test("runtime rejection preserves seeded summary and raw-report evidence", () => {
    const fixtureRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-mutation-runtime-",
    )));
    const summary = path.join(fixtureRoot, ".quality", "mutation", "summary-changed.json");
    const rawReport = path.join(fixtureRoot, ".quality", "mutation", "mutation.json");
    const seeded = new Map([
      [summary, Buffer.from("seeded mutation summary\n")],
      [rawReport, Buffer.from("seeded raw mutation report\n")],
    ]);
    let runtimeValidations = 0;
    try {
      fs.writeFileSync(path.join(fixtureRoot, ".node-version"), "22.23.2\n");
      for (const [target, bytes] of seeded) {
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, bytes);
      }

      assert.throws(
        () => runMutation({
          argumentsList: ["changed"],
          root: fixtureRoot,
          assertCanonicalNodeRuntime(root, version) {
            runtimeValidations += 1;
            assert.strictEqual(root, fixtureRoot);
            assert.strictEqual(version, process.version);
            throw new Error("synthetic canonical runtime rejection");
          },
        }),
        /synthetic canonical runtime rejection/u,
      );

      assert.strictEqual(runtimeValidations, 1);
      for (const [target, bytes] of seeded) {
        assert.deepStrictEqual(fs.readFileSync(target), bytes);
      }
    } finally {
      fs.rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });

  test("baseline preflight rejection preserves seeded summary and raw-report evidence", () => {
    const fixtureRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-mutation-baseline-",
    )));
    const summary = path.join(fixtureRoot, ".quality", "mutation", "summary-changed.json");
    const rawReport = path.join(fixtureRoot, ".quality", "mutation", "mutation.json");
    const baseline = path.join(fixtureRoot, "quality", "mutation-baseline.json");
    const seeded = new Map([
      [summary, Buffer.from("seeded mutation summary\n")],
      [rawReport, Buffer.from("seeded raw mutation report\n")],
    ]);
    try {
      fs.writeFileSync(path.join(fixtureRoot, ".node-version"), `${process.versions.node}\n`);
      fs.mkdirSync(path.dirname(baseline), { recursive: true });
      fs.writeFileSync(baseline, "{}\n");
      for (const [target, bytes] of seeded) {
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, bytes);
      }

      assert.throws(
        () => runMutation({
          argumentsList: ["changed"],
          root: fixtureRoot,
          assertCanonicalNodeRuntime() {},
        }),
        /Mutation evidence requires exact Node/u,
      );

      for (const [target, bytes] of seeded) {
        assert.deepStrictEqual(fs.readFileSync(target), bytes);
      }
    } finally {
      fs.rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });
});
