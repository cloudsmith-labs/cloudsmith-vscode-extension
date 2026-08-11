const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { ActivationOwner, FORMAT_OPTIONS, runDependencyScan } = require("../extension");
const { SUPPORTED_UPSTREAM_FORMATS } = require("../util/upstreamFormats");

suite("Extension Test Suite", () => {
  test("activation owner reports async cleanup failure without retaining its error", async () => {
    const reports = [];
    const owner = new ActivationOwner(() => reports.push("cleanup failed"));
    owner.add({
      async dispose() {
        throw new Error("secret cleanup infrastructure detail");
      },
    });

    owner.dispose();
    await owner.settle();
    await owner.settle();

    assert.deepStrictEqual(reports, ["cleanup failed"]);
    assert.strictEqual(JSON.stringify(reports).includes("secret cleanup infrastructure detail"), false);
  });

  test("uses the shared upstream format list for format picks", () => {
    assert.strictEqual(FORMAT_OPTIONS, SUPPORTED_UPSTREAM_FORMATS);
    assert.ok(FORMAT_OPTIONS.includes("conan"));
    assert.ok(FORMAT_OPTIONS.includes("terraform"));
    assert.ok(FORMAT_OPTIONS.includes("raw"));
  });

  test("primary dependency scan command establishes scope on first use", async () => {
    const calls = [];
    const provider = {
      hasSuccessfulScan() {
        return false;
      },
      async scan(workspace, repo) {
        calls.push({ workspace, repo });
        return "scanned";
      },
    };

    const result = await runDependencyScan(provider, async () => ({
      scanWorkspace: "workspace-a",
      scanRepo: "repo-a",
    }));

    assert.strictEqual(result, "scanned");
    assert.deepStrictEqual(calls, [{ workspace: "workspace-a", repo: "repo-a" }]);
  });

  test("primary dependency scan command reuses successful scope on repeat use", async () => {
    let initialTargetCalls = 0;
    let rescanCalls = 0;
    const provider = {
      hasSuccessfulScan() {
        return true;
      },
      async rescan() {
        rescanCalls += 1;
        return "rescanned";
      },
    };

    const result = await runDependencyScan(provider, async () => {
      initialTargetCalls += 1;
      return { scanWorkspace: "unused", scanRepo: null };
    });

    assert.strictEqual(result, "rescanned");
    assert.strictEqual(rescanCalls, 1);
    assert.strictEqual(initialTargetCalls, 0);
  });

  test("dependency health title exposes one Scan dependencies action", () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
    const scanCommands = manifest.contributes.commands.filter((entry) => (
      entry.command === "cloudsmith-vsc.scanDependencies"
      || entry.command === "cloudsmith-vsc.scanDependenciesPending"
      || entry.command === "cloudsmith-vsc.scanDependenciesComplete"
    ));
    const titleScanCommands = manifest.contributes.menus["view/title"].filter((entry) => (
      entry.command === "cloudsmith-vsc.scanDependencies"
      || entry.command === "cloudsmith-vsc.scanDependenciesPending"
      || entry.command === "cloudsmith-vsc.scanDependenciesComplete"
    ));

    assert.deepStrictEqual(scanCommands.map((entry) => entry.command), ["cloudsmith-vsc.scanDependencies"]);
    assert.strictEqual(scanCommands[0].title, "Scan dependencies");
    assert.deepStrictEqual(titleScanCommands, [{
      command: "cloudsmith-vsc.scanDependencies",
      group: "navigation@1",
      when: "view == cloudsmithDependencyHealthView && !cloudsmith.depOperationRunning",
    }]);

    const changeScopeEntry = manifest.contributes.menus["view/title"].find(
      (entry) => entry.command === "cloudsmith-vsc.changeDependencyScanScope"
    );
    assert.deepStrictEqual(changeScopeEntry, {
      command: "cloudsmith-vsc.changeDependencyScanScope",
      group: "navigation@1.5",
      when: "view == cloudsmithDependencyHealthView && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning",
    });
  });
});
