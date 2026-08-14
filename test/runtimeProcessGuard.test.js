const assert = require("assert");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const sourceRoots = ["extension.js", "commands", "domain", "models", "views", "util"];
const MAX_SOURCE_FILES = 512;
const MAX_SOURCE_BYTES = 2 * 1024 * 1024;
const MAX_TRAVERSAL_ENTRIES = 1024;
const MAX_TRAVERSAL_DEPTH = 16;
const prohibited = Object.freeze([
  /require\s*\(\s*["'](?:node:)?child_process["']\s*\)/,
  /from\s+["'](?:node:)?child_process["']/,
  /\bchild_?process\s*\./,
  /(?<!\.)\b(?:execFile|execFileSync|execSync|spawn|spawnSync)\s*\(/,
  /\bshell\s*:\s*true\b/,
]);

function sourceFiles() {
  const files = [];
  let visited = 0;
  const visit = (target, depth = 0) => {
    assert.ok(depth <= MAX_TRAVERSAL_DEPTH, "Runtime source traversal exceeds its depth bound");
    visited += 1;
    assert.ok(visited <= MAX_TRAVERSAL_ENTRIES, "Runtime source traversal exceeds its entry bound");
    const stat = fs.lstatSync(target);
    assert.strictEqual(stat.isSymbolicLink(), false, "Runtime source inventory contains a symlink");
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(target).sort()) visit(path.join(target, entry), depth + 1);
      return;
    }
    if (stat.isFile() && target.endsWith(".js")) {
      assert.ok(files.length < MAX_SOURCE_FILES, "Runtime source inventory exceeds its file bound");
      files.push(target);
    }
  };
  for (const sourceRoot of sourceRoots) visit(path.join(root, sourceRoot));
  return files;
}

suite("runtime process execution guard", () => {
  test("runtime sources contain no unowned process execution APIs", () => {
    const files = sourceFiles();
    assert.ok(files.length > 0, "Runtime source inventory is empty");
    const violations = [];
    for (const file of files) {
      const descriptor = fs.openSync(
        file,
        fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
      );
      let source;
      try {
        const stat = fs.fstatSync(descriptor);
        assert.strictEqual(stat.isFile(), true, "Runtime source inventory changed during inspection");
        assert.ok(stat.size <= MAX_SOURCE_BYTES, "Runtime source file exceeds its inspection bound");
        source = fs.readFileSync(descriptor, "utf8");
      } finally {
        fs.closeSync(descriptor);
      }
      for (const pattern of prohibited) {
        if (pattern.test(source)) {
          violations.push(path.relative(root, file));
          break;
        }
      }
    }
    assert.deepStrictEqual(violations, []);
  });
});
