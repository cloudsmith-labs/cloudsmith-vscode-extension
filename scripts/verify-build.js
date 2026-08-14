const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const root = path.resolve(__dirname, "..");
const manifest = require(path.join(root, "package.json"));
const runtimeDirectories = ["commands", "domain", "models", "util", "views"];

function collectJavaScriptFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      return collectJavaScriptFiles(entryPath);
    }
    return entry.isFile() && entry.name.endsWith(".js") ? [entryPath] : [];
  });
}

function assertFile(relativePath, description) {
  const absolutePath = path.resolve(root, relativePath);
  if (!fs.statSync(absolutePath, { throwIfNoEntry: false })?.isFile()) {
    throw new Error(`${description} does not exist: ${relativePath}`);
  }
}

if (!manifest.main && !manifest.browser) {
  throw new Error("package.json must declare a main or browser entry point");
}

const entryPoints = [manifest.main, manifest.browser].filter(Boolean);
for (const entryPoint of entryPoints) {
  assertFile(entryPoint, "Extension runtime entry point");
}

assertFile(manifest.icon, "Extension icon");
for (const container of manifest.contributes?.viewsContainers?.activitybar ?? []) {
  assertFile(container.icon, `Activity bar icon for ${container.id}`);
}

const runtimeFiles = [
  ...entryPoints.map((entryPoint) => path.resolve(root, entryPoint)),
  ...runtimeDirectories.flatMap((directory) =>
    collectJavaScriptFiles(path.join(root, directory)),
  ),
];

for (const runtimeFile of runtimeFiles) {
  const result = spawnSync(process.execPath, ["--check", runtimeFile], {
    encoding: "utf8",
  });
  if (result.status !== 0) {
    process.stderr.write(result.stderr);
    process.exit(result.status ?? 1);
  }
}

console.log(`Validated ${runtimeFiles.length} runtime JavaScript files.`);
