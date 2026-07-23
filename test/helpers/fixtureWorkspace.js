const fs = require("fs");
const os = require("os");
const path = require("path");

async function makeTempWorkspace(prefix = "cloudsmith-lockfile-") {
  return fs.promises.mkdtemp(path.join(os.tmpdir(), prefix));
}

async function copyFixtureDir(fixtureName, targetDir) {
  const sourceDir = path.join(__dirname, "..", "fixtures", fixtureName);
  await copyDirectory(sourceDir, targetDir);
}

async function copyDirectory(sourceDir, targetDir) {
  await fs.promises.mkdir(targetDir, { recursive: true });
  const entries = await fs.promises.readdir(sourceDir, { withFileTypes: true });

  for (const entry of entries) {
    const sourcePath = path.join(sourceDir, entry.name);
    const targetPath = path.join(targetDir, entry.name);

    if (entry.isDirectory()) {
      await copyDirectory(sourcePath, targetPath);
      continue;
    }

    await fs.promises.copyFile(sourcePath, targetPath);
  }
}

async function writeTextFile(targetPath, content) {
  await fs.promises.mkdir(path.dirname(targetPath), { recursive: true });
  await fs.promises.writeFile(targetPath, content, "utf8");
}

async function removeDirectory(targetDir) {
  await fs.promises.rm(targetDir, { recursive: true, force: true });
}

module.exports = {
  copyDirectory,
  copyFixtureDir,
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
};
