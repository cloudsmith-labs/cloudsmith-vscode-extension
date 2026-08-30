// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { isPlainObject, uniqueSorted } = require("./common");

const MUTATION_TOOLCHAIN = Object.freeze({
  core: "@stryker-mutator/core",
  engine: "mocha",
  runner: "@stryker-mutator/mocha-runner",
});

function validateMutationToolchain(baseline, manifest, lockfile) {
  const errors = [];
  const tool = baseline?.tool;
  const expectedKeys = [
    "core", "engine", "engineVersion", "nodeVersion", "runner", "runnerVersion", "version",
  ];
  if (!isPlainObject(tool)
    || JSON.stringify(uniqueSorted(Object.keys(tool))) !== JSON.stringify(expectedKeys)
    || tool.core !== MUTATION_TOOLCHAIN.core
    || tool.engine !== MUTATION_TOOLCHAIN.engine
    || tool.runner !== MUTATION_TOOLCHAIN.runner
    || !/^\d+\.\d+\.\d+$/u.test(tool.version || "")
    || !/^\d+\.\d+\.\d+$/u.test(tool.engineVersion || "")
    || !/^\d+\.\d+\.\d+$/u.test(tool.nodeVersion || "")
    || !/^\d+\.\d+\.\d+$/u.test(tool.runnerVersion || "")) {
    return ["Mutation baseline toolchain declaration is invalid."];
  }
  if (!isPlainObject(manifest)) {
    errors.push("Mutation toolchain package manifest is unavailable.");
  }
  if (!isPlainObject(lockfile) || !isPlainObject(lockfile.packages)) {
    errors.push("Mutation toolchain lockfile is unavailable.");
  }
  const requirements = [
    [tool.core, tool.version],
    [tool.engine, tool.engineVersion],
    [tool.runner, tool.runnerVersion],
  ];
  for (const [packageName, version] of requirements) {
    if (manifest?.devDependencies?.[packageName] !== version) {
      errors.push(`Mutation baseline ${packageName} version must match package.json exactly.`);
    }
    if (lockfile?.packages?.[""]?.devDependencies?.[packageName] !== version
      || lockfile?.packages?.[`node_modules/${packageName}`]?.version !== version) {
      errors.push(`Mutation baseline ${packageName} version must match package-lock.json exactly.`);
    }
  }
  return uniqueSorted(errors);
}

module.exports = {
  MUTATION_TOOLCHAIN,
  validateMutationToolchain,
};
