// Copyright 2026 Cloudsmith Ltd. All rights reserved.

async function runDependencyScan(
  provider,
  resolveInitialTarget,
  isCurrent = () => true,
  resolveInitialProjectFolder = null
) {
  const initialScan = async () => {
    const scanTarget = await resolveInitialTarget();
    if (!scanTarget || !isCurrent()) return null;
    const projectFolder = typeof resolveInitialProjectFolder === "function"
      ? await resolveInitialProjectFolder()
      : null;
    if (!isCurrent() || (typeof resolveInitialProjectFolder === "function" && !projectFolder)) {
      return null;
    }
    return provider.scan(
      scanTarget.scanWorkspace,
      scanTarget.scanRepo,
      projectFolder || undefined
    );
  };
  if (!isCurrent()) return null;
  return provider.hasSuccessfulScan()
    ? provider.rescan(initialScan, isCurrent)
    : initialScan();
}

module.exports = { runDependencyScan };
