// Copyright 2026 Cloudsmith Ltd. All rights reserved.

async function runDependencyScan(provider, resolveInitialTarget, isCurrent = () => true) {
  const initialScan = async () => {
    const scanTarget = await resolveInitialTarget();
    if (!scanTarget || !isCurrent()) return null;
    return provider.scan(scanTarget.scanWorkspace, scanTarget.scanRepo);
  };
  if (!isCurrent()) return null;
  return provider.hasSuccessfulScan() ? provider.rescan(initialScan) : initialScan();
}

module.exports = { runDependencyScan };
