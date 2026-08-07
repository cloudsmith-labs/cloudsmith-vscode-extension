// Diagnostics publisher — publishes VS Code diagnostics on manifest files
// so vulnerable/quarantined dependencies show inline squiggly underlines.

const vscode = require("vscode");
const { ManifestParser } = require("./manifestParser");
const { buildRepositoryUrl } = require("./webAppUrls");

class DiagnosticsPublisher {
  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection("cloudsmith");
  }

  /**
   * Publish diagnostics for scanned dependencies on their manifest files.
   *
   * @param {Array<{filePath: string, format: string}>} manifests
   *        Manifest files detected during the scan.
   * @param {Array} dependencies
   *        DependencyHealthNode instances from the scan.
   */
  async publish(manifests, dependencies) {
    this.clear();

    // Group dependencies by their format to match to the right manifest
    const depsByFormat = {};
    for (const dep of dependencies) {
      const format = dep.format;
      if (!depsByFormat[format]) {
        depsByFormat[format] = [];
      }
      depsByFormat[format].push(dep);
    }

    // For each manifest, find problematic deps and create diagnostics
    for (const manifest of manifests) {
      const depsForManifest = depsByFormat[manifest.format] || [];
      const diagnostics = [];

      for (const dep of depsForManifest) {
        // Only publish diagnostics for deps with issues
        if (dep.state === "available" || dep.state === "syncing") {
          continue;
        }

        const location = await ManifestParser.findDependencyLocation(
          manifest.filePath, dep.name, manifest.format
        );
        if (!location) {
          continue;
        }

        const range = new vscode.Range(
          location.line, location.startChar,
          location.line, location.endChar
        );

        const severity = this._getSeverity(dep.state);
        const message = this._getMessage(dep);

        const diagnostic = new vscode.Diagnostic(range, message, severity);
        diagnostic.source = "Cloudsmith";

        // Add related info if there's a fix version available
        if (dep.cloudsmithMatch && dep.cloudsmithMatch.num_vulnerabilities > 0) {
          const repositoryUrl = buildRepositoryUrl(
            dep.cloudsmithMatch.namespace,
            dep.cloudsmithMatch.repository
          );
          const vulnerabilityCode = `${dep.cloudsmithMatch.num_vulnerabilities} vulnerabilities`;
          diagnostic.code = repositoryUrl
            ? {
              value: vulnerabilityCode,
              target: vscode.Uri.parse(repositoryUrl),
            }
            : vulnerabilityCode;
        }

        diagnostics.push(diagnostic);
      }

      if (diagnostics.length > 0) {
        this.collection.set(vscode.Uri.file(manifest.filePath), diagnostics);
      }
    }
  }

  /**
   * Map dependency state to VS Code DiagnosticSeverity.
   */
  _getSeverity(state) {
    switch (state) {
      case "quarantined":
        return vscode.DiagnosticSeverity.Error;
      case "violated":
        return vscode.DiagnosticSeverity.Warning;
      case "not_found":
        return vscode.DiagnosticSeverity.Information;
      default:
        return vscode.DiagnosticSeverity.Information;
    }
  }

  /**
   * Build an actionable diagnostic message for a dependency.
   */
  _getMessage(dep) {
    const version = dep.declaredVersion ? ` ${dep.declaredVersion}` : "";

    switch (dep.state) {
      case "quarantined":
        return `${dep.name}${version} is quarantined in Cloudsmith. Use "Find safe version" to find an alternative.`;
      case "violated":
        return `${dep.name}${version} has policy violations in Cloudsmith.`;
      case "not_found":
        return `${dep.name}${version} was not found in the configured Cloudsmith workspace.`;
      default:
        return `${dep.name}${version} has issues in Cloudsmith.`;
    }
  }

  /** Clear all diagnostics. */
  clear() {
    this.collection.clear();
  }

  /** Dispose the diagnostic collection. */
  dispose() {
    this.collection.dispose();
  }
}

module.exports = { DiagnosticsPublisher };
