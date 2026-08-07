// License classifier - classifies SPDX license identifiers into risk tiers.
// Supports compound SPDX expressions and user-configurable restrictive overrides.

const vscode = require("vscode");

function isExpressionWhitespace(character) {
  return character.trim() === "";
}

function matchesAsciiLetter(value, index, uppercaseLetter, lowercaseLetter) {
  const character = value[index];
  return character === uppercaseLetter || character === lowercaseLetter;
}

function getCompoundOperatorLength(value, index) {
  if (
    matchesAsciiLetter(value, index, "O", "o")
    && matchesAsciiLetter(value, index + 1, "R", "r")
  ) {
    return 2;
  }

  if (
    matchesAsciiLetter(value, index, "A", "a")
    && matchesAsciiLetter(value, index + 1, "N", "n")
    && matchesAsciiLetter(value, index + 2, "D", "d")
  ) {
    return 3;
  }

  return 0;
}

class LicenseClassifier {
  static SPDX_LICENSE_BASE_URL = "https://spdx.org/licenses";

  static RESTRICTIVE = new Set([
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "SSPL-1.0",
    "EUPL-1.1", "EUPL-1.2",
    "OSL-3.0",
    "CPAL-1.0",
    "CC-BY-SA-4.0",
    "Sleepycat",
  ]);

  static CAUTIOUS = new Set([
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "MPL-2.0",
    "EPL-1.0", "EPL-2.0",
    "CDDL-1.0", "CDDL-1.1",
    "CPL-1.0",
    "Artistic-2.0",
    "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0",
  ]);

  static PERMISSIVE = new Set([
    "MIT", "MIT-0",
    "Apache-2.0",
    "BSD-2-Clause", "BSD-3-Clause",
    "ISC",
    "Unlicense",
    "CC0-1.0",
    "0BSD",
    "BSL-1.0",
    "Zlib",
    "PSF-2.0",
    "Python-2.0",
    "CC-BY-4.0",
  ]);

  static TIER_METADATA = {
    restrictive: {
      icon: "error",
      label: "Restrictive",
      description: "\u26D4 Restrictive",
      tooltip: "This license has strong copyleft or viral terms that may require releasing derivative works under the same license. Legal review recommended before use in commercial software.",
      quickPickDescription: "Restrictive",
    },
    cautious: {
      icon: "warning",
      label: "Review required",
      description: "\u26A0 Review required",
      tooltip: "This license has weak copyleft or uncommon terms. Review the specific obligations before use.",
      quickPickDescription: "Review required",
    },
    permissive: {
      icon: "check",
      label: "Permissive",
      description: "\u2713 Permissive",
      tooltip: "This license is generally compatible with commercial use with minimal obligations.",
      quickPickDescription: "Permissive",
    },
    unknown: {
      icon: "question",
      label: "Unknown",
      description: "? Unknown license",
      tooltip: "This license was not recognized. Review the license text manually.",
      quickPickDescription: "Unknown",
    },
  };

  /**
   * Normalize an individual SPDX identifier or override value for comparisons.
   *
   * @param   {string|null|undefined} identifier
   * @returns {string}
   */
  static _normalizeIdentifier(identifier) {
    if (typeof identifier !== "string") {
      return "";
    }
    return identifier.trim();
  }

  /**
   * Normalize a license metadata field. Empty strings become null.
   *
   * @param   {string|null|undefined} value
   * @returns {string|null}
   */
  static _normalizeMetadataField(value) {
    const normalized = LicenseClassifier._normalizeIdentifier(value);
    return normalized || null;
  }

  /**
   * Return the built-in SPDX identifiers recognized by the extension.
   *
   * @returns {Set<string>}
   */
  static _getKnownSpdxIdentifiers() {
    return new Set([
      ...LicenseClassifier.RESTRICTIVE,
      ...LicenseClassifier.CAUTIOUS,
      ...LicenseClassifier.PERMISSIVE,
    ]);
  }

  /**
   * Build a canonical SPDX URL for a license identifier.
   *
   * @param   {string|null|undefined} identifier
   * @returns {string|null}
   */
  static _buildSpdxLicenseUrl(identifier) {
    const normalized = LicenseClassifier._normalizeMetadataField(identifier);
    if (!normalized) {
      return null;
    }
    return `${LicenseClassifier.SPDX_LICENSE_BASE_URL}/${encodeURIComponent(normalized)}.html`;
  }

  /**
   * Split a Cloudsmith license string or SPDX expression into identifiers.
   *
   * @param   {string|null|undefined} license
   * @returns {string[]}
   */
  static _extractIdentifiers(license) {
    const normalized = LicenseClassifier._normalizeIdentifier(license);
    if (!normalized) {
      return [];
    }

    const parts = LicenseClassifier._splitCompoundExpression(normalized);
    const identifiers = [];
    const seen = new Set();

    for (const part of parts) {
      const clean = LicenseClassifier._normalizeIdentifier(part.replace(/[()]/g, ""));
      if (clean && !seen.has(clean)) {
        seen.add(clean);
        identifiers.push(clean);
      }
    }

    return identifiers;
  }

  /**
   * Split AND/OR operators surrounded by whitespace in one pass.
   *
   * @param   {string} expression
   * @returns {string[]}
   */
  static _splitCompoundExpression(expression) {
    const parts = [];
    let partStart = 0;
    let index = 0;

    while (index < expression.length) {
      if (!isExpressionWhitespace(expression[index])) {
        index += 1;
        continue;
      }

      const separatorStart = index;
      while (index < expression.length && isExpressionWhitespace(expression[index])) {
        index += 1;
      }

      const operatorLength = getCompoundOperatorLength(expression, index);
      const afterOperator = index + operatorLength;
      if (
        operatorLength === 0
        || afterOperator >= expression.length
        || !isExpressionWhitespace(expression[afterOperator])
      ) {
        continue;
      }

      parts.push(expression.slice(partStart, separatorStart));
      index = afterOperator;
      while (index < expression.length && isExpressionWhitespace(expression[index])) {
        index += 1;
      }
      partStart = index;
    }

    parts.push(expression.slice(partStart));
    return parts;
  }

  /**
   * Escape a value for use in a Cloudsmith query.
   *
   * @param   {string} value
   * @returns {string}
   */
  static _escapeQueryValue(value) {
    const escaped = value.replace(/(\\|&&|\|\||[+\-!(){}\[\]^"~*?:/|&])/g, (match) => `\\${match}`);
    return /\s/.test(escaped) ? `"${escaped}"` : escaped;
  }

  /**
   * Get the user-configured restrictive license overrides.
   * @returns {Set<string>}
   */
  static _getUserRestrictiveOverrides() {
    const overrides = new Set();
    try {
      const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
      const userList = config.get("restrictiveLicenses");
      if (Array.isArray(userList)) {
        for (const lic of userList) {
          const normalized = LicenseClassifier._normalizeIdentifier(lic);
          if (normalized) {
            overrides.add(normalized);
          }
        }
      }
    } catch (e) {  // eslint-disable-line no-unused-vars
      // vscode not available (e.g., in unit tests without mock)
    }
    return overrides;
  }

  /**
   * Get presentation metadata for a classification tier.
   *
   * @param   {string} tier
   * @returns {{ icon: string, label: string, description: string, tooltip: string, quickPickDescription: string }}
   */
  static getTierMetadata(tier) {
    return LicenseClassifier.TIER_METADATA[tier] || LicenseClassifier.TIER_METADATA.unknown;
  }

  /**
   * Build a Cloudsmith license query from SPDX identifiers.
   *
   * @param   {string[]} identifiers
   * @returns {string}
   */
  static buildQueryFromIdentifiers(identifiers) {
    if (!Array.isArray(identifiers) || identifiers.length === 0) {
      return "";
    }

    const uniqueIdentifiers = [];
    const seen = new Set();
    for (const identifier of identifiers) {
      const normalized = LicenseClassifier._normalizeIdentifier(identifier);
      if (normalized && !seen.has(normalized)) {
        seen.add(normalized);
        uniqueIdentifiers.push(normalized);
      }
    }

    if (uniqueIdentifiers.length === 0) {
      return "";
    }

    const clauses = uniqueIdentifiers.map((identifier) => `license:${LicenseClassifier._escapeQueryValue(identifier)}`);
    if (clauses.length === 1) {
      return clauses[0];
    }
    return `(${clauses.join(" OR ")})`;
  }

  /**
   * Inspect a Cloudsmith license string and return canonical interpretation data.
   *
   * @param   {string|null|undefined} license
   * @returns {{
   *   raw: string|null,
   *   normalized: string,
   *   identifiers: string[],
   *   searchIdentifiers: string[],
   *   searchQuery: string,
   *   baseTier: string,
   *   tier: string,
   *   label: string,
   *   icon: string,
   *   isRestrictive: boolean,
   *   overrideApplied: boolean,
   *   overrideMatches: string[],
   *   metadata: { icon: string, label: string, description: string, tooltip: string, quickPickDescription: string },
   *   displayValue: string|null,
   *   displaySourceField: string|null,
   *   canonicalValue: string|null,
   *   canonicalSourceField: string|null,
   *   spdxLicense: string|null,
   *   licenseValue: string|null,
   *   rawLicense: string|null,
   *   spdxIdentifier: string|null,
   *   licenseUrl: string|null
   * }}
   */
  static _inspectStringLicense(license, details = {}) {
    const raw = typeof license === "string" ? license : null;
    const normalized = LicenseClassifier._normalizeIdentifier(raw);

    if (!normalized) {
      const metadata = LicenseClassifier.getTierMetadata("unknown");
      return {
        raw,
        normalized: "",
        identifiers: [],
        searchIdentifiers: [],
        searchQuery: "",
        baseTier: "unknown",
        tier: "unknown",
        label: details.displayValue || "No license specified",
        icon: metadata.icon,
        isRestrictive: false,
        overrideApplied: false,
        overrideMatches: [],
        metadata,
        displayValue: details.displayValue || null,
        displaySourceField: details.displaySourceField || null,
        canonicalValue: details.canonicalValue || null,
        canonicalSourceField: details.canonicalSourceField || null,
        spdxLicense: details.spdxLicense || null,
        licenseValue: details.licenseValue || null,
        rawLicense: details.rawLicense || null,
        spdxIdentifier: details.spdxIdentifier || null,
        licenseUrl: details.licenseUrl || null,
      };
    }

    const identifiers = LicenseClassifier._extractIdentifiers(raw);
    const searchIdentifiers = identifiers.length > 0 ? identifiers : [normalized];

    let baseTier = "unknown";
    let foundKnown = false;

    for (const identifier of identifiers) {
      if (LicenseClassifier.RESTRICTIVE.has(identifier)) {
        baseTier = "restrictive";
        foundKnown = true;
        break;
      }

      if (LicenseClassifier.CAUTIOUS.has(identifier)) {
        baseTier = "cautious";
        foundKnown = true;
        continue;
      }

      if (LicenseClassifier.PERMISSIVE.has(identifier)) {
        if (!foundKnown) {
          baseTier = "permissive";
        }
        foundKnown = true;
      }
    }

    if (!foundKnown) {
      baseTier = "unknown";
    }

    const userOverrides = LicenseClassifier._getUserRestrictiveOverrides();
    const overrideMatches = searchIdentifiers.filter((identifier) => userOverrides.has(identifier));
    const overrideApplied = overrideMatches.length > 0 && baseTier !== "restrictive";
    const tier = overrideMatches.length > 0 ? "restrictive" : baseTier;
    const metadata = LicenseClassifier.getTierMetadata(tier);

    return {
      raw,
      normalized,
      identifiers,
      searchIdentifiers,
      searchQuery: LicenseClassifier.buildQueryFromIdentifiers(searchIdentifiers),
      baseTier,
      tier,
      label: details.displayValue || raw,
      icon: metadata.icon,
      isRestrictive: tier === "restrictive",
      overrideApplied,
      overrideMatches,
      metadata,
      displayValue: details.displayValue || raw,
      displaySourceField: details.displaySourceField || null,
      canonicalValue: details.canonicalValue || raw,
      canonicalSourceField: details.canonicalSourceField || null,
      spdxLicense: details.spdxLicense || null,
      licenseValue: details.licenseValue || null,
      rawLicense: details.rawLicense || null,
      spdxIdentifier: details.spdxIdentifier || null,
      licenseUrl: details.licenseUrl || null,
    };
  }

  /**
   * Inspect Cloudsmith package license metadata using shared field precedence.
   *
   * Canonical precedence for interpretation/search/URL resolution:
   *   spdx_license -> license -> raw_license
   *
   * Display precedence:
   *   license -> raw_license -> spdx_license
   *
   * @param   {Object} packageLike
   * @returns {Object}
   */
  static _inspectPackageLicense(packageLike) {
    const spdxLicense = LicenseClassifier._normalizeMetadataField(packageLike && (packageLike.spdx_license || packageLike.spdxLicense));
    const licenseValue = LicenseClassifier._normalizeMetadataField(packageLike && packageLike.license);
    const rawLicense = LicenseClassifier._normalizeMetadataField(packageLike && (packageLike.raw_license || packageLike.rawLicense));
    const providedLicenseUrl = LicenseClassifier._normalizeMetadataField(packageLike && (packageLike.license_url || packageLike.licenseUrl));

    const canonicalValue = spdxLicense || licenseValue || rawLicense || null;
    const canonicalSourceField = spdxLicense
      ? "spdx_license"
      : licenseValue
        ? "license"
        : rawLicense
          ? "raw_license"
          : null;

    const displayValue = licenseValue || rawLicense || spdxLicense || null;
    const displaySourceField = licenseValue
      ? "license"
      : rawLicense
        ? "raw_license"
        : spdxLicense
          ? "spdx_license"
          : null;

    const knownSpdxIdentifiers = LicenseClassifier._getKnownSpdxIdentifiers();
    const spdxIdentifier = spdxLicense || (canonicalValue && knownSpdxIdentifiers.has(canonicalValue) ? canonicalValue : null);
    const licenseUrl = providedLicenseUrl || LicenseClassifier._buildSpdxLicenseUrl(spdxIdentifier);

    return LicenseClassifier._inspectStringLicense(canonicalValue, {
      displayValue,
      displaySourceField,
      canonicalValue,
      canonicalSourceField,
      spdxLicense,
      licenseValue,
      rawLicense,
      spdxIdentifier,
      licenseUrl,
    });
  }

  /**
   * Inspect either a plain license string or a Cloudsmith package/license metadata object.
   *
   * @param   {string|Object|null|undefined} license
   * @returns {Object}
   */
  static inspect(license) {
    if (license && typeof license === "object" && !Array.isArray(license)) {
      if (license.metadata && Object.prototype.hasOwnProperty.call(license, "canonicalValue")) {
        return license;
      }
      if (license.licenseInfo && typeof license.licenseInfo === "object") {
        return license.licenseInfo;
      }
      return LicenseClassifier._inspectPackageLicense(license);
    }

    return LicenseClassifier._inspectStringLicense(license, {
      displayValue: typeof license === "string" ? license : null,
      canonicalValue: typeof license === "string" ? license : null,
    });
  }

  /**
   * Return all searchable licenses grouped by their effective tier.
   *
   * @returns {{ restrictive: Array<{ license: string, description: string, overrideApplied: boolean, searchQuery: string }>, cautious: Array<{ license: string, description: string, overrideApplied: boolean, searchQuery: string }>, permissive: Array<{ license: string, description: string, overrideApplied: boolean, searchQuery: string }> }}
   */
  static getSearchableLicensesByTier() {
    const allIdentifiers = new Set([
      ...LicenseClassifier.RESTRICTIVE,
      ...LicenseClassifier.CAUTIOUS,
      ...LicenseClassifier.PERMISSIVE,
      ...LicenseClassifier._getUserRestrictiveOverrides(),
    ]);

    const grouped = {
      restrictive: [],
      cautious: [],
      permissive: [],
    };

    for (const license of Array.from(allIdentifiers).sort((left, right) => left.localeCompare(right))) {
      const inspection = LicenseClassifier.inspect(license);
      if (!grouped[inspection.tier]) {
        continue;
      }

      grouped[inspection.tier].push({
        license,
        description: inspection.overrideApplied
          ? "Restrictive override"
          : inspection.metadata.quickPickDescription,
        overrideApplied: inspection.overrideApplied,
        searchQuery: inspection.searchQuery,
      });
    }

    return grouped;
  }

  /**
   * Return Quick Pick items for the Search by License command.
   *
   * @returns {Array<{ label?: string, description?: string, query?: string, kind?: number }>}
   */
  static getSearchQuickPickItems() {
    const grouped = LicenseClassifier.getSearchableLicensesByTier();
    const quickPickItems = [];
    const tierOrder = ["restrictive", "cautious", "permissive"];

    for (const tier of tierOrder) {
      const licenses = grouped[tier];
      if (!licenses || licenses.length === 0) {
        continue;
      }

      quickPickItems.push({
        label: LicenseClassifier.getTierMetadata(tier).label,
        kind: vscode.QuickPickItemKind.Separator,
      });

      for (const item of licenses) {
        quickPickItems.push({
          label: item.license,
          description: item.description,
          query: item.searchQuery || item.query || LicenseClassifier.buildLicenseQuery(item.license),
        });
      }
    }

    return quickPickItems;
  }

  /**
   * Build a Cloudsmith query for a specific Cloudsmith license string or metadata object.
   *
   * @param   {string|Object|null|undefined} license
   * @returns {string}
   */
  static buildLicenseQuery(license) {
    return LicenseClassifier.inspect(license).searchQuery;
  }

  /**
   * Build a query that matches all licenses treated as restrictive by the extension.
   *
   * @returns {string}
   */
  static buildRestrictiveQuery() {
    const grouped = LicenseClassifier.getSearchableLicensesByTier();
    return LicenseClassifier.buildQueryFromIdentifiers(grouped.restrictive.map((item) => item.license));
  }

  /**
   * Resolve a license URL from Cloudsmith metadata or a canonical SPDX identifier.
   *
   * @param   {string|Object|null|undefined} license
   * @returns {string|null}
   */
  static resolveLicenseUrl(license) {
    return LicenseClassifier.inspect(license).licenseUrl || null;
  }

  /**
   * Determine whether a Cloudsmith license string or metadata object is treated as restrictive.
   *
   * @param   {string|Object|null|undefined} license
   * @returns {boolean}
   */
  static isRestrictive(license) {
    return LicenseClassifier.inspect(license).isRestrictive;
  }

  /**
   * Classify a license identifier or Cloudsmith package metadata into a risk tier.
   *
   * @param   {string|Object|null|undefined} license  SPDX license identifier, expression, or package metadata.
   * @returns {{ tier: string, label: string, icon: string }}
   */
  static classify(license) {
    const inspection = LicenseClassifier.inspect(license);
    return { tier: inspection.tier, label: inspection.label, icon: inspection.icon };
  }
}

module.exports = { LicenseClassifier };
