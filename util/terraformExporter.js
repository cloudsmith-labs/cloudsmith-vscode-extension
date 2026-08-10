// Copyright 2026 Cloudsmith Ltd.

const { getAllUpstreamData } = require("./upstreamChecker");
const { SUPPORTED_UPSTREAM_FORMATS } = require("./upstreamFormats");
const {
  formatUpstreamText,
  getTerraformUpstreamUrl,
} = require("./upstreamPresentation");

const REPOSITORY_OPTIONAL_FIELDS = [
  { apiField: "repository_type_str", terraformField: "repository_type", defaultValue: "Private" },
  { apiField: "index_files", terraformField: "index_files", defaultValue: true },
  { apiField: "storage_region", terraformField: "storage_region", defaultValue: "default" },
  { apiField: "use_vulnerability_scanning", terraformField: "use_vulnerability_scanning", defaultValue: false },
  { apiField: "copy_own", terraformField: "copy_own", defaultValue: true },
  { apiField: "copy_packages", terraformField: "copy_packages", defaultValue: "Read" },
  { apiField: "default_privilege", terraformField: "default_privilege", defaultValue: "Read" },
  { apiField: "delete_own", terraformField: "delete_own", defaultValue: true },
  { apiField: "delete_packages", terraformField: "delete_packages", defaultValue: "Admin" },
  { apiField: "move_own", terraformField: "move_own", defaultValue: true },
  { apiField: "move_packages", terraformField: "move_packages", defaultValue: "Admin" },
  { apiField: "replace_packages", terraformField: "replace_packages", defaultValue: "Admin" },
  { apiField: "replace_packages_by_default", terraformField: "replace_packages_by_default", defaultValue: false },
  { apiField: "resync_own", terraformField: "resync_own", defaultValue: true },
  { apiField: "resync_packages", terraformField: "resync_packages", defaultValue: "Admin" },
  { apiField: "scan_own", terraformField: "scan_own", defaultValue: true },
  { apiField: "scan_packages", terraformField: "scan_packages", defaultValue: "Admin" },
  { apiField: "view_statistics", terraformField: "view_statistics", defaultValue: "Read" },
  { apiField: "use_entitlements_privilege", terraformField: "use_entitlements_privilege", defaultValue: "Read" },
  { apiField: "user_entitlements_enabled", terraformField: "user_entitlements_enabled", defaultValue: true },
  { apiField: "docker_refresh_tokens_enabled", terraformField: "docker_refresh_tokens_enabled", defaultValue: false },
  { apiField: "proxy_npmjs", terraformField: "proxy_npmjs", defaultValue: false },
  { apiField: "proxy_pypi", terraformField: "proxy_pypi", defaultValue: false },
  { apiField: "raw_package_index_enabled", terraformField: "raw_package_index_enabled", defaultValue: false },
  { apiField: "raw_package_index_signatures_enabled", terraformField: "raw_package_index_signatures_enabled", defaultValue: false },
  { apiField: "strict_npm_validation", terraformField: "strict_npm_validation", defaultValue: false },
  { apiField: "tag_pre_releases_as_latest", terraformField: "tag_pre_releases_as_latest", defaultValue: false },
  { apiField: "use_debian_labels", terraformField: "use_debian_labels", defaultValue: false },
  { apiField: "use_default_cargo_upstream", terraformField: "use_default_cargo_upstream", defaultValue: true },
  { apiField: "use_noarch_packages", terraformField: "use_noarch_packages", defaultValue: false },
  { apiField: "use_source_packages", terraformField: "use_source_packages", defaultValue: false },
  { apiField: "show_setup_all", terraformField: "show_setup_all", defaultValue: true },
  { apiField: "contextual_auth_realm", terraformField: "contextual_auth_realm", defaultValue: false },
  { apiField: "broadcast_state", terraformField: "broadcast_state", defaultValue: "Off" },
];

const RETENTION_FIELDS = [
  "retention_enabled",
  "retention_count_limit",
  "retention_days_limit",
  "retention_size_limit",
  "retention_group_by_name",
  "retention_group_by_format",
  "retention_group_by_package_type",
  "retention_package_query_string",
];

function sanitizeIdentifier(value, options = {}) {
  const { lowercase = true, fallback = "resource" } = options;
  const input = value == null ? "" : String(value);
  const normalized = lowercase ? input.toLowerCase() : input;
  let identifier = normalized
    .replace(/[.\-\s]+/g, "_")
    .replace(/[^a-zA-Z0-9_]/g, "")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "");

  if (!identifier) {
    identifier = fallback;
  }

  if (/^[0-9]/.test(identifier)) {
    identifier = `_${identifier}`;
  }

  return identifier;
}

function escapeHclString(value) {
  const literal = String(value)
    .split("${").join("$${")
    .split("%{").join("%%{");
  return JSON.stringify(literal);
}

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function getStringValue(value) {
  if (value == null) {
    return null;
  }

  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }

  if (isPlainObject(value)) {
    const directKeys = ["slug", "value", "label", "name", "region", "storage_region"];
    for (const key of directKeys) {
      if (value[key] != null) {
        const nestedValue = getStringValue(value[key]);
        if (nestedValue) {
          return nestedValue;
        }
      }
    }
  }

  return null;
}

function getRepoField(repo, fieldName) {
  if (!repo || typeof repo !== "object") {
    return undefined;
  }

  if (Object.prototype.hasOwnProperty.call(repo, fieldName)) {
    return repo[fieldName];
  }

  if (fieldName === "repository_type_str" && Object.prototype.hasOwnProperty.call(repo, "repository_type")) {
    return repo.repository_type;
  }

  return undefined;
}

function valueExists(value) {
  return value !== undefined && value !== null;
}

function hasMeaningfulString(value) {
  return typeof value === "string" ? value.trim().length > 0 : false;
}

function formatValue(value) {
  if (isPlainObject(value) && value.__hclReference) {
    return value.value;
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number") {
    return String(value);
  }
  return escapeHclString(value);
}

function hclReference(value) {
  return { __hclReference: true, value };
}

function formatBlock(header, assignments) {
  const meaningfulAssignments = assignments.filter((assignment) => valueExists(assignment.value));
  const maxFieldLength = meaningfulAssignments.reduce(
    (longest, assignment) => Math.max(longest, assignment.key.length),
    0
  );
  const lines = [header];

  for (const assignment of meaningfulAssignments) {
    lines.push(`  ${assignment.key.padEnd(maxFieldLength)} = ${formatValue(assignment.value)}`);
  }

  lines.push("}");
  return lines.join("\n");
}

function uniqueLabel(baseLabel, usedLabels, suffix) {
  let label = baseLabel;
  if (!usedLabels.has(label)) {
    usedLabels.add(label);
    return label;
  }

  const preferredLabel = sanitizeIdentifier(`${baseLabel}_${suffix}`);
  if (!usedLabels.has(preferredLabel)) {
    usedLabels.add(preferredLabel);
    return preferredLabel;
  }

  let counter = 2;
  while (usedLabels.has(`${preferredLabel}_${counter}`)) {
    counter += 1;
  }

  label = `${preferredLabel}_${counter}`;
  usedLabels.add(label);
  return label;
}

function buildVariableBlock(name, description) {
  return [
    `variable "${name}" {`,
    `  description = ${escapeHclString(description)}`,
    "  type        = string",
    "  sensitive   = true",
    "}",
  ].join("\n");
}

async function fetchRepositoryUpstreams(context, workspace, repoSlug, options = {}) {
  const upstreamData = await getAllUpstreamData(context, workspace, repoSlug, {
    ...options,
    bypassCache: true,
  });
  if (upstreamData === null) {
    return null;
  }

  const upstreams = Array.isArray(upstreamData.upstreams) ? upstreamData.upstreams : [];
  const failedFormats = Array.isArray(upstreamData.failedFormats) ? upstreamData.failedFormats : [];
  const uninspectedFormats = Array.isArray(upstreamData.uninspectedFormats)
    ? upstreamData.uninspectedFormats
    : [];
  const unavailableFormats = [...new Set([...failedFormats, ...uninspectedFormats])];
  const hasUsableUpstreams = upstreams.length > 0;

  if (unavailableFormats.length > 0 && !hasUsableUpstreams) {
    return {
      data: upstreams,
      error: `Could not load upstream data for: ${unavailableFormats.join(", ")}`,
      failedFormats,
      uninspectedFormats,
      complete: false,
      partial: false,
    };
  }

  return {
    data: upstreams,
    error: null,
    active: upstreamData.active,
    total: upstreamData.total,
    failedFormats,
    uninspectedFormats,
    complete: upstreamData.complete === true,
    partial: upstreamData.complete !== true && hasUsableUpstreams,
  };
}

function buildRepositoryBlock(repo, repoResourceLabel) {
  const slug = getStringValue(getRepoField(repo, "slug"));
  const description = getStringValue(getRepoField(repo, "description"));
  const repositoryType = getStringValue(getRepoField(repo, "repository_type_str"));
  const assignments = [
    { key: "name", value: getStringValue(getRepoField(repo, "name")) || slug || "repository" },
    { key: "namespace", value: hclReference("data.cloudsmith_namespace.this.slug_perm") },
    { key: "slug", value: slug || sanitizeIdentifier(getStringValue(getRepoField(repo, "name")) || "repository", { lowercase: true }).replace(/_/g, "-") },
  ];

  if (hasMeaningfulString(description)) {
    assignments.push({ key: "description", value: description });
  }

  if (hasMeaningfulString(repositoryType) && repositoryType !== "Private") {
    assignments.push({ key: "repository_type", value: repositoryType });
  }

  for (const field of REPOSITORY_OPTIONAL_FIELDS) {
    if (field.apiField === "repository_type_str") {
      continue;
    }

    let value = getRepoField(repo, field.apiField);
    if (field.apiField === "storage_region") {
      value = getStringValue(value);
    }

    if (!valueExists(value) || value === field.defaultValue || value === "") {
      continue;
    }

    assignments.push({ key: field.terraformField, value });
  }

  return formatBlock(`resource "cloudsmith_repository" "${repoResourceLabel}" {`, assignments);
}

function buildUpstreamBlocks(upstreams, repoSlug, repoResourceLabel) {
  const repoSlugIdentifier = sanitizeIdentifier(repoSlug, { lowercase: true, fallback: "repository" });
  const usedLabels = new Set();
  const variableBlocks = [];
  const seenVariables = new Set();
  const blocks = [];
  let omittedUnsafeUrlCount = 0;

  for (const upstream of upstreams) {
    const name = getStringValue(upstream && upstream.name);
    const upstreamUrlRaw = getStringValue(upstream && upstream.upstream_url);
    const upstreamType = getStringValue(
      upstream && (upstream._format != null ? upstream._format : upstream.format)
    );

    if (!name || !upstreamType) {
      continue;
    }

    const upstreamUrl = upstreamUrlRaw ? getTerraformUpstreamUrl(upstreamUrlRaw) : null;
    if (!upstreamUrl) {
      omittedUnsafeUrlCount += 1;
      continue;
    }

    const resourceBaseLabel = sanitizeIdentifier(`${repoSlugIdentifier}_${name}`, {
      lowercase: true,
      fallback: `${repoSlugIdentifier}_upstream`,
    });
    const resourceLabel = uniqueLabel(resourceBaseLabel, usedLabels, upstreamType);
    const authMode = getStringValue(upstream.auth_mode);
    const authUsername = getStringValue(upstream.auth_username);
    const comments = [];
    const assignments = [
      { key: "name", value: name },
      { key: "namespace", value: hclReference("data.cloudsmith_namespace.this.slug_perm") },
      { key: "repository", value: hclReference(`cloudsmith_repository.${repoResourceLabel}.slug_perm`) },
      { key: "upstream_type", value: upstreamType },
      { key: "upstream_url", value: upstreamUrl },
    ];

    if (upstream.is_active === false) {
      assignments.push({ key: "is_active", value: false });
    }

    if (hasMeaningfulString(upstream.mode)) {
      assignments.push({ key: "mode", value: upstream.mode });
    }

    if (upstream.verify_ssl === false) {
      assignments.push({ key: "verify_ssl", value: false });
    }

    if (typeof upstream.priority === "number" && upstream.priority !== 0) {
      assignments.push({ key: "priority", value: upstream.priority });
    }

    if (hasMeaningfulString(authMode) && authMode !== "None") {
      assignments.push({ key: "auth_mode", value: authMode });
    }

    if (hasMeaningfulString(authUsername) && authMode && authMode !== "None") {
      assignments.push({ key: "auth_username", value: authUsername });
    }

    if (hasMeaningfulString(authMode) && authMode !== "None" && authMode !== "Certificate and Key") {
      const secretVariable = sanitizeIdentifier(`upstream_${resourceLabel}_secret`, {
        lowercase: true,
        fallback: "upstream_secret",
      });
      comments.push("# Auth secret must be provided via variable.");
      assignments.push({ key: "auth_secret", value: hclReference(`var.${secretVariable}`) });

      if (!seenVariables.has(secretVariable)) {
        variableBlocks.push(buildVariableBlock(secretVariable, `Auth secret for the ${name} upstream.`));
        seenVariables.add(secretVariable);
      }
    }

    if (authMode === "Certificate and Key") {
      comments.push("# Certificate and key material must be added manually.");
    }

    if (hasMeaningfulString(upstream.extra_header_1)) {
      assignments.push({ key: "extra_header_1", value: upstream.extra_header_1 });
    }

    if (hasMeaningfulString(upstream.extra_value_1)) {
      const extraValueVariable = sanitizeIdentifier(`upstream_${resourceLabel}_extra_value_1`, {
        lowercase: true,
        fallback: "upstream_extra_value_1",
      });
      assignments.push({ key: "extra_value_1", value: hclReference(`var.${extraValueVariable}`) });

      if (!seenVariables.has(extraValueVariable)) {
        variableBlocks.push(buildVariableBlock(extraValueVariable, `Extra header value 1 for the ${name} upstream.`));
        seenVariables.add(extraValueVariable);
      }
    }

    if (hasMeaningfulString(upstream.extra_header_2)) {
      assignments.push({ key: "extra_header_2", value: upstream.extra_header_2 });
    }

    if (hasMeaningfulString(upstream.extra_value_2)) {
      const extraValueVariable = sanitizeIdentifier(`upstream_${resourceLabel}_extra_value_2`, {
        lowercase: true,
        fallback: "upstream_extra_value_2",
      });
      assignments.push({ key: "extra_value_2", value: hclReference(`var.${extraValueVariable}`) });

      if (!seenVariables.has(extraValueVariable)) {
        variableBlocks.push(buildVariableBlock(extraValueVariable, `Extra header value 2 for the ${name} upstream.`));
        seenVariables.add(extraValueVariable);
      }
    }

    const blockLines = [];
    if (comments.length > 0) {
      blockLines.push(...comments);
    }
    blockLines.push(formatBlock(`resource "cloudsmith_repository_upstream" "${resourceLabel}" {`, assignments));
    blocks.push(blockLines.join("\n"));
  }

  return { blocks, variableBlocks, omittedUnsafeUrlCount };
}

function buildRetentionBlock(retention, repoResourceLabel) {
  if (!retention || retention.retention_enabled !== true) {
    return null;
  }

  const assignments = [
    { key: "namespace", value: hclReference("data.cloudsmith_namespace.this.slug_perm") },
    { key: "repository", value: hclReference(`cloudsmith_repository.${repoResourceLabel}.slug_perm`) },
  ];

  for (const fieldName of RETENTION_FIELDS) {
    if (!valueExists(retention[fieldName])) {
      continue;
    }

    if (fieldName === "retention_package_query_string" && !hasMeaningfulString(retention[fieldName])) {
      continue;
    }

    assignments.push({ key: fieldName, value: retention[fieldName] });
  }

  return formatBlock('resource "cloudsmith_repository_retention_rule" "retention_rule" {', assignments);
}

function generateTerraformConfig(options) {
  const {
    repo,
    workspace,
    upstreams = [],
    retention = null,
    exportedAt = new Date().toISOString(),
    upstreamLoadFailed = false,
    upstreamLoadPartial = false,
    upstreamFailedFormats = [],
  } = options || {};

  const repoSlug = getStringValue(getRepoField(repo, "slug")) || "repository";
  const repoResourceLabel = sanitizeIdentifier(repoSlug, { lowercase: true, fallback: "repository" });
  const repositoryDisplayName = formatUpstreamText(
    getStringValue(getRepoField(repo, "name")) || repoSlug,
    "repository"
  );
  const workspaceDisplayName = formatUpstreamText(workspace, "workspace");
  const exportedAtDisplay = formatUpstreamText(exportedAt, "unknown time");
  const sections = [
    [
      `# Terraform configuration for repository "${repositoryDisplayName}" in workspace "${workspaceDisplayName}"`,
      `# Exported at ${exportedAtDisplay}`,
    ].join("\n"),
    formatBlock('data "cloudsmith_namespace" "this" {', [
      { key: "slug", value: workspace },
    ]),
    buildRepositoryBlock(repo, repoResourceLabel),
  ];

  if (upstreamLoadFailed) {
    sections.push("# Could not load upstream data. Add upstream resources manually.");
  } else if (Array.isArray(upstreams) && upstreams.length > 0) {
    if (upstreamLoadPartial) {
      const unavailable = Array.isArray(upstreamFailedFormats)
        ? [...new Set(upstreamFailedFormats.filter(value => (
          typeof value === "string" && SUPPORTED_UPSTREAM_FORMATS.includes(value)
        )))]
        : [];
      sections.push(
        `# Upstream data is incomplete${unavailable.length > 0 ? ` for: ${unavailable.join(", ")}` : ""}. Loaded upstream resources are included; additional resources may need to be added manually.`
      );
    }
    const { blocks, variableBlocks, omittedUnsafeUrlCount } = buildUpstreamBlocks(
      upstreams,
      repoSlug,
      repoResourceLabel
    );
    sections.push(...blocks);
    if (omittedUnsafeUrlCount > 0) {
      sections.push(
        `# ${omittedUnsafeUrlCount} upstream resource${omittedUnsafeUrlCount === 1 ? " was" : "s were"} omitted because the configured URL could not be exported safely. Add ${omittedUnsafeUrlCount === 1 ? "it" : "them"} manually.`
      );
    }

    const retentionBlock = buildRetentionBlock(retention, repoResourceLabel);
    if (retentionBlock) {
      sections.push(retentionBlock);
    }

    if (variableBlocks.length > 0) {
      sections.push(...variableBlocks);
    }

    return `${sections.filter(Boolean).join("\n\n")}\n`;
  }

  const retentionBlock = buildRetentionBlock(retention, repoResourceLabel);
  if (retentionBlock) {
    sections.push(retentionBlock);
  }

  return `${sections.filter(Boolean).join("\n\n")}\n`;
}

module.exports = {
  fetchRepositoryUpstreams,
  generateTerraformConfig,
  sanitizeIdentifier,
};
