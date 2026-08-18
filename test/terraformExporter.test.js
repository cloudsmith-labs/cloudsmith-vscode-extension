const assert = require("assert");
const { generateTerraformConfig } = require("../util/terraformExporter");

suite("TerraformExporter Test Suite", () => {
  const exportedAt = "2026-03-27T12:00:00.000Z";
  const workspace = "acme";

  test("basic repo export omits default-valued fields", () => {
    const output = generateTerraformConfig({
      repo: {
        name: "Example Repo",
        slug: "example-repo",
        description: "",
        repository_type_str: "Private",
        index_files: true,
        copy_own: true,
        proxy_npmjs: false,
      },
      workspace,
      exportedAt,
    });

    assert.ok(output.includes('# Terraform configuration for repository "Example Repo" in workspace "acme"'));
    assert.ok(output.includes('# Exported at 2026-03-27T12:00:00.000Z'));
    assert.ok(!output.includes("required_providers"));
    assert.ok(!output.includes('provider "cloudsmith"'));
    assert.ok(output.includes('data "cloudsmith_namespace" "this" {'));
    assert.ok(output.includes('slug = "acme"'));
    assert.ok(output.includes('resource "cloudsmith_repository" "example_repo" {'));
    assert.ok(output.includes('namespace = data.cloudsmith_namespace.this.slug_perm'));
    assert.ok(!output.includes('description = ""'));
    assert.ok(!output.includes("index_files"));
    assert.ok(!output.includes("copy_own"));
    assert.ok(!output.includes("proxy_npmjs"));
    assert.ok(!output.includes("cloudsmith_repository_upstream"));
    assert.ok(!output.includes("cloudsmith_repository_retention_rule"));
    assert.ok(!output.includes("# Could not load upstream data. Add upstream resources manually."));
  });

  test("repo export includes non-default permission and access fields", () => {
    const output = generateTerraformConfig({
      repo: {
        name: "Restricted Repo",
        slug: "restricted-repo",
        copy_own: false,
        copy_packages: "Write",
        default_privilege: "Admin",
        replace_packages_by_default: true,
        user_entitlements_enabled: false,
        broadcast_state: "Internal",
      },
      workspace,
      exportedAt,
    });

    assert.match(output, /copy_own\s+= false/);
    assert.match(output, /copy_packages\s+= "Write"/);
    assert.match(output, /default_privilege\s+= "Admin"/);
    assert.match(output, /replace_packages_by_default\s+= true/);
    assert.match(output, /user_entitlements_enabled\s+= false/);
    assert.match(output, /broadcast_state\s+= "Internal"/);
  });

  test("repo export includes upstreams across multiple formats", () => {
    const output = generateTerraformConfig({
      repo: {
        name: "Proxy Repo",
        slug: "proxy-repo",
      },
      workspace,
      upstreams: [
        {
          name: "PyPI",
          format: "python",
          upstream_url: "https://pypi.org/",
        },
        {
          name: "Docker Hub",
          format: "docker",
          upstream_url: "https://index.docker.io/",
          mode: "Cache and Proxy",
        },
      ],
      exportedAt,
    });

    assert.ok(output.includes('resource "cloudsmith_repository_upstream" "proxy_repo_docker_hub" {'));
    assert.ok(output.includes('resource "cloudsmith_repository_upstream" "proxy_repo_pypi" {'));
    assert.ok(output.includes('repository    = cloudsmith_repository.proxy_repo.slug_perm'));
    assert.ok(output.includes('upstream_type = "docker"'));
    assert.ok(output.includes('upstream_type = "python"'));
    assert.ok(output.includes('upstream_url  = "https://index.docker.io"'));
    assert.ok(output.includes('upstream_url  = "https://pypi.org"'));
  });

  test("omits unsafe upstream URLs without exposing secrets or dropping safe siblings", () => {
    const unsafeUrls = [
      "https://user:pass@example.com/private",
      "https://example.com/private?token=query-secret",
      "https://example.com/private#fragment-secret",
      "https://example.com/private?",
      "https://example.com/private#",
      "https://example.com/private\\normalized-secret",
      "https:example.com/missing-authority",
      "https:///example.com/extra-authority-slash",
      "https:////example.com/many-authority-slashes",
      "https://example.com/%2e%2e/dot-secret",
      "file:///tmp/path-secret",
      "not-a-url-secret",
    ];
    const output = generateTerraformConfig({
      repo: { name: "Proxy Repo", slug: "proxy-repo" },
      workspace,
      upstreams: [
        {
          name: "Safe mirror",
          format: "python",
          upstream_url: "https://safe.example:8443/simple/%3Fencoded",
        },
        ...unsafeUrls.map((upstream_url, index) => ({
          name: `Unsafe ${index}`,
          format: "npm",
          upstream_url,
        })),
        { name: "Missing URL", format: "ruby" },
      ],
      exportedAt,
    });

    assert.ok(output.includes('upstream_url  = "https://safe.example:8443/simple/%3Fencoded"'));
    assert.ok(output.includes("13 upstream resources were omitted"));
    assert.ok(!output.includes("Missing URL"));
    for (const secret of [
      "user:pass",
      "private?",
      "fragment-secret",
      "normalized-secret",
      "missing-authority",
      "extra-authority-slash",
      "many-authority-slashes",
      "dot-secret",
      "path-secret",
      "not-a-url-secret",
    ]) {
      assert.ok(!output.includes(secret), secret);
    }
  });

  test("escapes Terraform template introducers in URLs and other string fields", () => {
    const output = generateTerraformConfig({
      repo: {
        name: "Template Repo",
        slug: "template-repo",
        description: 'description %{ if file("/private") }',
      },
      workspace,
      upstreams: [{
        name: "Template mirror",
        format: "python",
        upstream_url: 'https://example.com/${file("/etc/passwd")}',
      }],
      exportedAt,
    });

    assert.ok(output.includes('$${file(\\"/etc/passwd\\")}'));
    assert.ok(output.includes('description %%{ if file(\\"/private\\") }'));
    assert.ok(!output.includes('https://example.com/${file'));
    assert.ok(!output.includes('description %{ if'));
  });

  test("keeps dynamic Terraform header values on one bounded comment line", () => {
    const output = generateTerraformConfig({
      repo: {
        name: 'safe\nresource "evil" "x" {}\u202e',
        slug: "safe-repo",
      },
      workspace: "acme\nmodule evil {}",
      exportedAt: "now\u2028resource evil {}",
    });

    assert.ok(output.includes(
      '# Terraform configuration for repository "safe resource "evil" "x" {}" in workspace "acme module evil {}"'
    ));
    assert.ok(output.includes("# Exported at now resource evil {}"));
    assert.ok(!output.includes('\nresource "evil"'));
    assert.ok(!output.includes("\nmodule evil"));
    const header = output.split("\n").slice(0, 2).join("\n");
    assert.ok(!header.includes("\u202e"));
    assert.ok(!header.includes("\u2028"));
  });

  test("upstream auth exports variable placeholders instead of secrets", () => {
    const output = generateTerraformConfig({
      repo: {
        name: "Auth Repo",
        slug: "auth-repo",
      },
      workspace,
      upstreams: [
        {
          name: "Docker Hub",
          format: "docker",
          upstream_url: "https://index.docker.io/",
          auth_mode: "Username and Password",
          auth_username: "octocat",
          auth_secret: "super-secret-password",
          extra_header_1: "X-Token",
          extra_value_1: "header-secret",
        },
      ],
      exportedAt,
    });

    assert.ok(output.includes("# Auth secret must be provided via variable."));
    assert.match(output, /auth_mode\s+= "Username and Password"/);
    assert.match(output, /auth_username\s+= "octocat"/);
    assert.match(output, /auth_secret\s+= var\.upstream_auth_repo_docker_hub_secret/);
    assert.match(output, /extra_value_1\s+= var\.upstream_auth_repo_docker_hub_extra_value_1/);
    assert.ok(output.includes('variable "upstream_auth_repo_docker_hub_secret" {'));
    assert.ok(output.includes('variable "upstream_auth_repo_docker_hub_extra_value_1" {'));
    assert.ok(!output.includes("super-secret-password"));
    assert.ok(!output.includes("header-secret"));
  });

  test("repo export includes retention rules when configured", () => {
    const output = generateTerraformConfig({
      repo: {
        name: "Retention Repo",
        slug: "retention-repo",
      },
      workspace,
      retention: {
        retention_enabled: true,
        retention_count_limit: 50,
        retention_days_limit: 14,
        retention_size_limit: 200000,
        retention_group_by_name: true,
        retention_group_by_format: false,
        retention_group_by_package_type: true,
      },
      exportedAt,
    });

    assert.ok(output.includes('resource "cloudsmith_repository_retention_rule" "retention_rule" {'));
    assert.ok(output.includes("namespace                       = data.cloudsmith_namespace.this.slug_perm"));
    assert.ok(output.includes("repository                      = cloudsmith_repository.retention_repo.slug_perm"));
    assert.ok(output.includes("retention_enabled               = true"));
    assert.ok(output.includes("retention_count_limit           = 50"));
    assert.ok(output.includes("retention_days_limit            = 14"));
    assert.ok(output.includes("retention_group_by_name         = true"));
    assert.ok(output.includes("retention_group_by_package_type = true"));
  });

  test("should not include upstream section when repository has no upstreams", () => {
    const output = generateTerraformConfig({
      repo: {
        name: "No Upstreams Repo",
        slug: "no-upstreams-repo",
      },
      workspace,
      upstreams: [],
      exportedAt,
    });

    assert.ok(!output.includes("cloudsmith_repository_upstream"));
    assert.ok(!output.includes("# Could not load upstream data. Add upstream resources manually."));
    assert.ok(output.includes('data "cloudsmith_namespace" "this" {'));
    assert.ok(output.includes('resource "cloudsmith_repository" "no_upstreams_repo" {'));
  });

  test("sanitizes HCL identifiers for repositories and upstreams", () => {
    const output = generateTerraformConfig({
      repo: {
        name: "Odd Repo",
        slug: "123.repo-name",
      },
      workspace,
      upstreams: [
        {
          name: "Vendor Registry.io",
          format: "npm",
          upstream_url: "https://registry.example.com/",
        },
      ],
      exportedAt,
    });

    assert.ok(output.includes('resource "cloudsmith_repository" "_123_repo_name" {'));
    assert.ok(output.includes('resource "cloudsmith_repository_upstream" "_123_repo_name_vendor_registry_io" {'));
  });

  test("omits empty and default fields from repo export", () => {
    const output = generateTerraformConfig({
      repo: {
        name: "Minimal Repo",
        slug: "minimal-repo",
        description: "",
        storage_region: "default",
        show_setup_all: true,
        contextual_auth_realm: false,
        broadcast_state: "Off",
      },
      workspace,
      exportedAt,
    });

    assert.ok(!output.includes("storage_region"));
    assert.ok(!output.includes("show_setup_all"));
    assert.ok(!output.includes("contextual_auth_realm"));
    assert.ok(!output.includes("broadcast_state"));
  });

  test("upstream fetch failure fallback adds comment and omits upstream resources", () => {
    const output = generateTerraformConfig({
      repo: {
        name: "Fallback Repo",
        slug: "fallback-repo",
      },
      workspace,
      upstreams: [
        {
          name: "Should Not Render",
          format: "npm",
          upstream_url: "https://registry.npmjs.org/",
        },
      ],
      exportedAt,
      upstreamLoadFailed: true,
    });

    assert.ok(output.includes("# Could not load upstream data. Add upstream resources manually."));
    assert.ok(!output.includes("cloudsmith_repository_upstream"));
  });

  test("partial upstream export keeps verified resources and marks the file incomplete", () => {
    const output = generateTerraformConfig({
      repo: { name: "Partial Repo", slug: "partial-repo" },
      workspace,
      upstreams: [{
        name: "npm",
        format: "npm",
        upstream_url: "https://registry.npmjs.org/",
      }],
      upstreamLoadPartial: true,
      upstreamFailedFormats: ["python"],
      exportedAt,
    });

    assert.match(output, /Upstream data is incomplete for: python/);
    assert.ok(output.includes('resource "cloudsmith_repository_upstream"'));
  });
});
