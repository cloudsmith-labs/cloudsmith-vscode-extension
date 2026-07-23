## 2.2.0 - April 2026
### Transitive Dependency Visibility

#### Transitive Dependency Resolution
- Dependency Health view now resolves the complete dependency set (direct and transitive) by parsing lockfiles and manifests directly.
- Ecosystems with lockfiles (npm, Yarn, pnpm, Python/Poetry/uv, Rust, Ruby, Go, NuGet, Dart, PHP, Helm, Swift, Hex) resolve the full transitive tree automatically.
- Maven and Gradle resolve direct dependencies from pom.xml and build.gradle. The extension prompts when a tree file is not found.
- Docker and Helm resolve direct dependencies (base images and chart dependencies).
- Summary bar shows total dependency count with direct/transitive breakdown and per-ecosystem composition for multi-ecosystem projects.

#### Vulnerability, License, and Policy Overlays
- Resolved dependencies found in Cloudsmith are checked for known vulnerabilities with severity indicators displayed inline.
- License classification (permissive, weak copyleft, restrictive) and policy compliance status shown for all covered dependencies.
- Summary bar aggregates vulnerability counts by severity, restrictive license count, and policy violation count.

#### Upstream Proxy Gap Analysis
- Dependencies not found in Cloudsmith are checked against configured upstream proxies across all repositories.
- Each uncovered dependency shows whether it's reachable via an existing upstream or requires a new proxy to be configured.

#### Tree Visualization
- New tree view mode displays the full dependency hierarchy with collapsible parent-child relationships.
- Diamond dependencies collapsed on subsequent occurrences to prevent exponential tree growth.
- Filters prune the tree to show only vulnerable, uncovered, or restrictive-license dependency paths.
- Three-way view toggle: direct only, all (flat), or all (tree).

#### Pull Dependencies Through Upstream
- New pull action caches uncovered dependencies through a selected repository's upstream proxy directly from the editor.
- Repository selector shows only repositories with upstream proxies matching the project's dependency formats.
- Right-click any individual uncovered dependency to pull just that package through an upstream.

#### Compliance Report
- New report view opens a dependency health summary in a dedicated editor panel with coverage, vulnerability, license, policy, and upstream gap analysis.

#### UX Improvements
- Toolbar consolidated to five inline actions: scan, pull, view mode cycle, sort and filter, and compliance report.
- Format-specific icons displayed on uncovered dependencies for at-a-glance ecosystem identification.

## 2.1.1 - April 2026
### Fixed
- Fixed erroneous error banner displaying in the Upstream Webview when all upstream data loaded successfully.
- Upstream Resolution Preview no longer throws an error when policy simulation endpoint returns 404

## 2.1.0 - March 2026
### Terraform Export

#### Export Repository as Terraform
- "Export as Terraform" context menu command on repository nodes generates a complete Cloudsmith Terraform provider configuration.
- Exports `cloudsmith_repository` with all base non-default settings
- Exports all configured upstreams as `cloudsmith_repository_upstream` resources with format type, URL, mode, priority, and active state.
- Supports all upstream formats.
- Exports `cloudsmith_repository_retention_rule` when retention is configured.
- Uses Terraform resource references (`data.cloudsmith_namespace`, `cloudsmith_repository.slug_perm`) for portable, import-ready configurations.
- Auth secrets are never exported as plaintext. Upstream credentials use Terraform variable placeholders with `sensitive = true`.
- Generated HCL opens in a new editor tab for review before saving.

#### Upstream Reliability
- Consolidated all upstream data fetching into a single shared helper across inline indicators, WebView, and Terraform export.
- Hardened upstream cache validation: malformed entries are evicted, expired entries force refetch, and cache write failures are non-fatal.
- Inline upstream count now reflects all configured formats, not just formats inferred from loaded packages.

#### License Resolution Reliability
- Fixed an issue causing licenses to not properly display in certain situations

## 2.0.0 - March 2026
### Package Intelligence Platform

This release transforms the extension from a basic package explorer into a full package intelligence platform with security remediation, dependency health scanning, license compliance, upstream inspection, and cross-repository promotion workflows.

#### Package Search
- Full-text package search across workspaces and repositories with Cloudsmith query syntax support.
- Guided multi-step search with filter presets for quarantined packages, policy violations, vulnerability violations, and license violations.
- Recent search history with one-click re-run.
- Per-repository filtering from the main tree view context menu.
- Paginated search results with "Load More" support.
- "Show Vulnerable Packages" context menu command on repository nodes filters to packages with known vulnerabilities using `vulnerabilities:>0` query syntax.
- "Show Vulnerable Packages (All Repos)" command on workspace nodes runs the same filter across the entire workspace.

#### Permissibility Indicators
- Visual status icons on all packages: error icons for quarantined/deny-violated, warning icons for non-deny policy violations, sync icons for packages still processing.
- Quarantine status shown in package descriptions.
- Policy violation details (EPM and legacy classic policies) as expandable child nodes under each package.
- Configurable via `showPermissibilityIndicators` and `showLegacyPolicies` settings.

#### Upstream Awareness
- Upstream proxy/cache indicator shown at the top of repositories with configured upstreams.
- Package origin detection — packages cached from upstreams are tagged with "(via upstream)" in the tree view.
- Origin detail node showing "Direct" or "Upstream: {name}" for each package.
- Lazy-loaded upstream config fetching with 10-minute cache to minimize API calls.
- "View Upstreams" command available from both repository rows and upstream indicator rows, opening a full WebView panel without introducing additional commands.

#### Upstream Inspect WebView
- Dedicated WebView panel showing all configured upstream sources for a repository, grouped by format.
- Each upstream card displays name, active/inactive status, URL, mode, SSL verification, trust level, validation status, distribution, and creation date.
- Upstream Trust Level displayed with contextual callouts explaining security implications: Trusted upstreams bypass dependency confusion protections; Untrusted (recommended) upstreams are blocked from serving packages whose names exist in private repositories or trusted sources.
- Trust level section omitted entirely when not present in the upstream config.
- Fetches all package format endpoints in parallel batches of 5 to respect rate limits, with silent error handling for unsupported formats.
- Stale-request cancellation and requestId guards prevent disposed or outdated panels from rendering results.
- All rendering uses VS Code CSS variables for full dark/light theme compatibility.
- Partial failure warning banner shown when some formats load successfully and others fail, avoiding false empty states.
- Error state rendered instead of empty state when failures make results uncertain.
- Indexing State, Packages Indexed, and Priority fields displayed per upstream where available.

#### Vulnerability Details & Remediation
- Inline vulnerability summary under each package showing CVE count and max severity.
- Expandable vulnerability nodes with CVE ID, severity, CVSS score, and fix version.
- Full vulnerability detail WebView panel with severity badges, CVSS scores, fix availability, and the quarantine reason from Cloudsmith's policy engine.
- Two-step API chain support for fetching scan metadata and detailed CVE results.
- "Find Safe Version" command that searches for clean, non-quarantined versions of a package within the same repo or across the workspace.
- "Open CVE" command to view CVE details on NVD or GitHub Advisories.
- "Copy CVE Report" for pasting vulnerability summaries into issue trackers.
- "Filter Vulnerabilities" command on vulnerability summary nodes with severity multi-select (Critical, High, Medium, Low) and CVSS threshold presets (>= 9.0, >= 7.0, >= 4.0, or custom 0.0–10.0). Active filters shown inline on the summary node label.

#### Dependency Health View
- New sidebar view that reads project manifest files and cross-references declared dependencies against Cloudsmith.
- Supported manifest formats: package.json (npm), requirements.txt (Python), pyproject.toml (Python), pom.xml (Maven), go.mod (Go), Cargo.toml (Rust).
- Dependencies shown with status: available, quarantined, policy violated, not found, or syncing.
- Batch OR queries to minimize API calls (groups of 5 dependencies per request).
- Progressive results — tree updates as each batch completes.
- Optional transitive dependency resolution via package manager CLI (`resolveTransitiveDependencies` setting).
- Auto-scan on workspace open when configured (`autoScanOnOpen` setting).
- Inline editor diagnostics — squiggly underlines on vulnerable dependencies in manifest files.

#### Install Commands
- "Copy Install Command" generates format-native install commands with Cloudsmith registry URLs for 12+ package formats: pip, npm, maven, nuget, docker, helm, cargo, go, ruby, conda, composer, dart, RPM, and raw/generic.
- "Show Install Command" opens multi-line commands (e.g., Maven pom.xml snippets) in a new document for review before copying.
- Docker install commands default to tag-based pulls (`docker pull registry/{name}:{tag}`); digest-based pulls available via the `showDockerDigestCommand` setting when a checksum is present.
- RPM install commands generate both `dnf install` and `yum install` variants.
- Raw/generic install commands generate both `curl` and `wget` variants using the CDN URL or a constructed fallback path.
- Private repository authentication notes included with each command.
- Install commands removed from package detail rows (version, format, etc.) where full package context is unavailable; commands remain available on package and search result rows.
- Integrated into the "Find Safe Version" remediation workflow — selecting a safe version copies the install command directly.

#### License Visibility & Risk Classification
- License risk classification with three tiers: Permissive, Cautious, and Restrictive.
- License node shown under each package with color-coded shield icons.
- Built-in SPDX classification for 40+ common licenses including compound expression support (e.g., "MIT OR GPL-3.0" classified by most restrictive component).
- Configurable restrictive license list via `restrictiveLicenses` setting for enterprise legal policy alignment.
- "Search by License" command for finding all packages with a specific license type.

#### Upstream Proxy Resolution Preview
- "Preview Upstream Resolution" command shows what would happen if a missing package were pulled through an upstream proxy.
- WebView panel displaying local status, active upstreams for the package format, and applicable policy preview.

#### Cross-Repository Promotion
- Configurable promotion pipeline via `promotionPipeline` setting (e.g., dev → staging → production).
- "Show Promotion Status" displays pipeline visualization with per-repo status for a package version.
- "Promote Package" performs one-click copy to the next pipeline stage with automatic tag application.
- Tag templates with `{target}`, `{source}`, and `{date}` placeholders via `promotionTags` setting.

#### Quarantine Policy Trace
- Enhanced vulnerability WebView shows which specific policy quarantined a package and why.
- Policy decision log integration via the Cloudsmith v2 API.
- Displays policy name, matched status, and actions taken.

#### Entitlement Token Visibility
- Optional display of active entitlement tokens under each repository (`showEntitlements` setting).
- Summary node showing active vs. total token count.
- "Copy Entitlement Token" command for quick access to token strings.

#### Workspace Info & Storage
- Workspace-level info node prepended to the repository list showing storage and bandwidth quota usage with color-coded thresholds (warning at 75%, error at 90%).
- Quota display gracefully handles insufficient permissions, showing a lock indicator rather than failing.
- Storage region displayed as a detail node under each repository.
- Workspace-level quota metrics removed from individual repository rows where they were misleading.

#### Default Workspace
- New `defaultWorkspace` setting that skips the workspace tree level for single-workspace users.
- Tree view title dynamically updates to "Repositories" when a default is set.
- "Set Default Workspace" command with QuickPick selection.
- Auto-suggest when connecting to a single-workspace account.
- All workspace-scoped commands (search, guided search, dependency scan) automatically use the default when set.

#### Authentication
- New credential setup QuickPick with four authentication methods: API Key, Service Account API Key, Import from Cloudsmith CLI, and Sign in with SSO.
- CLI credential import reads API keys from `~/.cloudsmith/config.ini` with cross-platform path detection.
- SSO terminal flow opens an integrated terminal to run `cloudsmith auth -o {workspace}` for interactive SAML/2FA authentication.
- Auto-detect CLI credentials on extension activation with prompt to import.
- Experimental browser-based SSO flow (gated behind `experimentalSSOBrowser` setting).

#### Code Quality & Security
- User-Agent header added to all API requests: `Cloudsmith-VSCode/{version} (VS Code {vscodeVersion})`.
- Redirect safety hardening: redirects are validated against `api.cloudsmith.io` before following, preventing API key leakage to untrusted hosts.
- SSO auth manager terminal listener leak fixed; disposable now cleaned up in both callback and timeout paths.
- Cloudsmith query syntax escaping via `SearchQueryBuilder` applied consistently across upstream checker and remediation helper, eliminating raw string interpolation of package names and formats.
- Tag action casing fixed in promotion payloads (`add`/`remove` lowercase to match Cloudsmith API contract).
- Copy/move promotion destination format corrected to `{owner}/{repo}` as required by the API.
- Transitive dependency resolver visited-set key changed to `{name}@{version}` to correctly handle multiple versions of the same package in npm dependency trees.

#### Testing
- Integration test suite running against the live Cloudsmith API.
- Tests for search, vulnerability API chain, install command generation, license classification, and manifest parsing.
- Integration tests automatically skipped when `CLOUDSMITH_TEST_API_KEY` is not set.

## 1.0.1 - 3rd Sept 2025

- Added support for Cursor IDE. Install the extension via the vsix file. 
- Updated Cloudsmith documentation links to the new website. 

## 1.0.0 - July 2025
### Initial release

- Initial release of the Cloudsmith extension. The extension in this release provides a package explorer for your Cloudsmith instance.
- Future releases will continue to build upon this with further capabilities and features. 


