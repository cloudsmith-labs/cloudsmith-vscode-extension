<img src="media/readme/brand-banner.png" alt="banner" />

# Cloudsmith Visual Studio Code Extension

<img src="media/readme/overview.gif" alt="overview" width="600"/>

<img src="media/readme/brand-card.png" alt="brand-card" />

## Installation

To install the extension, we recommend installing directly from the Visual Studio Code or OpenVSX marketplaces. Open the Extensions view, search for `cloudsmith` to filter results and select the Cloudsmith extension authored by Cloudsmith.

### Connect to Cloudsmith

After installing, to connect to your Cloudsmith instance, you can utilize an API Key, Service Account Token, import from a local Cloudsmith CLI, or Sign in with SSO.

- **API Key** — Enter your API key directly in the extension settings.
- **Service Account Token** — Use a service account token for non-interactive authentication.
- **CLI Credential Import** — Reads API keys from `~/.cloudsmith/config.ini` with cross-platform path detection. Auto-detects CLI credentials on extension activation with a prompt to import.
- **SSO Sign-in (Experimental)** — Browser-based SSO flow gated behind the `experimentalSSOBrowser` setting.
  - SSO terminal flow opens an integrated terminal to run `cloudsmith auth -o {workspace}` for interactive SAML/2FA authentication.


## Features

### Package Explorer

The Cloudsmith extension contributes a dedicated Cloudsmith view to VS Code. The Cloudsmith Explorer lets you browse and manage packages stored within your Cloudsmith assets: **workspaces**, **repositories**, and **packages**.

#### Show Packages or Package Groups

By default the extension returns individual packages. You can display them as [package groups](https://help.cloudsmith.io/docs/package-groups) instead.


#### Package Details

A selection of important fields are available directly under a package. This varies depending on whether you are viewing packages or package groups. This is a subset of the full API response schema for [packages](https://help.cloudsmith.io/reference/packages_list) and [groups](https://help.cloudsmith.io/reference/packages_groups_list). You can inspect a package to obtain the full response.

You can right-click on each detail and copy the value to the clipboard.

##### Package Fields

- Status
- Format
- Name
- Slug
- Slug Perm
- Version
- Description
- License
- Size
- Number of downloads
- Tags
- Uploaded at date/time
- Checksum (SHA256)
- Repository
- Namespace

##### Package Group Fields

- Count of packages in group
- Format
- Name
- Version
- Description
- License
- Size
- Number of downloads
- Tags
- Last pushed date/time
- Namespace



#### Package Context Menus

The right-click menu provides access to the following commands, varying depending on whether you have enabled the package groups setting.

##### Package Commands

- **Inspect package** — View the full raw JSON API response for the package.
- **Copy Install Command** — Copy the installation command for the package to the clipboard.
- **Show Install Command** - Show the installation command for the package. 
- **Show vulnerabilities** - Open a webview showing the vulnerabilities report for a package. 
- **View package in Cloudsmith** - Open the package page in the Cloudsmith web UI for the configured workspace. 
- **Promote Package** - Promote the package between configured repositories. 
- **Show Promotion Status** - Show the current status of the package promotion request. 
- **Find safe version** - Show possible safe versions of the package within Cloudsmith for quick remediation. 

<img src="media/readme/packagegroup_context_menu.jpg" alt="contextMenu" width="400"/>



### Repository Explorer

Browse all repositories within a workspace. Repositories are displayed as children of their parent workspace. Each repository shows its packages (or package groups) as children.

### Workspace Switching

If you have access to multiple workspaces, the explorer lets you switch between them to browse different sets of repositories and packages.

### Search & Filtering

- **Search packages** — Search for packages within a repository using a search query.
- **Filter by format** — Filter packages by their format type.
- Pagination support for large result sets.

### Vulnerability Information

View vulnerability data associated with packages directly in the explorer, including security scan results when available.

### Configuration & Settings

The extension exposes several settings under `cloudsmith-vsc.*`:

| Setting | Description |
|---|---|
| `cloudsmith-vsc.groupByPackageGroups` | Display packages as package groups instead of individual packages. Default: `false`. |
| `cloudsmith-vsc.inspectOutput` | When enabled, inspect output opens in a new text document instead of the Output tab. Default: `false`. |
| `cloudsmith-vsc.showMaxPackages` | Maximum number of packages returned per repository (1–30). Default: `30`. |
| `cloudsmith-vsc.defaultWorkspace` | Cloudsmith workspace slug to load by default. Leave empty to show all accessible workspaces. |
| `cloudsmith-vsc.showPermissibilityIndicators` | Show visual indicators for quarantined packages and policy violations. Default: `true`. |
| `cloudsmith-vsc.showLicenseIndicators` | Show license risk classification on packages. Default: `true`. |
| `cloudsmith-vsc.showDockerDigestCommand` | Show an additional "Pull by digest" option for Docker install commands. Default: `false`. |
| `cloudsmith-vsc.experimentalSSOBrowser` | Enable experimental browser-based SSO authentication. Default: `false`. |
| `cloudsmith-vsc.useLegacyWebApp` | Use the legacy `cloudsmith.io` webapp for platform links. Default: `false`. |
| `cloudsmith-vsc.autoScanOnOpen` | Automatically scan project dependencies against Cloudsmith when a workspace is opened. Default: `false`. |
| `cloudsmith-vsc.dependencyScanWorkspace` | Cloudsmith workspace slug to use for dependency health scanning. |
| `cloudsmith-vsc.dependencyScanRepo` | Cloudsmith repository slug to use for dependency health scanning. |
| `cloudsmith-vsc.resolveTransitiveDependencies` | Resolve transitive (indirect) dependencies using the package manager CLI. Default: `false`. |
| `cloudsmith-vsc.searchPageSize` | Number of results per page when searching packages (10–100). Default: `50`. |
| `cloudsmith-vsc.recentSearches` | Number of recent searches to remember (0–50). Default: `10`. |

### Commands

All commands are available via the Command Palette (`Cmd+Shift+P`):

| Command | Description |
|---|---|
| `Cloudsmith: Set Up Cloudsmith Authentication` | Configure Cloudsmith authentication using an API key, service account token, or imported credentials. |
| `Cloudsmith: Import CLI Credentials` | Import credentials from the Cloudsmith CLI config. |
| `Cloudsmith: Sign in with SSO` | Authenticate using SSO (experimental). |
| `Cloudsmith: Inspect Package` | View the full raw JSON for a package. |
| `Cloudsmith: Open in Cloudsmith` | Open the selected item in the Cloudsmith web UI. |
| `Cloudsmith: Copy to Clipboard` | Copy a package detail value to the clipboard. |
| `Cloudsmith: Refresh Packages` | Refresh the Cloudsmith explorer tree. |
| `Cloudsmith: Search Packages` | Search for packages within a repository. |


## License

Apache 2.0

