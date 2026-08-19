// Package details node treeview

const vscode = require('vscode');
const { inheritSelection } = require("../util/selectionProvenance");

/**
 * Unwrap a detail value that may be:
 *   - single-wrapped: { id: "Status", value: "Completed" }
 *   - double-wrapped: { label: { id: "Status", value: "Completed" } }
 *   - raw: a plain string
 * Returns { id, value } in all cases.
 */
function unwrapDetail(detail) {
	if (!detail) {
		return { id: "Detail", value: "Not available" };
	}
	// Double-wrapped: detail.label.id exists
	if (detail.label && detail.label.id !== undefined) {
		return { id: detail.label.id, value: detail.label.value };
	}
	// Single-wrapped: detail.id exists
	if (detail.id !== undefined) {
		return { id: detail.id, value: detail.value };
	}
	// Raw fallback
	return { id: "Detail", value: String(detail) };
}

class PackageDetailsNode {
	constructor(detail, context, owner = null) {
		this.context = context;
		this.label = detail;
		inheritSelection(this, owner);
	}

	getTreeItem() {
		let iconPath = undefined;
		const unwrapped = unwrapDetail(this.label);
		const id = unwrapped.id;
		let value = unwrapped.value;

		if (value === null || value === undefined) {
			value = "Not available";
		}

		if (value instanceof Array) {
			value = String(value);
		}

		// handle icon rendering with ThemeIcon
		const idLower = id.toLowerCase();
		if (idLower === "source" || idLower === "origin") {
			if (String(value).toLowerCase().includes("cached from")) {
				iconPath = new vscode.ThemeIcon('cloud-download');
			} else {
				iconPath = new vscode.ThemeIcon('cloud-upload');
			}
		}
		if (idLower.includes("slug")) {
			iconPath = new vscode.ThemeIcon('info');
		}
		if (idLower.includes("downloads")) {
			iconPath = new vscode.ThemeIcon('cloud-download');
		}
		if (idLower.includes("uploaded") || idLower.includes("last pushed")) {
			iconPath = new vscode.ThemeIcon('cloud-upload');
		}
		if (idLower.includes("size")) {
			iconPath = new vscode.ThemeIcon('file-zip');
		}
		if (idLower.includes("tags") || idLower.includes("count")) {
			iconPath = new vscode.ThemeIcon('tag');
		}
		if (idLower.includes("version")) {
			iconPath = new vscode.ThemeIcon('versions');
		}
		if (idLower.includes("policy")) {
			if (value === "true" || value === true || value === "Yes") {
				iconPath = new vscode.ThemeIcon('shield', new vscode.ThemeColor('errorForeground'));
			} else {
				iconPath = new vscode.ThemeIcon('shield', new vscode.ThemeColor('testing.iconPassed'));
			}
		}
		if (idLower.includes("status")) {
			if (String(value).includes("Quarantined")) {
				iconPath = new vscode.ThemeIcon('error');
			} else {
				iconPath = new vscode.ThemeIcon('check');
			}
		}

		return {
			label: String(id),
			description: String(value),
			tooltip: `${id}: ${String(value)}\nSelect to copy`,
			collapsibleState: vscode.TreeItemCollapsibleState.None,
			contextValue: "packageDetail",
			iconPath: iconPath,
			// Store id and value for the copy command
			command: {
				command: 'cloudsmith-vsc.copySelected',
				title: 'Copy value',
				arguments: [this]
			}
		};
	}

	getChildren() {
		return [];
	}

}

module.exports = PackageDetailsNode;
