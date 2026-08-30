// Help & feedback treeview

const vscode = require('vscode');

class helpNode extends vscode.TreeItem {
    constructor(label, linkId, url, icon) {
        super(label);
        this.tooltip = url;
        this.label = label;
        this.linkId = linkId;
        this.url = url;
        this.icon = icon;
        this.command = {
            command: 'cloudsmith-vscode-extension.cloudsmithDocs',
            title: 'Open Link',
            arguments: [linkId]
        };
    }

    getTreeItem() {
        return {
            label: this.label,
            accessibilityInformation: { label: this.label },
            iconPath: this.icon,
            command: this.command,
            tooltip: this.tooltip,
        };
    }

    getChildren() {
        return [];
    }
}

module.exports = helpNode;
