//  This class handles the help & feedback view

const vscode = require('vscode');
const helpNode = require('../models/helpNode');
const path = require('path');
const { HELP_LINKS } = require('../util/helpLinks');

class helpProvider {
    constructor(context) {
        this.context = context;
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    }

    getTreeItem(element) {
        return element.getTreeItem();
    }

    getChildren(element) {
        if (element && typeof element.getChildren === "function") {
            return element.getChildren();
        }

        const cloudsmithLogo = {
            light: path.join(__filename, "..", "..", "media", "workspace_light.svg"),
            dark: path.join(__filename, "..", "..", "media", "workspace_dark.svg")
        };

        return HELP_LINKS.map(link => new helpNode(
            link.label,
            link.url,
            link.icon === 'cloudsmith' ? cloudsmithLogo : new vscode.ThemeIcon(
                link.icon === 'github' ? 'logo-github' : 'link-external'
            )
        ));
    }

    refresh() {
        this._onDidChangeTreeData.fire();
    }
}

module.exports = { helpProvider };

