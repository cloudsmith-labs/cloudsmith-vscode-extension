// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const vscode = require("vscode");

const TERMINAL_CONTEXTS = Object.freeze({
  empty: "repositoryPackagesEmpty",
  partial: "repositoryPackagesPartial",
  failed: "repositoryPackagesFailed",
  cancelled: "repositoryPackagesCancelled",
});
const TERMINAL_KINDS = new Set(Object.keys(TERMINAL_CONTEXTS));
const TERMINAL_ACTIONS = new Set(["none", "retry", "change-filter"]);

class RepositoryTerminalNode {
  constructor(kind, repositoryNode, options = {}) {
    if (!TERMINAL_KINDS.has(kind)) {
      throw new TypeError("Invalid repository package terminal kind.");
    }
    const scope = options.scope === "filter" ? "filter" : "repository";
    const defaultAction = kind === "empty"
      ? (scope === "filter" ? "change-filter" : "none")
      : "retry";
    const action = TERMINAL_ACTIONS.has(options.action) ? options.action : defaultAction;
    this.repositoryNode = repositoryNode;
    this.terminalOutcome = Object.freeze({
      kind,
      scope,
      authoritative: kind === "empty",
      action,
    });
    this._label = options.label || terminalLabel(kind, scope);
    this._description = options.description || actionDescription(action);
    this._tooltip = options.tooltip || terminalTooltip(kind, scope, action);
    this._icon = options.icon || terminalIcon(kind, scope);
    this._command = options.command || terminalCommand(action, repositoryNode);
  }

  getTreeItem() {
    const contextValue = this.terminalOutcome.kind === "empty"
      && this.terminalOutcome.scope === "filter"
      ? "repositoryPackagesFilteredEmpty"
      : TERMINAL_CONTEXTS[this.terminalOutcome.kind];
    const item = {
      label: this._label,
      description: this._description,
      tooltip: this._tooltip,
      collapsibleState: vscode.TreeItemCollapsibleState.None,
      contextValue,
      iconPath: new vscode.ThemeIcon(this._icon),
    };
    if (this._command) item.command = this._command;
    return item;
  }

  getChildren() {
    return [];
  }
}

function terminalLabel(kind, scope) {
  if (kind === "empty") {
    return scope === "filter" ? "No packages match filter" : "Repository is empty";
  }
  if (kind === "partial") return "Some packages could not be loaded";
  if (kind === "failed") return "Could not load packages";
  return "Package loading canceled";
}

function actionDescription(action) {
  if (action === "retry") return "Retry";
  if (action === "change-filter") return "Change filter";
  return "";
}

function terminalTooltip(kind, scope, action) {
  if (kind === "empty") {
    return scope === "filter"
      ? "Change or clear the filter."
      : "This repository does not contain any packages.";
  }
  if (kind === "partial") {
    return action === "change-filter"
      ? "Loaded packages are shown. Change the filter to narrow the results."
      : "Loaded packages are shown. Retry.";
  }
  if (kind === "failed") return "Could not load packages. Retry.";
  return "Package loading was canceled. Retry.";
}

function terminalIcon(kind, scope) {
  if (kind === "empty") return scope === "filter" ? "filter" : "info";
  if (kind === "cancelled") return "circle-slash";
  return "warning";
}

function terminalCommand(action, repositoryNode) {
  if (action === "retry") {
    return {
      command: "cloudsmith-vsc.refreshView",
      title: "Retry",
    };
  }
  if (action === "change-filter" && repositoryNode) {
    return {
      command: "cloudsmith-vsc.changeFilter",
      title: "Change filter",
      arguments: [repositoryNode],
    };
  }
  return null;
}

function isRepositoryTerminalNode(value) {
  return value instanceof RepositoryTerminalNode;
}

module.exports = {
  RepositoryTerminalNode,
  isRepositoryTerminalNode,
};
