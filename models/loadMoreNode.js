// Load More node for paginated search results.

const vscode = require("vscode");

class LoadMoreNode {
    constructor(currentPage, totalPages, totalCount, loadedCount = null) {
        this.currentPage = currentPage;
        this.totalPages = totalPages;
        this.totalCount = totalCount;
        this.loadedCount = loadedCount;
    }

    getTreeItem() {
        const progress = Number.isSafeInteger(this.totalCount) && this.totalCount >= 0
            ? `page ${this.currentPage} of ${this.totalPages}, ${this.totalCount} total`
            : `${Number.isSafeInteger(this.loadedCount) ? this.loadedCount : 0} loaded; page ${this.currentPage} of ${this.totalPages}`;
        return {
            label: `Load more results (${progress})`,
            tooltip: "Load the next page of search results.",
            collapsibleState: vscode.TreeItemCollapsibleState.None,
            contextValue: "loadMore",
            iconPath: new vscode.ThemeIcon('ellipsis'),
            command: {
                command: 'cloudsmith-vsc.searchNextPage',
                title: 'Load more results',
            },
        };
    }

    getChildren() {
        return [];
    }
}

module.exports = LoadMoreNode;
