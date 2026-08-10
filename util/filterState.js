// Shared filter state — module singleton, survives tree refreshes.
// Key: "workspace/repo", Value: { query, label } object.
// CommonJS module caching guarantees the same Map instance everywhere.

const activeFilters = new Map();

function clear() {
  activeFilters.clear();
}

module.exports = { activeFilters, clear };
