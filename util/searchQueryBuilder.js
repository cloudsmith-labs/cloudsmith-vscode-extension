// Builds query strings for the Cloudsmith packages API.
// Handles escaping, boolean operators, and field-specific syntax.

class SearchQueryBuilder {
    constructor() {
        this.terms = [];
    }

    /**
     * Escape a value for use in a Cloudsmith query.
     */
    _escapeValue(value) {
        if (typeof value !== 'string') {
            value = String(value);
        }

        const escaped = value.replace(/(\\|&&|\|\||[!(){}\[\]^"~*?:|&])/g, (match) => `\\${match}`);
        return /\s/.test(escaped) ? `"${escaped}"` : escaped;
    }

    /** Add a name search term. */
    name(value) {
        this.terms.push(`name:${this._escapeValue(value)}`);
        return this;
    }

    /** Add a format filter. */
    format(value) {
        this.terms.push(`format:${this._escapeValue(value)}`);
        return this;
    }

    /** Add a status filter. */
    status(value) {
        this.terms.push(`status:${this._escapeValue(value)}`);
        return this;
    }

    /** Add a version filter. */
    version(value) {
        this.terms.push(`version:${this._escapeValue(value)}`);
        return this;
    }

    /** Add a tag filter. */
    tag(value) {
        this.terms.push(`tag:${this._escapeValue(value)}`);
        return this;
    }

    /**
     * Add a raw query term (pass-through for advanced users).
     * @warning Raw input is not escaped; only use trusted, advanced query fragments here.
     */
    raw(queryString) {
        if (queryString) {
            this.terms.push(queryString);
        }
        return this;
    }

    /** Build the final query string. */
    build() {
        return this.terms.join(' AND ');
    }

    /** Reset the builder for reuse. */
    reset() {
        this.terms = [];
        return this;
    }

    /**
     * Static helper: build a permissibility query for a package name.
     * Returns packages that are not quarantined and have no deny policy violations.
     */
    static permissible(name) {
        const builder = new SearchQueryBuilder();
        return `name:${builder._escapeValue(name)} AND NOT status:quarantined AND deny_policy_violated:false`;
    }

    /**
     * Static helper: build a query for blocked/quarantined packages.
     */
    static blocked() {
        return 'status:quarantined OR deny_policy_violated:true';
    }
}

module.exports = { SearchQueryBuilder };
