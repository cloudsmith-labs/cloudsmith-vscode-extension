// Builds query strings for the Cloudsmith packages API.
// Handles escaping, boolean operators, and field-specific syntax.

const MAX_ADVANCED_QUERY_LENGTH = 2048;
const MAX_STRICT_FIELD_VALUE_LENGTH = 2048;
const QUERY_CONTROL_OR_BIDI_PATTERN = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/;

function isValidAdvancedQuery(value) {
    return typeof value === 'string'
        && value.trim().length > 0
        && value.length <= MAX_ADVANCED_QUERY_LENGTH
        && !QUERY_CONTROL_OR_BIDI_PATTERN.test(value);
}

function escapeCloudsmithQueryValue(value) {
    const normalized = typeof value === 'string' ? value : String(value);
    return quoteCloudsmithQueryValue(escapeCloudsmithQueryLiteral(normalized));
}

function escapeExactCloudsmithQueryValue(value) {
    const normalized = normalizeStrictCloudsmithQueryValue(value);
    const escaped = escapeCloudsmithQueryLiteral(normalized);
    return quoteCloudsmithQueryValue(`^${escaped}$`);
}

function normalizeStrictCloudsmithQueryValue(value) {
    if (typeof value === 'number') {
        if (!Number.isFinite(value)) {
            throw new TypeError('Cloudsmith query field value must be finite.');
        }
        return String(value);
    }
    if (
        typeof value !== 'string'
        || value.trim().length === 0
        || value.trim() !== value
        || value.length > MAX_STRICT_FIELD_VALUE_LENGTH
        || QUERY_CONTROL_OR_BIDI_PATTERN.test(value)
    ) {
        throw new TypeError('Cloudsmith query field value is invalid.');
    }
    return value;
}

function escapeCloudsmithQueryLiteral(normalized) {
    return normalized.replace(
        /(?:^[+-]+|\\|&&|\|\||[!(){}\[\]^$'"~*?:<>|&])/g,
        (match, offset) => (
            offset === 0 && /^[+-]+$/.test(match)
                ? [...match].map((character) => `\\${character}`).join('')
                : `\\${match}`
        )
    );
}

function quoteCloudsmithQueryValue(escaped) {
    return /\s/.test(escaped) ? `"${escaped}"` : escaped;
}

class SearchQueryBuilder {
    constructor() {
        this.terms = [];
    }

    /**
     * Escape a value for use in a Cloudsmith query.
     */
    _escapeValue(value) {
        return escapeCloudsmithQueryValue(value);
    }

    /** Add a name search term. */
    name(value) {
        this.terms.push(`name:${this._escapeValue(value)}`);
        return this;
    }

    /** Add an exact canonical package-name term. */
    exactName(value) {
        this.terms.push(`name:${escapeExactCloudsmithQueryValue(value)}`);
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

    /** Add a semantic version lower bound, excluding the current version. */
    versionGreaterThan(value) {
        this.terms.push(`version:>${this._escapeValue(normalizeStrictCloudsmithQueryValue(value))}`);
        return this;
    }

    /** Add an inclusive semantic version lower bound. */
    versionAtLeast(value) {
        this.terms.push(`version:>=${this._escapeValue(normalizeStrictCloudsmithQueryValue(value))}`);
        return this;
    }

    /** Add a tag filter. */
    tag(value) {
        this.terms.push(`tag:${this._escapeValue(value)}`);
        return this;
    }

    /**
     * Add a user-authored Cloudsmith query-language expression after validating
     * its transport boundary. Operators remain intentional DSL, not field data.
     */
    advanced(queryString) {
        if (typeof queryString !== 'string') {
            throw new TypeError('Advanced Cloudsmith query must be a string.');
        }
        const query = queryString.trim();
        if (!isValidAdvancedQuery(query)) {
            throw new TypeError('Advanced Cloudsmith query is invalid.');
        }
        this.terms.push(query);
        return this;
    }

    /**
     * Add a raw query term (pass-through for advanced users).
     * @warning Raw input is not escaped or validated; only use trusted internal fragments here.
     */
    raw(queryString) {
        if (queryString) {
            this.terms.push(queryString);
        }
        return this;
    }

    /** Build the final query string. */
    build() {
        const query = this.terms.join(' AND ');
        if (query && !isValidAdvancedQuery(query)) {
            throw new RangeError('Cloudsmith query exceeds the safe transport boundary.');
        }
        return query;
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
        return new SearchQueryBuilder()
            .name(name)
            .raw('NOT status:quarantined')
            .raw('deny_policy_violated:false')
            .build();
    }

    /**
     * Static helper: build a query for blocked/quarantined packages.
     */
    static blocked() {
        return 'status:quarantined OR deny_policy_violated:true';
    }
}

module.exports = {
    SearchQueryBuilder,
    escapeCloudsmithQueryValue,
    isValidAdvancedQuery,
};
