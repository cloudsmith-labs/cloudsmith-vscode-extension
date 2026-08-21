const assert = require('assert');
const { SearchQueryBuilder } = require('../util/searchQueryBuilder');

suite('SearchQueryBuilder Test Suite', () => {

	test('name() produces name:value', () => {
		const builder = new SearchQueryBuilder();
		assert.strictEqual(builder.name('flask').build(), 'name:flask');
	});

	test('format() produces format:value', () => {
		const builder = new SearchQueryBuilder();
		assert.strictEqual(builder.format('python').build(), 'format:python');
	});

	test('status() produces status:value', () => {
		const builder = new SearchQueryBuilder();
		assert.strictEqual(builder.status('quarantined').build(), 'status:quarantined');
	});

	test('version() produces version:value', () => {
		const builder = new SearchQueryBuilder();
		assert.strictEqual(builder.version('3.0.0').build(), 'version:3.0.0');
	});

	test('tag() produces tag:value', () => {
		const builder = new SearchQueryBuilder();
		assert.strictEqual(builder.tag('production').build(), 'tag:production');
	});

	test('build() joins multiple terms with AND', () => {
		const builder = new SearchQueryBuilder();
		const result = builder.name('flask').format('python').build();
		assert.strictEqual(result, 'name:flask AND format:python');
	});

	test('chaining works across all methods', () => {
		const builder = new SearchQueryBuilder();
		const result = builder.name('flask').format('python').status('completed').version('3.0.0').build();
		assert.strictEqual(result, 'name:flask AND format:python AND status:completed AND version:3.0.0');
	});

	test('reset() clears terms', () => {
		const builder = new SearchQueryBuilder();
		builder.name('flask').format('python');
		builder.reset();
		assert.strictEqual(builder.build(), '');
	});

	test('raw() passes through query string', () => {
		const builder = new SearchQueryBuilder();
		assert.strictEqual(builder.raw('downloads:>100').build(), 'downloads:>100');
	});

	test('raw() with empty string is ignored', () => {
		const builder = new SearchQueryBuilder();
		builder.raw('').raw(null).raw(undefined);
		assert.strictEqual(builder.build(), '');
	});

	test('raw() combined with field methods', () => {
		const builder = new SearchQueryBuilder();
		const result = builder.name('flask').raw('NOT status:quarantined').build();
		assert.strictEqual(result, 'name:flask AND NOT status:quarantined');
	});

	test('values with spaces are quoted', () => {
		const builder = new SearchQueryBuilder();
		assert.strictEqual(builder.name('my package').build(), 'name:"my package"');
	});

	test('field methods escape special query characters', () => {
		const builder = new SearchQueryBuilder();
		const result = builder.name('pkg:"beta"').build();
		assert.strictEqual(result, 'name:pkg\\:\\\"beta\\\"');
	});

	test('registry-native slash identities remain searchable while query operators are escaped', () => {
		const builder = new SearchQueryBuilder();
		assert.strictEqual(
			builder.name('@scope/package OR status:quarantined').build(),
			'name:"@scope/package OR status\\:quarantined"'
		);
	});

	test('ordinary hyphen and plus identity characters remain searchable', () => {
		const builder = new SearchQueryBuilder();
		assert.strictEqual(
			builder.name('@aws-sdk/client-s3').version('1.2.3-beta+build').build(),
			'name:@aws-sdk/client-s3 AND version:1.2.3-beta+build'
		);
	});

	test('empty build returns empty string', () => {
		const builder = new SearchQueryBuilder();
		assert.strictEqual(builder.build(), '');
	});

	test('permissible() static produces correct query', () => {
		const result = SearchQueryBuilder.permissible('flask');
		assert.strictEqual(result, 'name:flask AND NOT status:quarantined AND deny_policy_violated:false');
	});

	test('blocked() static produces correct query', () => {
		const result = SearchQueryBuilder.blocked();
		assert.strictEqual(result, 'status:quarantined OR deny_policy_violated:true');
	});

	test('reset() returns builder for chaining', () => {
		const builder = new SearchQueryBuilder();
		const result = builder.name('old').reset().name('new').build();
		assert.strictEqual(result, 'name:new');
	});

	test('permissible() escapes special characters in package names', () => {
		const result = SearchQueryBuilder.permissible('pkg:name');
		assert.strictEqual(result, 'name:pkg\\:name AND NOT status:quarantined AND deny_policy_violated:false');
	});
});
