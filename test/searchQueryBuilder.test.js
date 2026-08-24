const assert = require('assert');
const { SearchQueryBuilder } = require('../util/searchQueryBuilder');
const { buildAdvancedSearchQuery } = require('../commands/support');

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

	test('advanced() accepts a bounded query DSL without escaping its operators', () => {
		const builder = new SearchQueryBuilder();
		assert.strictEqual(
			builder.advanced('name:^flask$ OR (format:python AND NOT status:quarantined)').build(),
			'name:^flask$ OR (format:python AND NOT status:quarantined)'
		);
	});

	test('advanced() rejects blank, control-bearing, bidi, and oversized query text', () => {
		for (const query of ['', '   ', 'name:foo\nOR name:bar', 'name:foo\u202e', 'x'.repeat(2049)]) {
			assert.throws(
				() => new SearchQueryBuilder().advanced(query),
				/Advanced Cloudsmith query/,
				query
			);
		}
	});

	test('build() enforces the aggregate transport boundary across individually valid terms', () => {
		const builder = new SearchQueryBuilder()
			.advanced('x'.repeat(1024))
			.advanced('y'.repeat(1024));

		assert.throws(() => builder.build(), /safe transport boundary/);
	});

	test('user-authored advanced queries do not cross the trusted raw() boundary', () => {
		let advancedInput = null;
		class BoundaryBuilder {
			advanced(value) {
				advancedInput = value;
				return this;
			}
			raw() {
				throw new Error('raw() must remain limited to trusted internal fragments');
			}
			build() {
				return advancedInput;
			}
		}

		assert.strictEqual(
			buildAdvancedSearchQuery(BoundaryBuilder, 'name:widget OR format:npm'),
			'name:widget OR format:npm'
		);
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

	test('leading modifier hardening preserves established boolean-symbol escaping', () => {
		assert.strictEqual(
			new SearchQueryBuilder().name('foo&&bar||baz').build(),
			'name:foo\\&&bar\\||baz'
		);
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

	test('escapes only leading plus and minus runs while preserving registry-native identity syntax', () => {
		const cases = [
			['foo-bar', 'foo-bar'],
			['foo+bar', 'foo+bar'],
			['1.2.3-beta+build', '1.2.3-beta+build'],
			['@scope/package', '@scope/package'],
			['@aws-sdk/client-s3', '@aws-sdk/client-s3'],
			['+foo', '\\+foo'],
			['-foo', '\\-foo'],
			['++foo', '\\+\\+foo'],
			['--foo', '\\-\\-foo'],
			['+-foo', '\\+\\-foo'],
			['-+foo', '\\-\\+foo'],
			['+foo-bar', '\\+foo-bar'],
			['-foo+bar', '\\-foo+bar'],
			['value with spaces', '"value with spaces"'],
			['+value with spaces', '"\\+value with spaces"'],
			['-value with spaces', '"\\-value with spaces"'],
			['path\\segment', 'path\\\\segment'],
			['field:value', 'field\\:value'],
			['end$anchor', 'end\\$anchor'],
			['version>1<2', 'version\\>1\\<2'],
			["'quoted'", "\\'quoted\\'"],
			['say "hello"', '"say \\"hello\\""'],
			['OR NOT status:quarantined', '"OR NOT status\\:quarantined"'],
		];

		for (const [input, escaped] of cases) {
			assert.strictEqual(
				new SearchQueryBuilder().name(input).build(),
				`name:${escaped}`,
				input
			);
		}
	});

	test('neutralizes leading modifiers consistently for every escaped builder field', () => {
		const builderMethods = ['name', 'format', 'status', 'version', 'tag'];
		for (const method of builderMethods) {
			assert.strictEqual(
				new SearchQueryBuilder()[method]('+-hostile').build(),
				`${method}:\\+\\-hostile`,
				method
			);
			assert.strictEqual(
				new SearchQueryBuilder()[method]('literal$identity').build(),
				`${method}:literal\\$identity`,
				method
			);
			assert.strictEqual(
				new SearchQueryBuilder()[method](">literal<'identity'").build(),
				`${method}:\\>literal\\<\\'identity\\'`,
				method
			);
		}
		assert.strictEqual(
			SearchQueryBuilder.permissible('--hostile'),
			'name:\\-\\-hostile AND NOT status:quarantined AND deny_policy_violated:false'
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

	test('permissible() enforces the same final control and length boundary', () => {
		assert.throws(() => SearchQueryBuilder.permissible('name\nOR status:quarantined'));
		assert.throws(() => SearchQueryBuilder.permissible('x'.repeat(2048)));
	});
});
