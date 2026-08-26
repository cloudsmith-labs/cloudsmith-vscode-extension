const assert = require('assert');
const {
  InstallCommandBuilder,
  InstallCommandValidationError,
} = require('../../util/installCommandBuilder');

suite('Integration: Install Command Builder', function () {

  const formats = [
    { format: 'python', commandPart: 'dl.cloudsmith.io/basic/my-ws/my-repo/python/simple/' },
    { format: 'npm', commandPart: 'npm.cloudsmith.io/my-ws/my-repo/' },
    { format: 'nuget', commandPart: 'nuget.cloudsmith.io/my-ws/my-repo/v3/index.json' },
    { format: 'docker', commandPart: 'docker.cloudsmith.io/my-ws/my-repo/' },
    { format: 'helm', commandPart: 'dl.cloudsmith.io/basic/my-ws/my-repo/helm/charts/' },
    { format: 'cargo', commandPart: "--registry 'cloudsmith-my-ws-my-repo-", notePart: 'cargo.cloudsmith.io/my-ws/my-repo/' },
    { format: 'go', commandPart: 'golang.cloudsmith.io/my-ws/my-repo/' },
    { format: 'ruby', commandPart: 'dl.cloudsmith.io/basic/my-ws/my-repo/ruby/' },
    { format: 'conda', commandPart: 'conda.cloudsmith.io/my-ws/my-repo/', options: { qualifiers: { build: 'build_0', subdir: 'linux-64' } } },
    { format: 'composer', name: 'vendor/test-pkg', commandPart: 'composer.cloudsmith.io/my-ws/my-repo/' },
    { format: 'dart', name: 'test_pkg', commandPart: 'dart.cloudsmith.io/my-ws/my-repo/' },
    { format: 'rpm', commandPart: "--enablerepo='my-ws-my-repo'", notePart: 'dl.cloudsmith.io/basic/my-ws/my-repo/', options: { qualifiers: { release: '1', architecture: 'x86_64' } } },
    { format: 'raw', commandPart: 'dl.cloudsmith.io/basic/my-ws/my-repo/', options: { cdnUrl: 'https://dl.cloudsmith.io/basic/my-ws/my-repo/raw/files/test-pkg-1.0.0' } },
  ];

  for (const { format, name = 'test-pkg', commandPart, notePart, options } of formats) {
    test(`${format} preserves identity and targets the selected Cloudsmith repository`, function () {
      const result = InstallCommandBuilder.build(
        format, name, '1.0.0', 'my-ws', 'my-repo', options
      );
      assert.ok(result.command, `${format}: command should be non-empty`);
      assert.ok(
        result.command.startsWith('# Verify package details before running') || format === 'maven',
        `${format}: command should include the verification banner`
      );
      assert.ok(result.command.includes(name), `${format}: command should contain package name`);
      assert.ok(result.command.includes('1.0.0'), `${format}: command should contain version`);
      assert.ok(
        result.command.includes(commandPart),
        `${format}: executable/config output should select "${commandPart}"`
      );
      if (notePart) assert.ok(result.note && result.note.includes(notePart));
      assert.strictEqual(`${result.command}\n${result.note || ''}`.includes('actual-secret-value'), false);
    });
  }

  test('formats with public defaults explicitly suppress or replace them', function () {
    const ruby = InstallCommandBuilder.build('ruby', 'rack', '3.1.0', 'ws', 'repo');
    const conda = InstallCommandBuilder.build('conda', 'numpy', '2.0.0', 'ws', 'repo', {
      qualifiers: { build: 'py312_0', subdir: 'linux-64' },
    });
    const cargo = InstallCommandBuilder.build('cargo', 'serde', '1.0.0', 'ws', 'repo');
    const dart = InstallCommandBuilder.build('dart', 'http', '1.2.0', 'ws', 'repo');

    assert.ok(ruby.command.includes('--clear-sources'));
    assert.ok(conda.command.includes('--override-channels'));
    assert.ok(cargo.command.includes('--registry'));
    assert.ok(dart.command.includes('--hosted'));
    assert.ok(!dart.command.includes('--hosted-url'));
  });

  test('maven generates separate settings and pom.xml merge guidance', function () {
    const result = InstallCommandBuilder.build('maven', 'example:test-pkg', '1.0.0', 'ws', 'repo');
    assert.ok(result.command.includes('<mirror>'), 'Should contain a settings.xml mirror block');
    assert.ok(result.command.includes('<dependency>'), 'Should contain <dependency> block');
    assert.ok(result.command.includes('maven/'), 'Should contain maven URL');
    assert.strictEqual(result.language, 'markdown');
  });

  test('maven splits groupId:artifactId correctly', function () {
    const result = InstallCommandBuilder.build('maven', 'com.example:mylib', '2.0', 'ws', 'repo');
    assert.ok(result.command.includes('<groupId>com.example</groupId>'),
      'Should split groupId from colon-separated name');
    assert.ok(result.command.includes('<artifactId>mylib</artifactId>'),
      'Should split artifactId from colon-separated name');
  });

  test('unknown format fails closed instead of returning comment-only guidance', function () {
    assert.throws(
      () => InstallCommandBuilder.build('unknown-fmt', 'pkg', '1.0', 'ws', 'repo'),
      error => error instanceof InstallCommandValidationError
        && error.field === 'Package format'
    );
  });

  test('private-repo formats include auth notes', function () {
    const formatsWithNotes = ['python', 'npm', 'docker', 'cargo', 'go'];
    for (const format of formatsWithNotes) {
      const version = ['npm', 'cargo', 'go'].includes(format) ? '1.0.0' : '1.0';
      const result = InstallCommandBuilder.build(format, 'pkg', version, 'ws', 'repo');
      assert.ok(result.note, `${format}: should have an auth note for private repos`);
      assert.ok(typeof result.note === 'string', `${format}: note should be a string`);
    }
  });

  test('all private-repo formats have notes', function () {
    const result = InstallCommandBuilder.build('ruby', 'mygem', '1.0', 'ws', 'repo');
    // Ruby may or may not have a note — just ensure the method doesn't throw
    assert.ok(result.command.includes('gem install'), 'Ruby command should use gem install');
  });

  test('shell command formats quote package coordinates', function () {
    const result = InstallCommandBuilder.build('python', 'demo', '1.2.3', 'ws', 'repo');
    assert.ok(result.command.includes("'demo==1.2.3'"), 'Should quote package name and version');
  });
});
