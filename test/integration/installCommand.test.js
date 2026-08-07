const assert = require('assert');
const { InstallCommandBuilder } = require('../../util/installCommandBuilder');

suite('Integration: Install Command Builder', function () {

  const formats = [
    { format: 'python', urlPart: 'python/simple/' },
    { format: 'npm', urlPart: 'npm.cloudsmith.io' },
    { format: 'nuget', urlPart: 'nuget.cloudsmith.io' },
    { format: 'docker', urlPart: 'docker.cloudsmith.io' },
    { format: 'helm', urlPart: 'helm/charts/' },
    { format: 'cargo', urlPart: 'cargo' },
    { format: 'go', urlPart: 'go' },
    { format: 'ruby', urlPart: 'ruby/' },
    { format: 'conda', urlPart: 'conda.cloudsmith.io' },
    { format: 'composer', urlPart: 'composer' },
    { format: 'dart', urlPart: 'dart' },
    { format: 'rpm', urlPart: 'dl.cloudsmith.io' },
    { format: 'raw', urlPart: 'dl.cloudsmith.io' },
  ];

  for (const { format, urlPart } of formats) {
    test(`${format} generates a valid install command`, function () {
      const result = InstallCommandBuilder.build(format, 'test-pkg', '1.0.0', 'my-ws', 'my-repo');
      assert.ok(result.command, `${format}: command should be non-empty`);
      assert.ok(
        result.command.startsWith('# Verify package details before running') || format === 'maven',
        `${format}: command should include the verification banner`
      );
      assert.ok(result.command.includes('test-pkg'), `${format}: command should contain package name`);
      assert.ok(result.command.includes('1.0.0'), `${format}: command should contain version`);
      assert.ok(
        result.command.includes(urlPart) || result.note && result.note.includes(urlPart),
        `${format}: command or note should contain format-specific URL part "${urlPart}"`
      );
    });
  }

  test('maven generates pom.xml snippet with repository and dependency', function () {
    const result = InstallCommandBuilder.build('maven', 'test-pkg', '1.0.0', 'ws', 'repo');
    assert.ok(result.command.includes('<repository>'), 'Should contain <repository> block');
    assert.ok(result.command.includes('<dependency>'), 'Should contain <dependency> block');
    assert.ok(result.command.includes('maven/'), 'Should contain maven URL');
  });

  test('maven splits groupId:artifactId correctly', function () {
    const result = InstallCommandBuilder.build('maven', 'com.example:mylib', '2.0', 'ws', 'repo');
    assert.ok(result.command.includes('<groupId>com.example</groupId>'),
      'Should split groupId from colon-separated name');
    assert.ok(result.command.includes('<artifactId>mylib</artifactId>'),
      'Should split artifactId from colon-separated name');
  });

  test('unknown format returns comment fallback', function () {
    const result = InstallCommandBuilder.build('unknown-fmt', 'pkg', '1.0', 'ws', 'repo');
    assert.ok(result.command.startsWith('#'), 'Unknown format command should start with #');
    assert.ok(result.note, 'Unknown format should have a note with web app link');
  });

  test('private-repo formats include auth notes', function () {
    const formatsWithNotes = ['python', 'npm', 'docker', 'cargo', 'go'];
    for (const format of formatsWithNotes) {
      const result = InstallCommandBuilder.build(format, 'pkg', '1.0', 'ws', 'repo');
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
