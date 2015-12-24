Package.describe({
  name: 'aumel:security-acl',
  version: '0.4.0',
  // Brief, one-line summary of the package.
  summary: 'An Access Control List (ACL) security system.',
  // URL to the Git repository containing the source code for this package.
  git: 'https://github.com/aumel/meteor-security-acl',
  // By default, Meteor will default to using README.md for documentation.
  // To avoid submitting documentation, set this field to null.
  documentation: 'README.md'
});

Package.onUse(function(api) {
  api.versionsFrom('1.2');
  api.addFiles('src/utils/utils.js');
  api.addFiles('src/utils/cycle.js');
  api.addFiles('src/security-acl.js');
  api.addFiles('src/service/service.js');
  api.addFiles('src/domain/acl.js');
  api.addFiles('src/domain/object-identity.js');
  api.addFiles('src/domain/permission-granting-strategy.js');
  api.addFiles('src/domain/security-identity.js');
  api.addFiles('src/domain/user-security-identity.js');
  api.addFiles('src/domain/role-security-identity.js');
  api.addFiles('src/domain/entry.js');
  api.addFiles('src/domain/field-entry.js');
  api.addFiles('src/permission/mask-builder.js');
  api.addFiles('src/permission/permission-map.js');
  api.addFiles('src/domain/security-identity-retrieval-strategy.js');
  api.addFiles('src/domain/object-identity-retrieval-strategy.js');
  api.addFiles('src/voter/field-vote.js');
  api.addFiles('src/voter/acl-voter.js');
  api.addFiles('src/authorization-checker/authorization-checker.js');
  api.use('mongo', ['client', 'server']);
  api.use('underscore');
  api.export('SecurityAcl');
});

Package.onTest(function(api) {
  api.use('accounts-password');
  api.use('ecmascript');
  api.use('tinytest');
  api.use('aumel:security-acl');
  api.use('mongo', ['client', 'server']);

  api.addFiles('tests/test-helpers.js', 'server');
  api.addFiles('tests/setup-tests.js', 'server');
  api.addFiles('tests/security-acl-tests.js', 'server');
  api.addFiles('tests/acl-tests.js', 'server');
  api.addFiles('tests/object-identity-tests.js', 'server');
  api.addFiles('tests/entry-tests.js', 'server');
  api.addFiles('tests/field-entry-tests.js', 'server');
  api.addFiles('tests/security-identity-tests.js', 'server');
  api.addFiles('tests/permission-granting-strategy-tests.js', 'server');
  api.addFiles('tests/mask-builder-tests.js', 'server');
  api.addFiles('tests/permission-map-tests.js', 'server');
  api.addFiles('tests/acl-service-tests.js', 'server');
  api.addFiles('tests/authorization-checker-tests.js', ['server']);
  api.addFiles('tests/authorization-checker-meteor-user-tests.js', ['client', 'server']);/**/


});
