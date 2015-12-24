
// tests
Tinytest.add('SecurityAcl - Collections', function (test) {
  test.isNotUndefined(SecurityAcl, 'defined');
  test.isNotUndefined(SecurityAcl.Classes, 'defined');
  test.isNotUndefined(SecurityAcl.ObjectIdentities, 'defined');
  test.isNotUndefined(SecurityAcl.ObjectIdentitiesAncestors, 'defined');
  test.isNotUndefined(SecurityAcl.Entries, 'defined');
  test.isNotUndefined(SecurityAcl.SecurityIdentities, 'defined');
});