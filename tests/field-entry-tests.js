
Tinytest.add('SecurityAcl - FieldEntry', function (test) {
  
  var oid = new SecurityAcl.ObjectIdentity('identifier', 'className');
  var permissionGrantingStrategy = new SecurityAcl.PermissionGrantingStrategy();
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [], true);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  var field = 'field';
  
  test.throws(function () {
    SecurityAcl.FieldEntry('id', acl, field, sid, 'strategy', 128, true, true, true);
  }, 'Use "new" to construct a SecurityAcl.FieldEntry');
  
  test.throws(function () {
    new SecurityAcl.FieldEntry('id', 'invalidAcl', field, sid, 'strategy', 128, true, true, true);
  }, 'The acl must be an instance of SecurityAcl.Acl.');
  
  test.throws(function () {
    new SecurityAcl.FieldEntry('id', acl, field, 'invalidSid', 'strategy', 128, true, true, true);
  }, 'The sid must be an instance of SecurityAcl.SecurityIdentity.');
  
  test.throws(function () {
    new SecurityAcl.FieldEntry('id', acl, field, sid, 12345, 128, true, true, true);
  }, 'The strategy must be a string.');
  
  test.throws(function () {
    new SecurityAcl.FieldEntry('id', acl, field, sid, 'strategy', 564.2, true, true, true);
  }, 'The mask must be an integer.');
  
  test.throws(function () {
    new SecurityAcl.FieldEntry('id', acl, field, sid, 'strategy', 128, 'invalidGranting', true, true);
  }, 'The granting must be a boolean.');
  
  test.throws(function () {
    new SecurityAcl.FieldEntry('id', acl, field, sid, 'strategy', 128, true, 'invalidAuditFailure', true);
  }, 'The auditFailure must be a boolean.');
  
  test.throws(function () {
    new SecurityAcl.FieldEntry('id', acl, field, sid, 'strategy', 128, true, true, 'invalidAuditSuccess');
  }, 'The auditSuccess must be a boolean.');
  
  var fieldEntry = new SecurityAcl.FieldEntry('id', acl, field, sid, 'strategy', 128, true, true, true);
  
  test.equal(fieldEntry.id(), 'id', 'id() returns the id value.');
  test.equal(fieldEntry.acl(), acl, 'acl() returns the acl value.');
  test.equal(fieldEntry.field(), 'field', 'field() returns the field value.');
  test.equal(fieldEntry.sid(), sid, 'sid() returns the sid value.');
  test.equal(fieldEntry.strategy(), 'strategy', 'strategy() returns the strategy value.');
  test.equal(fieldEntry.mask(), 128, 'mask() returns the mask value.');
  test.isTrue(fieldEntry.isGranting(),'isGranting() returns whether this ACE is granting, or denying.');
  
});