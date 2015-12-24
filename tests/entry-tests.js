
Tinytest.add('SecurityAcl - Entry', function (test) {
  
  var oid = new SecurityAcl.ObjectIdentity('identifier', 'className');
  var permissionGrantingStrategy = new SecurityAcl.PermissionGrantingStrategy();
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [], true);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  
  test.throws(function () {
    SecurityAcl.Entry('id', acl, sid, 'strategy', 128, true, true, true);
  }, 'Use "new" to construct a SecurityAcl.Entry');
  
  test.throws(function () {
    new SecurityAcl.Entry('id', 'invalidAcl', sid, 'strategy', 128, true, true, true);
  }, 'The acl must be an instance of SecurityAcl.Acl.');
  
  test.throws(function () {
    new SecurityAcl.Entry('id', acl, 'invalidSid', 'strategy', 128, true, true, true);
  }, 'The sid must be an instance of SecurityAcl.SecurityIdentity.');
  
  test.throws(function () {
    new SecurityAcl.Entry('id', acl, sid, 12345, 128, true, true, true);
  }, 'The strategy must be a string.');
  
  test.throws(function () {
    new SecurityAcl.Entry('id', acl, sid, 'strategy', 564.2, true, true, true);
  }, 'The mask must be an integer.');
  
  test.throws(function () {
    new SecurityAcl.Entry('id', acl, sid, 'strategy', 128, 'invalidGranting', true, true);
  }, 'The granting must be a boolean.');
  
  test.throws(function () {
    new SecurityAcl.Entry('id', acl, sid, 'strategy', 128, true, 'invalidAuditFailure', true);
  }, 'The auditFailure must be a boolean.');
  
  test.throws(function () {
    new SecurityAcl.Entry('id', acl, sid, 'strategy', 128, true, true, 'invalidAuditSuccess');
  }, 'The auditSuccess must be a boolean.');
  
  var entry = new SecurityAcl.Entry('id', acl, sid, 'strategy', 128, true, true, true);
  
  test.equal(entry.id(), 'id', 'id() returns the id value.');
  test.equal(entry.acl(), acl, 'acl() returns the acl value.');
  test.equal(entry.sid(), sid, 'sid() returns the sid value.');
  test.equal(entry.strategy(), 'strategy', 'strategy() returns the strategy value.');
  test.equal(entry.mask(), 128, 'mask() returns the mask value.');
  test.isTrue(entry.isGranting(),'isGranting() returns whether this ACE is granting, or denying.');
  test.isTrue(entry.isAuditSuccess(),'isAuditSuccess() returns the auditSuccess boolean value.');
  test.isTrue(entry.isAuditFailure(),'isAuditFailure() returns the auditFailure boolean value.');
  
  entry.setMask(256);
  
  test.equal(entry.mask(), 256, 'setMask() sets the permission mask.');
  
  entry.setStrategy('new strategy');
  
  test.equal(entry.strategy(), 'new strategy', 'setStrategy() sets the mask comparison strategy.');
  
});