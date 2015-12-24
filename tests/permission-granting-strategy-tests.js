
Tinytest.add('SecurityAcl - PermissionGrantingStrategy', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  test.throws(function () {
    SecurityAcl.PermissionGrantingStrategy();
  }, 'Use "new" to construct a SecurityAcl.PermissionGrantingStrategy');
  
  // Test: isAceApplicable
  var oid = new SecurityAcl.ObjectIdentity('identifier', 'className');
  var permissionGrantingStrategy = new SecurityAcl.PermissionGrantingStrategy();
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [], true);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  
  var entry = new SecurityAcl.Entry('id', acl, sid, 'invalid-strategy', 128, true, true, true);
  
  test.throws(function () {
    permissionGrantingStrategy._isAceApplicable(128, entry);
  }, 'The strategy invalid-strategy is not supported.');
  
  var entry = new SecurityAcl.Entry('id', acl, sid, 'ALL', 3, true, true, true);
  
  test.isTrue(permissionGrantingStrategy._isAceApplicable(1, entry),'ACE (mask 3) is applicable for a mask 1.');
  test.isTrue(permissionGrantingStrategy._isAceApplicable(2, entry),'ACE (mask 3) is applicable for a mask 2.');
  test.isTrue(permissionGrantingStrategy._isAceApplicable(3, entry),'ACE (mask 3) is applicable for a mask 3.');
  test.isFalse(permissionGrantingStrategy._isAceApplicable(4, entry),'ACE (mask 3) is not applicable for a mask 4.');
  test.isFalse(permissionGrantingStrategy._isAceApplicable(5, entry),'ACE (mask 3) is not applicable for a mask 5.');
  
  var entry = new SecurityAcl.Entry('id', acl, sid, 'ANY', 3, true, true, true);
  
  test.isTrue(permissionGrantingStrategy._isAceApplicable(1, entry),'ACE (mask 3) is applicable for a mask 1.');
  test.isTrue(permissionGrantingStrategy._isAceApplicable(2, entry),'ACE (mask 3) is applicable for a mask 2.');
  test.isTrue(permissionGrantingStrategy._isAceApplicable(3, entry),'ACE (mask 3) is applicable for a mask 3.');
  test.isFalse(permissionGrantingStrategy._isAceApplicable(4, entry),'ACE (mask 3) is not applicable for a mask 4.');
  test.isTrue(permissionGrantingStrategy._isAceApplicable(5, entry),'ACE (mask 3) is applicable for a mask 5.');
  
  var entry = new SecurityAcl.Entry('id', acl, sid, 'EQUAL', 3, true, true, true);
  
  test.isFalse(permissionGrantingStrategy._isAceApplicable(1, entry),'ACE (mask 3) is not applicable for a mask 1.');
  test.isFalse(permissionGrantingStrategy._isAceApplicable(2, entry),'ACE (mask 3) is not applicable for a mask 2.');
  test.isTrue(permissionGrantingStrategy._isAceApplicable(3, entry),'ACE (mask 3) is applicable for a mask 3.');
  test.isFalse(permissionGrantingStrategy._isAceApplicable(4, entry),'ACE (mask 3) is not applicable for a mask 4.');
  test.isFalse(permissionGrantingStrategy._isAceApplicable(5, entry),'ACE (mask 3) is not applicable for a mask 5.');
  
  // Test: hasPermissions
  
  var entry = new SecurityAcl.Entry('id', acl, sid, 'ALL', 3, true, true, true);
  var aces = [entry];
  var masks = [3];
  var sids = [sid];
  
  test.isTrue(permissionGrantingStrategy._hasPermissions(acl, aces, masks, sids, false),'It returns true for ACE mask 3.');
  
  var masks = [4];
  
  test.throws(function () {
    permissionGrantingStrategy._hasPermissions(acl, aces, masks, sids, false);
  }, 'No ACE found.');
  
  // Test: isGranted
  var masks = [3];
  var sids = [sid];
  
  test.throws(function () {
    permissionGrantingStrategy.isGranted(acl, masks, sids, false);
  }, 'No ACE found.');
  
  // we add ACE to ACL
  //class-scope
  var aclService = new SecurityAcl.Service();
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  var acl = aclService.createAcl(oid);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  var masks = [1];
  var sids = [sid];
  acl.insertClassAce(sid, 3);
  aclService.updateAcl(acl);
  
  test.isTrue(permissionGrantingStrategy.isGranted(acl, masks, sids, false),'It returns true for ACE mask 3.');
  
  var masks = [2];
  
  test.isTrue(permissionGrantingStrategy.isGranted(acl, masks, sids, false),'It returns true for ACE mask 3.');
  
  var masks = [3];
  
  test.isTrue(permissionGrantingStrategy.isGranted(acl, masks, sids, false),'It returns true for ACE mask 3.');
  
  var masks = [4];
  
  test.throws(function () {
    permissionGrantingStrategy.isGranted(acl, masks, sids, false);
  }, 'No ACE found.');
  
  // Test: isFieldGranted
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  var aclService = new SecurityAcl.Service();
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  var acl = aclService.createAcl(oid);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  var masks = [3];
  var sids = [sid];
  
  test.throws(function () {
    permissionGrantingStrategy.isFieldGranted(acl, 'field', masks, sids, false);
  }, 'No ACE found.');
  
  // we add an ACE
  var masks = [1];
  acl.insertClassFieldAce('field', sid, 3);
  aclService.updateAcl(acl);
  
  test.isTrue(permissionGrantingStrategy.isFieldGranted(acl, 'field', masks, sids, false),'It returns true for ACE mask 3.');
  
  var masks = [2];
  
  test.isTrue(permissionGrantingStrategy.isFieldGranted(acl, 'field', masks, sids, false),'It returns true for ACE mask 3.');
  
  var masks = [3];
  
  test.isTrue(permissionGrantingStrategy.isFieldGranted(acl, 'field', masks, sids, false),'It returns true for ACE mask 3.');
  
  var masks = [4];
  
  test.throws(function () {
    permissionGrantingStrategy.isFieldGranted(acl, 'field', masks, sids, false);
  }, 'No ACE found.');
  
});