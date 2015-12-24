
Tinytest.add('SecurityAcl - SecurityIdentity', function (test) {
  
  test.throws(function () {
    SecurityAcl.UserSecurityIdentity('username', 'className');
  }, 'Use "new" to construct a SecurityAcl.UserSecurityIdentity');
  
  test.throws(function () {
    new SecurityAcl.UserSecurityIdentity(null, 'className');
  }, 'Username cannot be null or undefined.');
  
  test.throws(function () {
    new SecurityAcl.UserSecurityIdentity('username', null);
  }, 'ClassName cannot be null or undefined.');
  
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  test.isTrue(sid instanceof SecurityAcl.SecurityIdentity, 'UserSecurityIdentity from SecurityIdentity');
  test.equal(sid.username(), 'username', 'Username() returns the username value.');
  test.equal(sid.className(), 'className', 'className() returns the className value.');
  
  var sid2 = 'invalidSid';
  test.isFalse(sid.equals(sid2), 'Equals methods returns false if sid is not an instance of UserSecurityIdentity.');
  
  var sid2 = new SecurityAcl.UserSecurityIdentity('username2', 'className');
  test.isFalse(sid.equals(sid2), 'Equals methods returns false if username of sid is different.');
  
  var sid2 = new SecurityAcl.UserSecurityIdentity('username', 'className2');
  test.isFalse(sid.equals(sid2), 'Equals methods returns false if className of sid is different.');
  
  var sid2 = new SecurityAcl.UserSecurityIdentity('username', 'className');
  test.isTrue(sid.equals(sid2), 'Equals methods returns true if sid is equal.');
  
  
  test.throws(function () {
    SecurityAcl.RoleSecurityIdentity('role');
  }, 'Use "new" to construct a SecurityAcl.RoleSecurityIdentity');
  
  test.throws(function () {
    new SecurityAcl.RoleSecurityIdentity(null);
  }, 'Role cannot be null or undefined.');
  
  var sid = new SecurityAcl.RoleSecurityIdentity('role');
  test.isTrue(sid instanceof SecurityAcl.SecurityIdentity, 'RoleSecurityIdentity from SecurityIdentity');
  test.equal(sid.role(), 'role', 'Role() returns the role value.');
  
  var sid2 = 'invalidSid';
  test.isFalse(sid.equals(sid2), 'Equals methods returns false if sid is not an instance of RoleSecurityIdentity.');
  test.isFalse(sid.equals(sid2), 'Equals methods returns false if sid is not an instance of RoleSecurityIdentity.');
  
  var sid2 = new SecurityAcl.RoleSecurityIdentity('role2');
  test.isFalse(sid.equals(sid2), 'Equals methods returns false if role of sid is different.');
  
  var sid2 = new SecurityAcl.RoleSecurityIdentity('role');
  test.isTrue(sid.equals(sid2), 'Equals methods returns true if sid is equal.');
  
  
});