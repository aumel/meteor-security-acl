

Tinytest.add('SecurityAcl - PermissionMap', function (test) {
  var permissionMap = new SecurityAcl.PermissionMap();
  
  test.equal(permissionMap.getMasks('VIEW'), [ 1, 4, 32, 64, 128 ], 'Permission VIEW correctly implemented.');
  
  test.equal(permissionMap.getMasks('EDIT'), [ 4, 32, 64, 128 ], 'Permission EDIT correctly implemented.');
  
  test.equal(permissionMap.getMasks('CREATE'), [ 2, 32, 64, 128 ], 'Permission CREATE correctly implemented.');
  
  test.equal(permissionMap.getMasks('DELETE'), [ 8, 32, 64, 128 ], 'Permission DELETE correctly implemented.');
  
  test.equal(permissionMap.getMasks('UNDELETE'), [ 16, 32, 64, 128 ], 'Permission UNDELETE correctly implemented.');
  
  test.equal(permissionMap.getMasks('OPERATOR'), [ 32, 64, 128 ], 'Permission OPERATOR correctly implemented.');
  
  test.equal(permissionMap.getMasks('MASTER'), [ 64, 128 ], 'Permission MASTER correctly implemented.');
  
  test.equal(permissionMap.getMasks('OWNER'), [ 128 ], 'Permission OWNER correctly implemented.');
  
  SecurityAclTestHelpers.cleanUpDatabase();
});