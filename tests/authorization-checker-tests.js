
"use strict";

Tinytest.add('AuthorizationChecker - setAuthenticatedUser', function (test) {

  test.throws(function () {
    SecurityAcl.AuthorizationChecker();
  }, 'Use "new" to construct a SecurityAcl.AuthorizationChecker');

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();

  test.throws(function () {
    authorizationChecker.setAuthenticatedUser(user);
  }, 'The user cannot be undefined.');

  var user = 'invalid-user';

  test.throws(function () {
    authorizationChecker.setAuthenticatedUser(user);
  }, 'The user.username cannot be undefined.');

  user = {};
  user.username = 'username';

  user = {};
  user.username = 'username';
  user.getClassName = function () {
    return 'users';
  };

  authorizationChecker.setAuthenticatedUser(user);
  test.equal(
    authorizationChecker._authenticatedUser,
    user,
    'The authenticated user is setted.');

});

Tinytest.add(
  'AuthorizationChecker - isGranted (objectAce for UserSecurityIdentity)',
  function (test) {

  SecurityAclTestHelpers.cleanUpDatabase();

  var user = {};
  user.username = 'username';
  user.getClassName = function () {
    return 'users';
  };

  // VIEW permission

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  test.isFalse(
    authorizationChecker.isGranted('VIEW', post),
    'The authenticated user cannot view the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('EDIT', post),
    'The authenticated user cannot edit the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('CREATE', post),
    'The authenticated user cannot create the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('DELETE', post),
    'The authenticated user cannot delete the specific post..');
  test.isFalse(
    authorizationChecker.isGranted('UNDELETE', post),
    'The authenticated user cannot undelete the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('OPERATOR', post),
    'The authenticated user has not OPERATOR permission for the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('MASTER', post),
    'The authenticated user has not MASTER permission for the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('OWNER', post),
    'The authenticated user has not OWNER permission for the specific post.');

  
  // add view permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('view');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(
    user.username,
    user.getClassName());
  
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isTrue(
    authorizationChecker.isGranted('VIEW', post),
    'The authenticated user can view the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('EDIT', post),
    'The authenticated user cannot edit the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('CREATE', post),
    'The authenticated user cannot create the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('DELETE', post),
    'The authenticated user cannot delete the specific post..');
  test.isFalse(
    authorizationChecker.isGranted('UNDELETE', post),
    'The authenticated user cannot undelete the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('OPERATOR', post),
    'The authenticated user has not OPERATOR permission for the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('MASTER', post),
    'The authenticated user has not MASTER permission for the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('OWNER', post),
    'The authenticated user has not OWNER permission for the specific post.');

  // EDIT permission

  SecurityAclTestHelpers.cleanUpDatabase();

  authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  post = Posts.findOne({});

  test.isFalse(
    authorizationChecker.isGranted('VIEW', post),
    'The authenticated user cannot view the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('EDIT', post),
    'The authenticated user cannot edit the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('CREATE', post),
    'The authenticated user cannot create the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('DELETE', post),
    'The authenticated user cannot delete the specific post..');
  test.isFalse(
    authorizationChecker.isGranted('UNDELETE', post),
    'The authenticated user cannot undelete the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('OPERATOR', post),
    'The authenticated user has not OPERATOR permission for the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('MASTER', post),
    'The authenticated user has not MASTER permission for the specific post.');
  test.isFalse(
    authorizationChecker.isGranted('OWNER', post),
    'The authenticated user has not OWNER permission for the specific post.');

  // add edit permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('edit');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isTrue(authorizationChecker.isGranted('VIEW', post), 'The authenticated user can view the specific post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', post), 'The authenticated user can edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The authenticated user cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The authenticated user cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The authenticated user cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The authenticated user has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The authenticated user has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The authenticated user has not OWNER permission for the specific post.');

  // CREATE permission

  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The authenticated user cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The authenticated user cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The authenticated user cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The authenticated user cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The authenticated user cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The authenticated user not has OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The authenticated user has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The authenticated user has not OWNER permission for the specific post.');

  // add create permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('create');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The authenticated user cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The authenticated user cannot edit the specific post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', post), 'The authenticated user can create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The authenticated user cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The authenticated user cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The authenticated user has OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The authenticated user has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The authenticated user has not OWNER permission for the specific post.');


  // DELETE permission

  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The authenticated user cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The authenticated user cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The authenticated user cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The authenticated user cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The authenticated user cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The authenticated user has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The authenticated user has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The authenticated user has not OWNER permission for the specific post.');

  // add delete permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('delete');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The authenticated user cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The authenticated user cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The authenticated user cannot create the specific post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', post), 'The authenticated user can delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The authenticated user cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The authenticated user has OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The authenticated user has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The authenticated user has not OWNER permission for the specific post.');

  // UNDELETE permission

  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The authenticated user cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The authenticated user cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The authenticated user cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The authenticated user cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The authenticated user cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The authenticated user has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The authenticated user has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The authenticated user has not OWNER permission for the specific post.');

  // add undelete permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('undelete');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The authenticated user cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The authenticated user cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The authenticated user cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The authenticated user cannot delete the specific post..');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', post), 'The authenticated user cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The authenticated user has OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The authenticated user has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The authenticated user has not OWNER permission for the specific post.');

  // OPERATOR permission

  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The authenticated user cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The authenticated user cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The authenticated user cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The authenticated user cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The authenticated user cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The authenticated user has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The authenticated user has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The authenticated user has not OWNER permission for the specific post.');

  // add operator permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('operator');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isTrue(authorizationChecker.isGranted('OPERATOR', post), 'The authenticated user has OPERATOR permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('VIEW', post), 'The authenticated user has VIEW permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', post), 'The authenticated user has EDIT permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', post), 'The authenticated user has CREATE permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', post), 'The authenticated user has DELETE permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', post), 'The authenticated user has UNDELETE permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The authenticated user has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The authenticated user has not OWNER permission for the specific post.');

  // MASTER permission

  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The authenticated user cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The authenticated user cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The authenticated user cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The authenticated user cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The authenticated user cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The authenticated user has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The authenticated user has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The authenticated user has not OWNER permission for the specific post.');

  // add master permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('master');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isTrue(authorizationChecker.isGranted('MASTER', post), 'The authenticated user has MASTER permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('VIEW', post), 'The authenticated user has VIEW permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', post), 'The authenticated user has EDIT permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', post), 'The authenticated user has CREATE permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', post), 'The authenticated user has DELETE permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', post), 'The authenticated user has UNDELETE permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', post), 'The authenticated user has OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The authenticated user has not OWNER permission for the specific post.');

  // OWNER permission

  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The authenticated user cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The authenticated user cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The authenticated user cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The authenticated user cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The authenticated user cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The authenticated user has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The authenticated user has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The authenticated user has not OWNER permission for the specific post.');

  // add owner permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('owner');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isTrue(authorizationChecker.isGranted('OWNER', post), 'The authenticated user has OWNER permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('VIEW', post), 'The authenticated user has VIEW permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', post), 'The authenticated user has EDIT permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', post), 'The authenticated user has CREATE permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', post), 'The authenticated user has DELETE permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', post), 'The authenticated user has UNDELETE permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', post), 'The authenticated user has OPERATOR permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('MASTER', post), 'The authenticated user has MASTER permission for the specific post.');

});

Tinytest.add('AuthorizationChecker - isGranted (objectFieldAce for UserSecurityIdentity)', function (test) {

  SecurityAclTestHelpers.cleanUpDatabase();

  var user = {};
  user.username = 'username';
  user.getClassName = function () {
    return 'users';
  };

  // VIEW permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of the post.');

  
  // add view permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-field-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('view');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertObjectFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The authenticated user can view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of the post.');

  // we don't have access to the other field 'text'
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field textd of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field text of the post.');

  // EDIT permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of the post.');

  
  // add edit permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-field-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('edit');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertObjectFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The authenticated user can view the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', object), 'The authenticated user can edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of the post.');

  // we don't have access to the other field 'text'
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field textd of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field text of the post.');

  // CREATE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of the post.');

  
  // add create permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-field-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('create');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertObjectFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', object), 'The authenticated user can create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of the post.');

  // we don't have access to the other field 'text'
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field textd of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field text of the post.');

  // DELETE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of the post.');

  
  // add delete permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-field-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('delete');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertObjectFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', object), 'The authenticated user can delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of the post.');

  // we don't have access to the other field 'text'
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field textd of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field text of the post.');

  // UNDELETE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of the post.');

  
  // add undelete permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-field-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('undelete');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertObjectFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user can view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user can undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of the post.');

  // we don't have access to the other field 'text'
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field textd of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field text of the post.');

  // OPERATOR permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of the post.');

  
  // add operator permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-field-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('operator');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertObjectFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The authenticated user can view the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', object), 'The authenticated user can edit the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', object), 'The authenticated user can create the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', object), 'The authenticated user can delete the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user can undelete the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of the post.');

  // we don't have access to the other field 'text'
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field textd of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field text of the post.');

  // MASTER permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of the post.');

  
  // add master permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-field-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('master');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertObjectFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The authenticated user can view the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', object), 'The authenticated user can edit the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', object), 'The authenticated user can create the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', object), 'The authenticated user can delete the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user can undelete the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has OPERATOR permission for the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of the post.');

  // we don't have access to the other field 'text'
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field textd of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field text of the post.');

  // OWNER permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of the post.');

  // add owner permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-field-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('owner');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertObjectFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The authenticated user can view the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', object), 'The authenticated user can edit the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', object), 'The authenticated user can create the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', object), 'The authenticated user can delete the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user can undelete the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has OPERATOR permission for the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has MASTER permission for the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has OWNER permission for the field _id of the post.');

  // we don't have access to the other field 'text'
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field textd of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field text of the post.');

  
});


Tinytest.add('AuthorizationChecker - isGranted (objectAce for RoleSecurityIdentity)', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var user = {};
  user.username = 'username';
  user.roles = ['member'];
  user.getClassName = function () {
    return 'users';
  };

  // VIEW permission

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The user with role member cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The user with role member cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The user with role member cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The user with role member cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The user with role member cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The user with role member has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The user with role member has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The user with role member has not OWNER permission for the specific post.');

  // add view permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('view');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);
  
  test.isTrue(authorizationChecker.isGranted('VIEW', post), 'The user with role member can view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The user with role member cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The user with role member cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The user with role member cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The user with role member cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The user with role member has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The user with role member has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The user with role member has not OWNER permission for the specific post.');

  // EDIT permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The user with role member cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The user with role member cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The user with role member cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The user with role member cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The user with role member cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The user with role member has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The user with role member has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The user with role member has not OWNER permission for the specific post.');

  
  // add edit permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('edit');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);
  
  test.isTrue(authorizationChecker.isGranted('VIEW', post), 'The user with role member can view the specific post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', post), 'The user with role member can edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The user with role member cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The user with role member cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The user with role member cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The user with role member has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The user with role member has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The user with role member has not OWNER permission for the specific post.');

  // CREATE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The user with role member cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The user with role member cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The user with role member cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The user with role member cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The user with role member cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The user with role member has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The user with role member has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The user with role member has not OWNER permission for the specific post.');

  
  // add create permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('create');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);
  
  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The user with role member cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The user with role member cannot edit the specific post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', post), 'The user with role member can create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The user with role member cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The user with role member cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The user with role member has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The user with role member has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The user with role member has not OWNER permission for the specific post.');

  // DELETE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The user with role member cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The user with role member cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The user with role member cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The user with role member cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The user with role member cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The user with role member has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The user with role member has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The user with role member has not OWNER permission for the specific post.');

  
  // add delete permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('delete');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);
  
  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The user with role member cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The user with role member cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The user with role member cannot create the specific post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', post), 'The user with role member can delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The user with role member cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The user with role member has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The user with role member has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The user with role member has not OWNER permission for the specific post.');

  // UNDELETE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The user with role member cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The user with role member cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The user with role member cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The user with role member cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The user with role member cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The user with role member has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The user with role member has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The user with role member has not OWNER permission for the specific post.');

  
  // add undelete permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('undelete');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);
  
  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The user with role member cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The user with role member cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The user with role member cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The user with role member cannot delete the specific post..');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', post), 'The user with role member can undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The user with role member has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The user with role member has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The user with role member has not OWNER permission for the specific post.');

  // OPERATOR permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The user with role member cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The user with role member cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The user with role member cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The user with role member cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The user with role member cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The user with role member has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The user with role member has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The user with role member has not OWNER permission for the specific post.');

  
  // add operator permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('operator');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);
  
  test.isTrue(authorizationChecker.isGranted('VIEW', post), 'The user with role member can view the specific post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', post), 'The user with role member can edit the specific post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', post), 'The user with role member can create the specific post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', post), 'The user with role member can delete the specific post..');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', post), 'The user with role member can undelete the specific post.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', post), 'The user with role member has OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The user with role member has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The user with role member has not OWNER permission for the specific post.');

  // MASTER permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The user with role member cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The user with role member cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The user with role member cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The user with role member cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The user with role member cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The user with role member has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The user with role member has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The user with role member has not OWNER permission for the specific post.');

  
  // add master permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('master');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);
  
  test.isTrue(authorizationChecker.isGranted('VIEW', post), 'The user with role member can view the specific post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', post), 'The user with role member can edit the specific post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', post), 'The user with role member can create the specific post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', post), 'The user with role member can delete the specific post..');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', post), 'The user with role member can undelete the specific post.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', post), 'The user with role member has OPERATOR permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('MASTER', post), 'The user with role member has MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The user with role member has not OWNER permission for the specific post.');

  // OWNER permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The user with role member cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The user with role member cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The user with role member cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The user with role member cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The user with role member cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The user with role member has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The user with role member has MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The user with role member has not OWNER permission for the specific post.');

  
  // add owner permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('owner');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);
  
  test.isTrue(authorizationChecker.isGranted('VIEW', post), 'The user with role member can view the specific post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', post), 'The user with role member can edit the specific post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', post), 'The user with role member can create the specific post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', post), 'The user with role member can delete the specific post..');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', post), 'The user with role member can undelete the specific post.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', post), 'The user with role member has OPERATOR permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('MASTER', post), 'The user with role member has MASTER permission for the specific post.');
  test.isTrue(authorizationChecker.isGranted('OWNER', post), 'The user with role member has OWNER permission for the specific post.');

  
  
});

Tinytest.add('AuthorizationChecker - isGranted (objectFieldAce for RoleSecurityIdentity)', function (test) {

  SecurityAclTestHelpers.cleanUpDatabase();

  var user = {};
  user.username = 'username';
  user.roles = ['member'];
  user.getClassName = function () {
    return 'users';
  };

  // VIEW permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of the post.');

  
  // add view permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-field-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('view');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The user with role member can view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of the post.');

  // we don't have access to the other field 'text'
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field textd of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field text of the post.');

  // EDIT permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of the post.');

  
  // add edit permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-field-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('edit');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The user with role member can view the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', object), 'The user with role member can edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of the post.');

  // we don't have access to the other field 'text'
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field textd of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field text of the post.');

  // CREATE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of the post.');

  
  // add create permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-field-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('create');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', object), 'The user with role member can create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of the post.');

  // we don't have access to the other field 'text'
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field textd of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field text of the post.');

  // DELETE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of the post.');

  
  // add delete permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-field-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('delete');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', object), 'The user with role member can delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of the post.');

  // we don't have access to the other field 'text'
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field textd of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field text of the post.');

  // UNDELETE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of the post.');

  
  // add undelete permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-field-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('undelete');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member can undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of the post.');

  // we don't have access to the other field 'text'
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field textd of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field text of the post.');

  // OPERATOR permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of the post.');

  
  // add operator permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-field-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('operator');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The user with role member can view the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', object), 'The user with role member can edit the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', object), 'The user with role member can create the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', object), 'The user with role member can delete the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member can undelete the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of the post.');

  // we don't have access to the other field 'text'
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field textd of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field text of the post.');

  // MASTER permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of the post.');

  
  // add master permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-field-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('master');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The user with role member can view the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', object), 'The user with role member can edit the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', object), 'The user with role member can create the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', object), 'The user with role member can delete the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member can undelete the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has OPERATOR permission for the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('MASTER', object), 'The user with role member has MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of the post.');

  // we don't have access to the other field 'text'
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field textd of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field text of the post.');

  // OWNER permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of the post.');

  
  // add owner permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-field-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('owner');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The user with role member can view the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', object), 'The user with role member can edit the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', object), 'The user with role member can create the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', object), 'The user with role member can delete the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member can undelete the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has OPERATOR permission for the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('MASTER', object), 'The user with role member has MASTER permission for the field _id of the post.');
  test.isTrue(authorizationChecker.isGranted('OWNER', object), 'The user with role member has OWNER permission for the field _id of the post.');

  // we don't have access to the other field 'text'
  var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
  var object = new SecurityAcl.FieldVote(oid, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field textd of the post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field text of the post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field text of the post.');

});

Tinytest.add('AuthorizationChecker - isGranted (object argument for classAce)', function (test) {

  var user = {};
  user.username = 'username';
  user.getClassName = function () {
    return 'users';
  };

  // 'isGranted' method in a class-ace context,
  // uses a SecurityAcl.ObjectIdentity or
  // the unique className string as object argument

  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  // add VIEW permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('view');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  // classIdentity is a SecurityAcl.ObjectIdentity
  test.isTrue(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user can view a post.');

  // or use the unique className string
  test.isTrue(authorizationChecker.isGranted('VIEW', 'posts'), 'The authenticated user can view a post.');

});


Tinytest.add('AuthorizationChecker - isGranted (classAce for UserSecurityIdentity)', function (test) {

  var user = {};
  user.username = 'username';
  user.getClassName = function () {
    return 'users';
  };

  // VIEW permission

  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user cannot view a post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The authenticated user cannot edit a post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The authenticated user cannot create a post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The authenticated user cannot delete a post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The authenticated user cannot undelete a post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The authenticated user has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The authenticated user has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The authenticated user has not OWNER permission for a post object.');

  // add VIEW permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('view');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isTrue(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user can view a post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The authenticated user cannot edit a post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The authenticated user cannot create a post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The authenticated user cannot delete a post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The authenticated user cannot undelete a post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The authenticated user has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The authenticated user has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The authenticated user has not OWNER permission for a post object.');

  // EDIT permission

  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user cannot view a post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The authenticated user cannot edit a post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The authenticated user cannot create a post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The authenticated user cannot delete a post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The authenticated user cannot undelete a post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The authenticated user has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The authenticated user has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The authenticated user has not OWNER permission for a post object.');

  // add EDIT permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('edit');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isTrue(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user can view a post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', classIdentity), 'The authenticated user can edit a post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The authenticated user cannot create a post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The authenticated user cannot delete a post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The authenticated user cannot undelete a post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The authenticated user has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The authenticated user has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The authenticated user has not OWNER permission for a post object.');


  // CREATE permission

  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user cannot view a post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The authenticated user cannot edit a post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The authenticated user cannot create a post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The authenticated user cannot delete a post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The authenticated user cannot undelete a post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The authenticated user has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The authenticated user has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The authenticated user has not OWNER permission for a post object.');

  // add CREATE permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('create');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user cannot view a post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The authenticated user cannot edit a post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', classIdentity), 'The authenticated user can create a post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The authenticated user cannot delete a post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The authenticated user cannot undelete a post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The authenticated user has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The authenticated user has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The authenticated user has not OWNER permission for a post object.');


  // DELETE permission

  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user cannot view a post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The authenticated user cannot edit a post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The authenticated user cannot create a post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The authenticated user cannot delete a post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The authenticated user cannot undelete a post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The authenticated user has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The authenticated user has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The authenticated user has not OWNER permission for a post object.');

  // add DELETE permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('delete');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user cannot view a post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The authenticated user cannot edit a post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The authenticated user cannot create a post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', classIdentity), 'The authenticated user can delete a post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The authenticated user cannot undelete a post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The authenticated user has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The authenticated user has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The authenticated user has not OWNER permission for a post object.');

  // UNDELETE permission

  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user cannot view a post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The authenticated user cannot edit a post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The authenticated user cannot create a post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The authenticated user cannot delete a post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The authenticated user cannot undelete a post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The authenticated user has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The authenticated user has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The authenticated user has not OWNER permission for a post object.');

  // add UNDELETE permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('undelete');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user cannot view a post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The authenticated user cannot edit a post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The authenticated user cannot create a post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The authenticated user cannot delete a post.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The authenticated user can undelete a post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The authenticated user has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The authenticated user has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The authenticated user has not OWNER permission for a post object.');

  // OPERATOR permission

  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user cannot view a post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The authenticated user cannot edit a post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The authenticated user cannot create a post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The authenticated user cannot delete a post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The authenticated user cannot undelete a post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The authenticated user has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The authenticated user has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The authenticated user has not OWNER permission for a post object.');

  // add OPERATOR permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('operator');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isTrue(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user can view a post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', classIdentity), 'The authenticated user can edit a post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', classIdentity), 'The authenticated user can create a post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', classIdentity), 'The authenticated user can delete a post.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The authenticated user can undelete a post.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The authenticated user has OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The authenticated user has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The authenticated user has not OWNER permission for a post object.');

  // MASTER permission

  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user cannot view a post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The authenticated user cannot edit a post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The authenticated user cannot create a post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The authenticated user cannot delete a post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The authenticated user cannot undelete a post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The authenticated user has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The authenticated user has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The authenticated user has not OWNER permission for a post object.');

  // add MASTER permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('master');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isTrue(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user can view a post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', classIdentity), 'The authenticated user can edit a post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', classIdentity), 'The authenticated user can create a post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', classIdentity), 'The authenticated user can delete a post.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The authenticated user can undelete a post.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The authenticated user has OPERATOR permission for a post object.');
  test.isTrue(authorizationChecker.isGranted('MASTER', classIdentity), 'The authenticated user has MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The authenticated user has not OWNER permission for a post object.');

  // OWNER permission

  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user cannot view a post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The authenticated user cannot edit a post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The authenticated user cannot create a post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The authenticated user cannot delete a post.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The authenticated user cannot undelete a post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The authenticated user has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The authenticated user has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The authenticated user has not OWNER permission for a post object.');

  // add OWNER permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('owner');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isTrue(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user can view a post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', classIdentity), 'The authenticated user can edit a post.');
  test.isTrue(authorizationChecker.isGranted('CREATE', classIdentity), 'The authenticated user can create a post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', classIdentity), 'The authenticated user can delete a post.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The authenticated user can undelete a post.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The authenticated user has OPERATOR permission for a post object.');
  test.isTrue(authorizationChecker.isGranted('MASTER', classIdentity), 'The authenticated user has MASTER permission for a post object.');
  test.isTrue(authorizationChecker.isGranted('OWNER', classIdentity), 'The authenticated user has OWNER permission for a post object.');


});

Tinytest.add('AuthorizationChecker - isGranted (classFieldAce for UserSecurityIdentity)', function (test) {

  SecurityAclTestHelpers.cleanUpDatabase();

  var user = {};
  user.username = 'username';
  user.getClassName = function () {
    return 'users';
  };

  // VIEW permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of a post object.');

  // add view permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-field-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('view');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The authenticated user can view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of a post object.');

  // we don't have access to the other field 'text'
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field textd of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field text of a post object.');

  // EDIT permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of a post object.');

  // add edit permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-field-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('edit');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The authenticated user can view the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('EDIT', object), 'The authenticated user can edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of a post object.');

  // we don't have access to the other field 'text'
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field textd of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field text of a post object.');

  // CREATE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of a post object.');

  // add create permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-field-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('create');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('CREATE', object), 'The authenticated user can create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of a post object.');

  // we don't have access to the other field 'text'
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field textd of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field text of a post object.');

  // DELETE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of a post object.');

  // add delete permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-field-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('delete');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('DELETE', object), 'The authenticated user can delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of a post object.');

  // we don't have access to the other field 'text'
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field textd of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field text of a post object.');

  // UNDELETE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of a post object.');

  // add undelete permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-field-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('undelete');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user can undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of a post object.');

  // we don't have access to the other field 'text'
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field textd of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field text of a post object.');

  // OPERATOR permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of a post object.');

  // add operator permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-field-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('operator');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The authenticated user can view the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('EDIT', object), 'The authenticated user can edit the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('CREATE', object), 'The authenticated user can create the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('DELETE', object), 'The authenticated user can delete the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user can undelete the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of a post object.');

  // we don't have access to the other field 'text'
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field textd of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field text of a post object.');

  // MASTER permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of a post object.');

  // add master permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-field-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('master');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The authenticated user can view the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('EDIT', object), 'The authenticated user can edit the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('CREATE', object), 'The authenticated user can create the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('DELETE', object), 'The authenticated user can delete the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user can undelete the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has OPERATOR permission for the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of a post object.');

  // we don't have access to the other field 'text'
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field textd of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field text of a post object.');

  // OWNER permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field _id of a post object.');

  // add owner permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-field-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('owner');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The authenticated user can view the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('EDIT', object), 'The authenticated user can edit the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('CREATE', object), 'The authenticated user can create the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('DELETE', object), 'The authenticated user can delete the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user can undelete the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has OPERATOR permission for the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has MASTER permission for the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has OWNER permission for the field _id of a post object.');

  // we don't have access to the other field 'text'
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The authenticated user cannot view the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The authenticated user cannot edit the field textd of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The authenticated user cannot create the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The authenticated user cannot delete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The authenticated user cannot undelete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The authenticated user has not OPERATOR permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The authenticated user has not MASTER permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The authenticated user has not OWNER permission for the field text of a post object.');

});


Tinytest.add('AuthorizationChecker - isGranted (classAce for RoleSecurityIdentity)', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var user = {};
  user.username = 'username';
  user.roles = ['member'];
  user.getClassName = function () {
    return 'users';
  };

  // VIEW permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The user with role member cannot view a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The user with role member cannot edit  a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The user with role member cannot create a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The user with role member cannot delete a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The user with role member cannot undelete a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The user with role member has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The user with role member has not MASTER permission for the a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The user with role member has not OWNER permission for a post object.');

  // add view permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('view');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);
  
  test.isTrue(authorizationChecker.isGranted('VIEW', classIdentity), 'The user with role member can view a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The user with role member cannot edit a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The user with role member cannot create a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The user with role member cannot delete a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The user with role member cannot undelete a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The user with role member has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The user with role member has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The user with role member has not OWNER permission for a post object.');

  // EDIT permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The user with role member cannot view a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The user with role member cannot edit  a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The user with role member cannot create a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The user with role member cannot delete a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The user with role member cannot undelete a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The user with role member has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The user with role member has not MASTER permission for the a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The user with role member has not OWNER permission for a post object.');

  // add edit permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('edit');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);
  
  test.isTrue(authorizationChecker.isGranted('VIEW', classIdentity), 'The user with role member can view a post object.');
  test.isTrue(authorizationChecker.isGranted('EDIT', classIdentity), 'The user with role member can edit a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The user with role member cannot create a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The user with role member cannot delete a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The user with role member cannot undelete a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The user with role member has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The user with role member has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The user with role member has not OWNER permission for a post object.');

  // CREATE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The user with role member cannot view a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The user with role member cannot edit  a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The user with role member cannot create a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The user with role member cannot delete a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The user with role member cannot undelete a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The user with role member has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The user with role member has not MASTER permission for the a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The user with role member has not OWNER permission for a post object.');

  // add create permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('create');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);
  
  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The user with role member cannot view a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The user with role member cannot edit a post object.');
  test.isTrue(authorizationChecker.isGranted('CREATE', classIdentity), 'The user with role member can create a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The user with role member cannot delete a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The user with role member cannot undelete a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The user with role member has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The user with role member has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The user with role member has not OWNER permission for a post object.');

  // DELETE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The user with role member cannot view a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The user with role member cannot edit  a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The user with role member cannot create a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The user with role member cannot delete a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The user with role member cannot undelete a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The user with role member has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The user with role member has not MASTER permission for the a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The user with role member has not OWNER permission for a post object.');

  // add delete permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('delete');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);
  
  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The user with role member cannot view a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The user with role member cannot edit a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The user with role member cannot create a post object.');
  test.isTrue(authorizationChecker.isGranted('DELETE', classIdentity), 'The user with role member can  delete a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The user with role member cannot undelete a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The user with role member has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The user with role member has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The user with role member has not OWNER permission for a post object.');

  // UNDELETE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The user with role member cannot view a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The user with role member cannot edit  a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The user with role member cannot create a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The user with role member cannot delete a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The user with role member cannot undelete a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The user with role member has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The user with role member has not MASTER permission for the a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The user with role member has not OWNER permission for a post object.');

  // add undelete permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('undelete');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);
  
  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The user with role member cannot view a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The user with role member cannot edit a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The user with role member cannot create a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The user with role member cannot delete a post object.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The user with role member can undelete a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The user with role member has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The user with role member has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The user with role member has not OWNER permission for a post object.');

  // OPERATOR permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The user with role member cannot view a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The user with role member cannot edit  a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The user with role member cannot create a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The user with role member cannot delete a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The user with role member cannot undelete a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The user with role member has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The user with role member has not MASTER permission for the a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The user with role member has not OWNER permission for a post object.');

  // add operator permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('operator');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);
  
  test.isTrue(authorizationChecker.isGranted('VIEW', classIdentity), 'The user with role member can view a post object.');
  test.isTrue(authorizationChecker.isGranted('EDIT', classIdentity), 'The user with role member can edit a post object.');
  test.isTrue(authorizationChecker.isGranted('CREATE', classIdentity), 'The user with role member can create a post object.');
  test.isTrue(authorizationChecker.isGranted('DELETE', classIdentity), 'The user with role member can delete a post object.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The user with role member can undelete a post object.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The user with role member has OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The user with role member has not MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The user with role member has not OWNER permission for a post object.');

  // MASTER permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The user with role member cannot view a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The user with role member cannot edit  a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The user with role member cannot create a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The user with role member cannot delete a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The user with role member cannot undelete a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The user with role member has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The user with role member has not MASTER permission for the a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The user with role member has not OWNER permission for a post object.');

  // add master permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('master');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);
  
  test.isTrue(authorizationChecker.isGranted('VIEW', classIdentity), 'The user with role member can view a post object.');
  test.isTrue(authorizationChecker.isGranted('EDIT', classIdentity), 'The user with role member can edit a post object.');
  test.isTrue(authorizationChecker.isGranted('CREATE', classIdentity), 'The user with role member can create a post object.');
  test.isTrue(authorizationChecker.isGranted('DELETE', classIdentity), 'The user with role member can delete a post object.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The user with role member can undelete a post object.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The user with role member has OPERATOR permission for a post object.');
  test.isTrue(authorizationChecker.isGranted('MASTER', classIdentity), 'The user with role member has MASTER permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The user with role member has not OWNER permission for a post object.');

  // OWNER permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  test.isFalse(authorizationChecker.isGranted('VIEW', classIdentity), 'The user with role member cannot view a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', classIdentity), 'The user with role member cannot edit  a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', classIdentity), 'The user with role member cannot create a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', classIdentity), 'The user with role member cannot delete a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The user with role member cannot undelete a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The user with role member has not OPERATOR permission for a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', classIdentity), 'The user with role member has not MASTER permission for the a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', classIdentity), 'The user with role member has not OWNER permission for a post object.');

  // add owner permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('owner');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);
  
  test.isTrue(authorizationChecker.isGranted('VIEW', classIdentity), 'The user with role member can view a post object.');
  test.isTrue(authorizationChecker.isGranted('EDIT', classIdentity), 'The user with role member can edit a post object.');
  test.isTrue(authorizationChecker.isGranted('CREATE', classIdentity), 'The user with role member can create a post object.');
  test.isTrue(authorizationChecker.isGranted('DELETE', classIdentity), 'The user with role member can delete a post object.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', classIdentity), 'The user with role member can undelete a post object.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', classIdentity), 'The user with role member has OPERATOR permission for a post object.');
  test.isTrue(authorizationChecker.isGranted('MASTER', classIdentity), 'The user with role member has MASTER permission for a post object.');
  test.isTrue(authorizationChecker.isGranted('OWNER', classIdentity), 'The user with role member has OWNER permission for a post object.');

  
});

Tinytest.add('AuthorizationChecker - isGranted (classFieldAce for RoleSecurityIdentity)', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var user = {};
  user.username = 'username';
  user.roles = ['member'];
  user.getClassName = function () {
    return 'users';
  };

  // VIEW permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of a post object');

  
  // add view permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-field-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('view');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertClassFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The user with role member can view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of a post object.');

  // we don't have access to the other field 'text'
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field textd of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field text of a post object.');

  // EDIT permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of a post object.');

  
  // add edit permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-field-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('edit');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertClassFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The user with role member can view the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('EDIT', object), 'The user with role member can edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of a post object.');

  // we don't have access to the other field 'text'
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field textd of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field text of a post object.');

  // CREATE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of a post object.');

  
  // add create permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-field-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('create');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertClassFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('CREATE', object), 'The user with role member can create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of a post object.');

  // we don't have access to the other field 'text'
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field textd of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field text of a post object.');

  // DELETE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of a post object.');

  
  // add delete permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-field-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('delete');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertClassFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('DELETE', object), 'The user with role member can delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of a post object.');

  // we don't have access to the other field 'text'
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field textd of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field text of a post object.');

  // UNDELETE permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of a post object.');

  
  // add undelete permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-field-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('undelete');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertClassFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member can undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of a post object.');

  // we don't have access to the other field 'text'
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field textd of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field text of a post object.');

  // OPERATOR permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of a post object.');

  
  // add operator permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-field-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('operator');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertClassFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The user with role member can view the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('EDIT', object), 'The user with role member can edit the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('CREATE', object), 'The user with role member can create the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('DELETE', object), 'The user with role member can delete the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member can undelete the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of a post object.');

  // we don't have access to the other field 'text'
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field textd of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field text of a post object.');

  // MASTER permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of a post object.');

  
  // add master permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-field-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('master');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertClassFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The user with role member can view the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('EDIT', object), 'The user with role member can edit the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('CREATE', object), 'The user with role member can create the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('DELETE', object), 'The user with role member can delete the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member can undelete the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has OPERATOR permission for the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('MASTER', object), 'The user with role member has MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of a post object.');

  // we don't have access to the other field 'text'
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field textd of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field text of a post object.');

  // OWNER permission
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field _id of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field _id of a post object.');

  
  // add owner permission for _id field
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-field-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('owner');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertClassFieldAce('_id', securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, '_id');

  test.isTrue(authorizationChecker.isGranted('VIEW', object), 'The user with role member can view the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('EDIT', object), 'The user with role member can edit the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('CREATE', object), 'The user with role member can create the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('DELETE', object), 'The user with role member can delete the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member can undelete the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has OPERATOR permission for the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('MASTER', object), 'The user with role member has MASTER permission for the field _id of a post object.');
  test.isTrue(authorizationChecker.isGranted('OWNER', object), 'The user with role member has OWNER permission for the field _id of a post object.');

  // we don't have access to the other field 'text'
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');
  var object = new SecurityAcl.FieldVote(classIdentity, 'text');
  
  test.isFalse(authorizationChecker.isGranted('VIEW', object), 'The user with role member cannot view the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('EDIT', object), 'The user with role member cannot edit the field textd of a post object.');
  test.isFalse(authorizationChecker.isGranted('CREATE', object), 'The user with role member cannot create the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('DELETE', object), 'The user with role member cannot delete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', object), 'The user with role member cannot undelete the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', object), 'The user with role member has not OPERATOR permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('MASTER', object), 'The user with role member has not MASTER permission for the field text of a post object.');
  test.isFalse(authorizationChecker.isGranted('OWNER', object), 'The user with role member has not OWNER permission for the field text of a post object.');

});



Tinytest.add('AuthorizationChecker - isGranted (inheritance)', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var user = {};
  user.username = 'username';
  user.roles = ['member'];
  user.getClassName = function () {
    return 'users';
  };
  
  // EDIT permission

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixtures
  Posts.insert({
    text: 'test inheritance'
  });
  var post = Posts.findOne({});
  
  Comments.insert({
    text: 'test inheritance'
  });
  var comment = Comments.findOne({});

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The authenticated user cannot view the specific post.');
  test.isFalse(authorizationChecker.isGranted('EDIT', post), 'The authenticated user cannot edit the specific post.');
  test.isFalse(authorizationChecker.isGranted('CREATE', post), 'The authenticated user cannot create the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The authenticated user cannot delete the specific post..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', post), 'The authenticated user cannot undelete the specific post.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', post), 'The authenticated user has not OPERATOR permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('MASTER', post), 'The authenticated user has not MASTER permission for the specific post.');
  test.isFalse(authorizationChecker.isGranted('OWNER', post), 'The authenticated user has not OWNER permission for the specific post.');

  test.isFalse(authorizationChecker.isGranted('VIEW', comment), 'The authenticated user cannot view the specific comment.');
  test.isFalse(authorizationChecker.isGranted('EDIT', comment), 'The authenticated user cannot edit the specific comment.');
  test.isFalse(authorizationChecker.isGranted('CREATE', comment), 'The authenticated user cannot create the specific comment.');
  test.isFalse(authorizationChecker.isGranted('DELETE', comment), 'The authenticated user cannot delete the specific comment..');
  test.isFalse(authorizationChecker.isGranted('UNDELETE', comment), 'The authenticated user cannot undelete the specific comment.');
  test.isFalse(authorizationChecker.isGranted('OPERATOR', comment), 'The authenticated user has not OPERATOR permission for the specific comment.');
  test.isFalse(authorizationChecker.isGranted('MASTER', comment), 'The authenticated user has not MASTER permission for the specific comment.');
  test.isFalse(authorizationChecker.isGranted('OWNER', comment), 'The authenticated user has not OWNER permission for the specific comment.');

  
  // add edit permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var aclPost = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('edit');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  aclPost.insertObjectAce(securityIdentity, builder.getMask());

  aclService.updateAcl(aclPost);

  test.isTrue(authorizationChecker.isGranted('VIEW', post), 'The authenticated user can view the specific post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', post), 'The authenticated user can view the specific post.');
  
  // create ACL for comment
  var aclComment = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(comment));
  
  // aclComment inherits from aclPost
  aclComment.setParentAcl(aclPost);
  aclService.updateAcl(aclComment);
  
  test.isTrue(authorizationChecker.isGranted('VIEW', comment), 'The authenticated user can view the specific post.');
  test.isTrue(authorizationChecker.isGranted('EDIT', comment), 'The authenticated user can view the specific post.');
  
  
});

Tinytest.add('AuthorizationChecker - isGranted (class-scope)', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var user = {};
  user.username = 'username';
  user.getClassName = function () {
    return 'users';
  };
  
  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  
  // data-fixtures
  Posts.insert({
    text: 'test inheritance'
  });
  var post = Posts.findOne({});
  
  // add VIEW permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('VIEW');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassAce(securityIdentity, builder.getMask());
  
  aclService.updateAcl(acl);
  
  
  var aclService = new SecurityAcl.Service();
  var objectIdentity = new SecurityAcl.objectIdentityFromDomainObject(post);
  
  var acl = aclService.createAcl(objectIdentity);
  
  aclService.updateAcl(acl);
  
  test.isTrue(authorizationChecker.isGranted('VIEW', post), 'The authenticated user can view the specific post.');
  test.isFalse(authorizationChecker.isGranted('DELETE', post), 'The authenticated user can delete the specific post.');
  
  // add DELETE permission
  // creating an ACL and adding an ACE
  
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('DELETE');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  acl.insertClassAce(securityIdentity, builder.getMask());
  
  aclService.updateAcl(acl);
  
  test.isTrue(authorizationChecker.isGranted('VIEW', post), 'The authenticated user can view the specific post.');
  test.isTrue(authorizationChecker.isGranted('DELETE', post), 'The authenticated user can delete the specific post.');
  
  
});


Tinytest.add('AuthorizationChecker - isGranted (ACL updated)', function (test) {
  
  // authorizationChecker.isGranted must have always
  // the last updated ACL from database.
  
  SecurityAclTestHelpers.cleanUpDatabase();

  var user = {};
  user.username = 'username';
  user.roles = ['member'];
  user.getClassName = function () {
    return 'users';
  };

  // VIEW permission

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The authenticated user cannot view the specific post.');

  // add view permission for member role
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // object-scope
  var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('view');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('moderator');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  // the ACL has one ACE.
  aclService.updateAcl(acl);
  
  test.isFalse(authorizationChecker.isGranted('VIEW', post), 'The authenticated user with member role cannot view the specific post.');
  
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('view');

  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('member');
  acl.insertObjectAce(securityIdentity, builder.getMask());

  // the ACL has now two ACES.
  aclService.updateAcl(acl);
  
  // authorizationChecker.isGranted has the updated ACL
  test.isTrue(authorizationChecker.isGranted('VIEW', post), 'The authenticated user with member role can view the specific post.');
  
});

Tinytest.add('AuthorizationChecker - isGranted (RoleSecurityIdentity and groups)', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var user = {};
  user.username = 'username';
  user.roles = {
    'posts': ['moderator', 'reviewer'],
    'tech-blog': ['moderator']
  };
  user.getClassName = function () {
    return 'users';
  };
  
  // creating an ACL with a class identity.
  var aclService = new SecurityAcl.Service();
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'comments'));

  // defining the role security identity for an object literal
  var securityIdentity = new SecurityAcl.RoleSecurityIdentity('tech-blog-moderator');

  // you use a builder for the permission mask
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('EDIT');

  // grant operator access with classAce
  acl.insertClassAce(securityIdentity, builder.getMask());
  aclService.updateAcl(acl);
  
  // checking access
  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);
  
  // class identity (or domain object identity)
  var commentsIdentity = new SecurityAcl.ObjectIdentity('class', 'comments');
  
  test.isTrue(authorizationChecker.isGranted('EDIT', commentsIdentity), 'The authenticated user can edit a comment.');

});

Tinytest.add('AuthorizationChecker - isGranted (support ES6)', function (test) {

  // ES2015 (ES6) class
  class TestUser {
    constructor() {
      this.username = 'new-username';
    }
  }

  var user = new TestUser();

  SecurityAclTestHelpers.cleanUpDatabase();

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();

  authorizationChecker.setAuthenticatedUser(user);
  var classIdentity = new SecurityAcl.ObjectIdentity('class', 'posts');

  // add VIEW permission
  // creating an ACL and adding an ACE
  var aclService = new SecurityAcl.Service();

  // class-ace
  var acl = aclService.createAcl(new SecurityAcl.ObjectIdentity('class', 'posts'));
  var builder = new SecurityAcl.MaskBuilder();
  builder.add('view');

  var securityIdentity = new SecurityAcl.UserSecurityIdentity(user.username, user.constructor.name);
  acl.insertClassAce(securityIdentity, builder.getMask());

  aclService.updateAcl(acl);

  test.isTrue(authorizationChecker.isGranted('VIEW', classIdentity), 'The authenticated user can view a post.');

});







