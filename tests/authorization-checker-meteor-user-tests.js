

if (Meteor.isServer) {
  
  Meteor.publish('posts', function() {
      return Posts.find({});
  });
  
  SecurityAclTestHelpers.cleanUpDatabase();
  Meteor.users.remove({});
  
  Meteor.methods({
    viewPermissionObjectAce: function () {
      // check user logged in
      if (! Meteor.userId()) {
        return false;
      }
      
      // add VIEW permission
      
      // data-fixture
      SecurityAclTestHelpers.cleanUpDatabase();
      
      Posts.insert({
        text: 'view permission'
      });
      var post = Posts.findOne({ text: 'view permission'});
      
      // Creating an ACL and Adding an ACE
      var aclService = new SecurityAcl.Service();
      
      // object-scope
      var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
      var builder = new SecurityAcl.MaskBuilder();
      builder.add('view');
      
      var securityIdentity = SecurityAcl.userSecurityIdentityFromAccount(Meteor.user());
      acl.insertObjectAce(securityIdentity, builder.getMask());
      
      aclService.updateAcl(acl);
      
      // check VIEW permission
      var authorizationChecker = new SecurityAcl.AuthorizationChecker();
      
      if (false === authorizationChecker.isGranted('VIEW', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('EDIT', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('CREATE', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('DELETE', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('UNDELETE', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OPERATOR', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('MASTER', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OWNER', post)) {
        return false;
      }
      
      return true;
    },
    editPermissionObjectAce: function () {
      // check user logged in
      if (! Meteor.userId()) {
        return false;
      }
      
      // add EDIT permission
      
      // data-fixture
      SecurityAclTestHelpers.cleanUpDatabase();
      
      Posts.insert({
        text: 'edit permission'
      });
      var post = Posts.findOne({ text: 'edit permission'});
      
      // Creating an ACL and Adding an ACE
      var aclService = new SecurityAcl.Service();
      
      // object-scope
      var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
      var builder = new SecurityAcl.MaskBuilder();
      builder.add('edit');
      
      var securityIdentity = SecurityAcl.userSecurityIdentityFromAccount(Meteor.user());
      acl.insertObjectAce(securityIdentity, builder.getMask());
      
      aclService.updateAcl(acl);
      
      // check EDIT permission
      var authorizationChecker = new SecurityAcl.AuthorizationChecker();
      
      if (false === authorizationChecker.isGranted('VIEW', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('EDIT', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('CREATE', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('DELETE', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('UNDELETE', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OPERATOR', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('MASTER', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OWNER', post)) {
        return false;
      }
      
      return true;
    },
    createPermissionObjectAce: function () {
      // check user logged in
      if (! Meteor.userId()) {
        return false;
      }
      
      // add CREATE permission
      
      // data-fixture
      SecurityAclTestHelpers.cleanUpDatabase();
      
      Posts.insert({
        text: 'create permission'
      });
      var post = Posts.findOne({ text: 'create permission'});
      
      // Creating an ACL and Adding an ACE
      var aclService = new SecurityAcl.Service();
      
      // object-scope
      var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
      var builder = new SecurityAcl.MaskBuilder();
      builder.add('create');
      
      var securityIdentity = SecurityAcl.userSecurityIdentityFromAccount(Meteor.user());
      acl.insertObjectAce(securityIdentity, builder.getMask());
      
      aclService.updateAcl(acl);
      
      // check CREATE permission
      var authorizationChecker = new SecurityAcl.AuthorizationChecker();
      
      if (authorizationChecker.isGranted('VIEW', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('EDIT', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('CREATE', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('DELETE', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('UNDELETE', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OPERATOR', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('MASTER', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OWNER', post)) {
        return false;
      }
      
      return true;
    },
    deletePermissionObjectAce: function () {
      // check user logged in
      if (! Meteor.userId()) {
        return false;
      }
      
      // add DELETE permission
      
      // data-fixture
      SecurityAclTestHelpers.cleanUpDatabase();
      
      Posts.insert({
        text: 'delete permission'
      });
      var post = Posts.findOne({ text: 'delete permission'});
      
      // Creating an ACL and Adding an ACE
      var aclService = new SecurityAcl.Service();
      
      // object-scope
      var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
      var builder = new SecurityAcl.MaskBuilder();
      builder.add('delete');
      
      var securityIdentity = SecurityAcl.userSecurityIdentityFromAccount(Meteor.user());
      acl.insertObjectAce(securityIdentity, builder.getMask());
      
      aclService.updateAcl(acl);
      
      // check DELETE permission
      var authorizationChecker = new SecurityAcl.AuthorizationChecker();
      
      if (authorizationChecker.isGranted('VIEW', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('EDIT', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('CREATE', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('DELETE', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('UNDELETE', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OPERATOR', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('MASTER', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OWNER', post)) {
        return false;
      }
      
      return true;
    },
    undeletePermissionObjectAce: function () {
      // check user logged in
      if (! Meteor.userId()) {
        return false;
      }
      
      // add UNDELETE permission
      
      // data-fixture
      SecurityAclTestHelpers.cleanUpDatabase();
      
      Posts.insert({
        text: 'undelete permission'
      });
      var post = Posts.findOne({ text: 'undelete permission'});
      
      // Creating an ACL and Adding an ACE
      var aclService = new SecurityAcl.Service();
      
      // object-scope
      var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
      var builder = new SecurityAcl.MaskBuilder();
      builder.add('undelete');
      
      var securityIdentity = SecurityAcl.userSecurityIdentityFromAccount(Meteor.user());
      acl.insertObjectAce(securityIdentity, builder.getMask());
      
      aclService.updateAcl(acl);
      
      // check UNDELETE permission
      var authorizationChecker = new SecurityAcl.AuthorizationChecker();
      
      if (authorizationChecker.isGranted('VIEW', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('EDIT', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('CREATE', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('DELETE', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('UNDELETE', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OPERATOR', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('MASTER', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OWNER', post)) {
        return false;
      }
      
      return true;
    },
    operatorPermissionObjectAce: function () {
      // check user logged in
      if (! Meteor.userId()) {
        return false;
      }
      
      // add OPERATOR permission
      
      // data-fixture
      SecurityAclTestHelpers.cleanUpDatabase();
      
      Posts.insert({
        text: 'operator permission'
      });
      var post = Posts.findOne({ text: 'operator permission'});
      
      // Creating an ACL and Adding an ACE
      var aclService = new SecurityAcl.Service();
      
      // object-scope
      var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
      var builder = new SecurityAcl.MaskBuilder();
      builder.add('operator');
      
      var securityIdentity = SecurityAcl.userSecurityIdentityFromAccount(Meteor.user());
      acl.insertObjectAce(securityIdentity, builder.getMask());
      
      aclService.updateAcl(acl);
      
      // check OPERATOR permission
      var authorizationChecker = new SecurityAcl.AuthorizationChecker();
      
      if (! authorizationChecker.isGranted('VIEW', post)) {
        return false;
      }
      
      if (! authorizationChecker.isGranted('EDIT', post)) {
        return false;
      }
      
      if (! authorizationChecker.isGranted('CREATE', post)) {
        return false;
      }
      
      if (! authorizationChecker.isGranted('DELETE', post)) {
        return false;
      }
      
      if (! authorizationChecker.isGranted('UNDELETE', post)) {
        return false;
      }
      
      if (! authorizationChecker.isGranted('OPERATOR', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('MASTER', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OWNER', post)) {
        return false;
      }
      
      return true;
    },
    masterPermissionObjectAce: function () {
      // check user logged in
      if (! Meteor.userId()) {
        return false;
      }
      
      // add MASTER permission
      
      // data-fixture
      SecurityAclTestHelpers.cleanUpDatabase();
      
      Posts.insert({
        text: 'master permission'
      });
      var post = Posts.findOne({ text: 'master permission'});
      
      // Creating an ACL and Adding an ACE
      var aclService = new SecurityAcl.Service();
      
      // object-scope
      var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
      var builder = new SecurityAcl.MaskBuilder();
      builder.add('master');
      
      var securityIdentity = SecurityAcl.userSecurityIdentityFromAccount(Meteor.user());
      acl.insertObjectAce(securityIdentity, builder.getMask());
      
      aclService.updateAcl(acl);
      
      // check MASTER permission
      var authorizationChecker = new SecurityAcl.AuthorizationChecker();
      
      if (false === authorizationChecker.isGranted('VIEW', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('EDIT', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('CREATE', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('DELETE', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('UNDELETE', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('OPERATOR', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('MASTER', post)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OWNER', post)) {
        return false;
      }
      
      return true;
    },
    ownerPermissionObjectAce: function () {
      // check user logged in
      if (! Meteor.userId()) {
        return false;
      }
      
      // add OWNER permission
      
      // data-fixture
      SecurityAclTestHelpers.cleanUpDatabase();
      
      Posts.insert({
        text: 'owner permission'
      });
      var post = Posts.findOne({ text: 'owner permission'});
      
      // Creating an ACL and Adding an ACE
      var aclService = new SecurityAcl.Service();
      
      // object-scope
      var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
      var builder = new SecurityAcl.MaskBuilder();
      builder.add('owner');
      
      var securityIdentity = SecurityAcl.userSecurityIdentityFromAccount(Meteor.user());
      acl.insertObjectAce(securityIdentity, builder.getMask());
      
      aclService.updateAcl(acl);
      
      // check OWNER permission
      var authorizationChecker = new SecurityAcl.AuthorizationChecker();
      
      if (false === authorizationChecker.isGranted('VIEW', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('EDIT', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('CREATE', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('DELETE', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('UNDELETE', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('OPERATOR', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('MASTER', post)) {
        return false;
      }
      
      if (false === authorizationChecker.isGranted('OWNER', post)) {
        return false;
      }
      
      return true;
    },
    viewPermissionObjectFieldAce: function () {
      // check user logged in
      if (! Meteor.userId()) {
        return false;
      }
      
      // add VIEW permission
      
      // data-fixture
      SecurityAclTestHelpers.cleanUpDatabase();
      
      Posts.insert({
        text: 'view permission object-field-scope'
      });
      var post = Posts.findOne({ text: 'view permission object-field-scope'});
      
      // Creating an ACL and adding an ACE
      var aclService = new SecurityAcl.Service();
      
      // object-field-scope
      var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
      var builder = new SecurityAcl.MaskBuilder();
      builder.add('view');
      
      var securityIdentity = SecurityAcl.userSecurityIdentityFromAccount(Meteor.user());
      acl.insertObjectFieldAce('_id',securityIdentity, builder.getMask());
      
      aclService.updateAcl(acl);
      
      // check VIEW permission
      var authorizationChecker = new SecurityAcl.AuthorizationChecker();
      var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
      var object = new SecurityAcl.FieldVote(oid, '_id');
      
      if (false === authorizationChecker.isGranted('VIEW', object)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('EDIT', object)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('CREATE', object)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('DELETE', object)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('UNDELETE', object)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OPERATOR', object)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('MASTER', object)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OWNER', object)) {
        return false;
      }
      
      return true;
    },
    viewPermissionClassAce: function () {
      // check user logged in
      if (! Meteor.userId()) {
        return false;
      }
      
      // add VIEW permission
      
      // data-fixture
      SecurityAclTestHelpers.cleanUpDatabase();
      
      Posts.insert({
        text: 'view permission class-scope'
      });
      var post = Posts.findOne({ text: 'view permission class-scope'});
      
      // Creating an ACL and adding an ACE
      var aclService = new SecurityAcl.Service();
      
      // class-scope
      var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
      var builder = new SecurityAcl.MaskBuilder();
      builder.add('view');
      
      var securityIdentity = SecurityAcl.userSecurityIdentityFromAccount(Meteor.user());
      acl.insertClassAce(securityIdentity, builder.getMask());
      
      aclService.updateAcl(acl);
      
      // check VIEW permission
      var authorizationChecker = new SecurityAcl.AuthorizationChecker();
      var objectIdentity = new SecurityAcl.objectIdentityFromDomainObject(post);
      
      if (false === authorizationChecker.isGranted('VIEW', objectIdentity)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('EDIT', objectIdentity)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('CREATE', objectIdentity)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('DELETE', objectIdentity)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('UNDELETE', objectIdentity)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OPERATOR', objectIdentity)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('MASTER', objectIdentity)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OWNER', objectIdentity)) {
        return false;
      }
      
      return true;
    },
    viewPermissionClassFieldAce: function () {
      // check user logged in
      if (! Meteor.userId()) {
        return false;
      }
      
      // add VIEW permission
      
      // data-fixture
      SecurityAclTestHelpers.cleanUpDatabase();
      
      Posts.insert({
        text: 'view permission class-field-scope'
      });
      var post = Posts.findOne({ text: 'view permission class-field-scope'});
      
      // Creating an ACL and adding an ACE
      var aclService = new SecurityAcl.Service();
      
      // class-field-scope
      var acl = aclService.createAcl(new SecurityAcl.objectIdentityFromDomainObject(post));
      var builder = new SecurityAcl.MaskBuilder();
      builder.add('view');
      
      var securityIdentity = SecurityAcl.userSecurityIdentityFromAccount(Meteor.user());
      acl.insertClassFieldAce('_id',securityIdentity, builder.getMask());
      
      aclService.updateAcl(acl);
      
      // check VIEW permission
      var authorizationChecker = new SecurityAcl.AuthorizationChecker();
      var oid = new SecurityAcl.objectIdentityFromDomainObject(post);
      var object = new SecurityAcl.FieldVote(oid, '_id');
      
      if (false === authorizationChecker.isGranted('VIEW', object)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('EDIT', object)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('CREATE', object)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('DELETE', object)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('UNDELETE', object)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OPERATOR', object)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('MASTER', object)) {
        return false;
      }
      
      if (authorizationChecker.isGranted('OWNER', object)) {
        return false;
      }
      
      return true;
    }
  });
    
    
}

if (Meteor.isClient) {
  Tinytest.addAsync('AuthorizationChecker - Meteor.User (objectAce)', function (test, next) {
    
    // create user and log in
    Accounts.createUser({
      username: 'username',
      email: 'email@test.com',
      password: 'test'
    });
    
    // VIEW permission (object-scope)
    Meteor.call("viewPermissionObjectAce", function (error, result) {
      test.isTrue(result, 'The user can view a post.');
    });
    
    // EDIT permission (object-scope)
    Meteor.call("editPermissionObjectAce", function (error, result) {
      test.isTrue(result, 'The user can edit a post.');
    });
    
    // CREATE permission (object-scope)
    Meteor.call("createPermissionObjectAce", function (error, result) {
      test.isTrue(result, 'The user can create a post.');
    });
    
    // DELETE permission (object-scope)
    Meteor.call("deletePermissionObjectAce", function (error, result) {
      test.isTrue(result, 'The user can delete a post.');
    });
    
    // UNDELETE permission (object-scope)
    Meteor.call("undeletePermissionObjectAce", function (error, result) {
      test.isTrue(result, 'The user can undelete a post.');
    });
    
    // OPERATOR permission (object-scope)
    Meteor.call("operatorPermissionObjectAce", function (error, result) {
      test.isTrue(result, 'The user has operator permission.');
    });
    
    // MASTER permission (object-scope)
    Meteor.call("masterPermissionObjectAce", function (error, result) {
      test.isTrue(result, 'The user has master permission.');
    });
    
    // OWNER permission (object-scope)
    Meteor.call("ownerPermissionObjectAce", function (error, result) {
      test.isTrue(result, 'The user has owner permission.');
      next();
    });
    
  });
  
  Tinytest.addAsync('AuthorizationChecker - Meteor.User (objectFieldAce)', function (test, next) {
    // create user and log in
    Accounts.createUser({
      username: 'username',
      email: 'email@test.com',
      password: 'test'
    });
    
    // VIEW permission (objectfield-scope)
    Meteor.call("viewPermissionObjectFieldAce", function (error, result) {
      test.isTrue(result, 'The user can view the field _id of the post.');
      next();
    });
  });
    
  Tinytest.addAsync('AuthorizationChecker - Meteor.User (classAce)', function (test, next) {
    // create user and log in
    Accounts.createUser({
      username: 'username',
      email: 'email@test.com',
      password: 'test'
    });
    
    // VIEW permission (class-scope)
    Meteor.call("viewPermissionClassAce", function (error, result) {
      test.isTrue(result, 'The user can view a post.');
      next();
    });
    
  });
  
  Tinytest.addAsync('AuthorizationChecker - Meteor.User (classFieldAce)', function (test, next) {
    // create user and log in
    Accounts.createUser({
      username: 'username',
      email: 'email@test.com',
      password: 'test'
    });
    
    // VIEW permission (class-field-scope)
    Meteor.call("viewPermissionClassFieldAce", function (error, result) {
      test.isTrue(result, 'The user can view the field _id of the post.');
      next();
    });
  });
  
}

