

Tinytest.add('AclService - _createOrRetrieveClassId', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var aclService = new SecurityAcl.Service();
  
  var classId = aclService._createOrRetrieveClassId('posts');
  
  test.equal(classId, SecurityAcl.Classes.findOne({ 'classType': 'posts' })._id, 'Create classId');
  test.equal(aclService._createOrRetrieveClassId('posts'), classId, 'Retrieve classId');
  
  test.throws(function () {
    aclService._createOrRetrieveClassId();
  }, 'The classType cannot be null or undefined.');
  
});

Tinytest.add('AclService - _createOrRetrieveSecurityIdentityId', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var aclService = new SecurityAcl.Service();
  
  test.throws(function () {
    aclService._createOrRetrieveSecurityIdentityId('invalid-sid');
  },'The sid must be an instance of SecurityAcl.SecurityIdentity.');
  
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  var sidId = aclService._createOrRetrieveSecurityIdentityId(sid);
  
  test.equal(sidId,  SecurityAcl.SecurityIdentities.findOne({ 'identifier': 'className-username', 'username': true })._id, 'Create sid and return the id.');
  test.equal(aclService._createOrRetrieveSecurityIdentityId(sid), sidId, 'Retrieve sidId');
  
  var roleSid = new SecurityAcl.RoleSecurityIdentity('role');
  var roleSidId = aclService._createOrRetrieveSecurityIdentityId(roleSid);
  
  test.equal(roleSidId,  SecurityAcl.SecurityIdentities.findOne({ 'identifier': 'role', 'username': false })._id, 'Create role sid and return the id.');
  test.equal(aclService._createOrRetrieveSecurityIdentityId(roleSid), roleSidId, 'Retrieve roleSidId');
  
  
});

Tinytest.add('AclService - _createObjectIdentity', function (test) {
  SecurityAcl.ObjectIdentities.remove({});
  
  var aclService = new SecurityAcl.Service();
  
  test.throws(function () {
    aclService._createObjectIdentity('invalidOid');
  }, 'The argument must be an instance of SecurityAcl.ObjectIdentity.');
  
  Posts.insert({
    text: 'test'
  });
  
  var post = Posts.findOne();
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  
  aclService._createObjectIdentity(oid);
  
  var resultOid = SecurityAcl.ObjectIdentities.findOne({});
  var resultClass = SecurityAcl.Classes.findOne({});
  
  test.equal(resultOid.objectIdentifier, oid.identifier(), 'ObjectIdentifier correctly defined.');
  test.equal(resultOid.classId, resultClass._id, 'ClassId correctly defined.');
  test.equal(resultOid.entriesInheriting, true, 'EntriesInheriting defined.');
});

Tinytest.add('AclService - retrieveObjectIdentityPrimaryKey', function (test) {
  SecurityAcl.ObjectIdentities.remove({});
  
  var aclService = new SecurityAcl.Service();
  
  test.throws(function () {
    aclService.retrieveObjectIdentityPrimaryKey('invalidOid');
  }, 'The argument must be an instance of SecurityAcl.ObjectIdentity.');
  
  var oid = new SecurityAcl.ObjectIdentity('testIdentifier', 'collectionDocumentTest');
  
  test.equal(aclService.retrieveObjectIdentityPrimaryKey(oid), null, 'If oid doesnt exist, the retrieveObjectIdentityPrimaryKey returns null.');
  
  var post = Posts.findOne();
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  aclService._createObjectIdentity(oid);
  test.equal(aclService.retrieveObjectIdentityPrimaryKey(oid), SecurityAcl.ObjectIdentities.findOne({})._id, 'If oid exists, the retrieveObjectIdentityPrimaryKey returns the objectID.');
});


Tinytest.add('AclService - createAcl', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var aclService = new SecurityAcl.Service();
  
  test.throws(function () {
    aclService.createAcl('invalidOid');
  }, 'The argument must be an instance of SecurityAcl.ObjectIdentity.');
  
  Posts.insert({
    text: 'test createAcl'
  });
  
  var post = Posts.findOne();
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  aclService.createAcl(oid);
  
  test.throws(function () {
    aclService.createAcl(oid);
  }, 'The oid '+oid.identifier()+' is already associated with an ACL.');
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  //data fixtures for test
  Posts.insert({
    text: 'test createAcl2'
  });
  
  
  var post = Posts.findOne({ 'text': 'test createAcl2' });
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  var acl = aclService.createAcl(oid);
  
  test.isTrue(acl instanceof SecurityAcl.Acl, 'createAcl returns an ACL.');
  test.equal(acl.objectIdentity().identifier(), post._id, 'createAcl returns the right ACL.');
  test.equal(acl.objectIdentity().type(), 'posts', 'createAcl returns the right ACL.');
  
  var resultOid = SecurityAcl.ObjectIdentities.findOne({});
  var resultOidAncestor = SecurityAcl.ObjectIdentitiesAncestors.findOne({});
  var resultClass = SecurityAcl.Classes.findOne({});
  
  test.equal(resultOid.objectIdentifier, oid.identifier(), 'ObjectIdentifier correctly defined.');
  test.equal(resultOid.classId, resultClass._id, 'ClassId correctly defined.');
  test.equal(resultOid.entriesInheriting, true, 'EntriesInheriting defined.');
  test.equal(resultOidAncestor.objectIdentityId, resultOid._id, 'objectIdentityId (ancestors) defined.');
  test.equal(resultOidAncestor.ancestorId, resultOid._id, 'ancestorId (ancestors) defined.');
  
});



Tinytest.add('AclService - findOids', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var aclService = new SecurityAcl.Service();
  
  //data fixtures for test
  Posts.insert({
    text: 'test1 findOids'
  });
  
  Posts.insert({
    text: 'test2 findOids'
  });
  
  
  var post1 = Posts.findOne({ 'text': 'test1 findOids' });
  var oid1 = SecurityAcl.objectIdentityFromDomainObject(post1);
  aclService.createAcl(oid1);
  
  var post2 = Posts.findOne({ 'text': 'test2 findOids' });
  var oid2 = SecurityAcl.objectIdentityFromDomainObject(post2);
  aclService.createAcl(oid2);
  
  var aclOid1 = SecurityAcl.ObjectIdentities.findOne({ 'objectIdentifier': oid1.identifier() });
  var aclOid2 = SecurityAcl.ObjectIdentities.findOne({ 'objectIdentifier': oid2.identifier() });
  
  var oids = aclService.findOids([ aclOid1._id, aclOid2._id ]);
  
  test.length(oids, 2, 'It returns an array with 2 objects.');
  test.instanceOf(oids[0], SecurityAcl.ObjectIdentity, 'It is an instance of SecurityAcl.ObjectIdentity');
  
  // the order of the elements is not respected in oids
  var oidFound = false;
  for (var i = 0; i < oids.length; i++) {
    if (oids[i].equals(oid1)) {
      oidFound = true;
    }
  }
  
  test.isTrue(oidFound, 'It returns the correct oid1');
  
  var oidFound = false;
  for (var i = 0; i < oids.length; i++) {
    if (oids[i].equals(oid2)) {
      oidFound = true;
    }
  }
  
  test.isTrue(oidFound, 'It returns the correct oid2');
});

Tinytest.add('AclService - _getAncestorIds', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var aclService = new SecurityAcl.Service();
  
  //data fixtures for test
  Posts.insert({
    text: 'test1 getAncestorIds'
  });
  
  Posts.insert({
    text: 'test2 getAncestorIds'
  });
  
  Posts.insert({
    text: 'test3 getAncestorIds'
  });
  
  var post1 = Posts.findOne({ 'text': 'test1 getAncestorIds' });
  var oid1 = SecurityAcl.objectIdentityFromDomainObject(post1);
  
  aclService.createAcl(oid1);
  
  var post2 = Posts.findOne({ 'text': 'test2 getAncestorIds' });
  var oid2 = SecurityAcl.objectIdentityFromDomainObject(post2);
  aclService.createAcl(oid2);
  var post3 = Posts.findOne({ 'text': 'test3 getAncestorIds' });
  var oid3 = SecurityAcl.objectIdentityFromDomainObject(post3);
  aclService.createAcl(oid3);
  
  var aclOid1 = SecurityAcl.ObjectIdentities.findOne({ 'objectIdentifier': oid1.identifier() });
  var aclOid2 = SecurityAcl.ObjectIdentities.findOne({ 'objectIdentifier': oid2.identifier() });
  
  //Set: add oids to the batch
  var batch = [];
  batch.push(oid1);
  batch.push(oid2);
  test.length(aclService._getAncestorIds(batch), 2, 'It returns an array with 2 objects.');
  test.equal(aclService._getAncestorIds(batch)[0], aclOid1._id, 'It returns the correct ancestor.');
  test.equal(aclService._getAncestorIds(batch)[1], aclOid2._id, 'It returns the correct ancestor.');
  
  var aclOid3 = SecurityAcl.ObjectIdentities.findOne({ 'objectIdentifier': oid3.identifier() });
  //Set: oid2 inheriting from oid3
  SecurityAcl.ObjectIdentitiesAncestors.insert({ 'objectIdentityId': aclOid2._id, 'ancestorId': aclOid3._id  });
  
  test.length(aclService._getAncestorIds(batch), 3, 'It returns an array with 3 objects.');
  test.equal(aclService._getAncestorIds(batch)[0], aclOid1._id, 'It returns the correct ancestor.');
  test.equal(aclService._getAncestorIds(batch)[1], aclOid2._id, 'It returns the correct ancestor.');
  test.equal(aclService._getAncestorIds(batch)[2], aclOid3._id, 'It returns the correct ancestor.');
  
  test.throws(function () {
    aclService._getAncestorIds('invalidBatch');
  }, 'The argument must be an instance of Array.');
  
  test.throws(function () {
    aclService._getAncestorIds(['test']);
  }, 'The batch element must be an instance of SecurityAcl.ObjectIdentity.');
  
  
});



Tinytest.add('AclService - _lookupData', function (test) {
  
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var aclService = new SecurityAcl.Service();
  
  // data fixtures
  Posts.insert({
    text: 'test _lookupData'
  });
  
  var post = Posts.findOne({ 'text': 'test _lookupData' });
  
  SecurityAcl.SecurityIdentities.insert({
    identifier: '/test/user/1',
    username: 'user1'
  });
  
  var sid = SecurityAcl.SecurityIdentities.findOne({ username: 'user1' });
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  aclService.createAcl(oid);
   
  var dbClass = SecurityAcl.Classes.findOne({ classType: oid.type() });
  var dbOid = SecurityAcl.ObjectIdentities.findOne({ objectIdentifier: oid.identifier() });
  
  SecurityAcl.Entries.insert({
    classId: dbClass._id,
    objectIdentityId: dbOid._id,
    securityIdentityId: sid._id,
    fieldName: null,
    aceOrder: 0,
    mask: 32,
    granting: true,
    grantingStrategy: 'all',
    auditSuccess: false,
    auditFailure: false,
  });
  
  SecurityAcl.Entries.insert({
    classId: dbClass._id,
    objectIdentityId: dbOid._id,
    securityIdentityId: sid._id,
    fieldName: null,
    aceOrder: 0,
    mask: 128,
    granting: true,
    grantingStrategy: 'all',
    auditSuccess: false,
    auditFailure: false,
  });
  
  var batch = [];
  batch.push(oid);
  var ancestorIds = aclService._getAncestorIds(batch);
  
  var data = aclService._lookupData(ancestorIds);
  
  test.length(data, 2, 'It returns an array with 2 objects.');
  test.equal(data[0].aclId, dbOid._id, 'It returns correctly the data.');
  test.equal(data[0].objectIdentifier, oid.identifier(), 'It returns correctly the data.');
  test.equal(data[0].entriesInheriting, true, 'It returns correctly the data.');
  test.equal(data[0].classType, oid.type(), 'It returns correctly the data.');
  test.equal(data[0].aceId, SecurityAcl.Entries.findOne({ mask: 32 })._id, 'It returns correctly the data.');
  test.equal(data[0].objectIdentityId, SecurityAcl.Entries.findOne({ mask: 32 }).objectIdentityId, 'It returns correctly the data.');
  test.equal(data[0].fieldName, null, 'It returns correctly the data.');
  test.equal(data[0].aceOrder, 0, 'It returns correctly the data.');
  test.equal(data[0].mask, 32, 'It returns correctly the data.');
  test.equal(data[0].granting, true, 'It returns correctly the data.');
  test.equal(data[0].grantingStrategy, 'all', 'It returns correctly the data.');
  test.equal(data[0].auditSuccess, false, 'It returns correctly the data.');
  test.equal(data[0].auditFailure, false, 'It returns correctly the data.');
  
  test.equal(data[1].aclId, dbOid._id, 'It returns correctly the data.');
  test.equal(data[1].objectIdentifier, oid.identifier(), 'It returns correctly the data.');
  test.equal(data[1].mask, 128, 'It returns correctly the data.');
  
  // class-scope
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  aclService.createAcl(oid);
  
  var dbClass = SecurityAcl.Classes.findOne({ classType: oid.type() });
  
  SecurityAcl.Entries.insert({
    classId: dbClass._id,
    objectIdentityId: null,
    securityIdentityId: sid._id,
    fieldName: null,
    aceOrder: 0,
    mask: 64,
    granting: true,
    grantingStrategy: 'all',
    auditSuccess: false,
    auditFailure: false,
  });
  
  batch.push(oid);
  var ancestorIds = aclService._getAncestorIds(batch);
  
  var data = aclService._lookupData(ancestorIds);
  
  // 2 oids - 1 oid with 3 ACES and 1 oid with class ACE
  test.length(data, 4, 'It returns an array with 4 objects.');
  
  var result = data.filter(function(obj) {
    return obj.objectIdentifier == 'class';
  });
  
  test.length(result, 1, 'It returns 1 object with objectIdentifier class.');
  
  var result = data.filter(function(obj) {
    return obj.mask == 64;
  });
  
  test.length(result, 2, 'It returns 2 objects with mask 64.');
  
  var result = data.filter(function(obj) {
    return obj.mask == 32;
  });
  
  test.length(result, 1, 'It returns 1 object with mask 32.');
  
  var result = data.filter(function(obj) {
    return obj.mask == 128;
  });
  
  test.length(result, 1, 'It returns 1 object with mask 128.');
});

Tinytest.add('AclService - _hydrateObjectIdentities', function (test) {
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var aclService = new SecurityAcl.Service();
  
  //data fixtures
  Posts.insert({
    text: 'test _hydrateObjectIdentities'
  });
  
  var post = Posts.findOne({ 'text': 'test _hydrateObjectIdentities' });
  
  SecurityAcl.SecurityIdentities.insert({
    identifier: '/test/user-test@user-test.com',
    username: true
  });
  
  var sid = SecurityAcl.SecurityIdentities.findOne({ identifier: '/test/user-test@user-test.com' });
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  aclService.createAcl(oid);
   
  var dbClass = SecurityAcl.Classes.findOne({ classType: oid.type() });
  var dbOid = SecurityAcl.ObjectIdentities.findOne({ objectIdentifier: oid.identifier() });
  
  SecurityAcl.Entries.insert({
    classId: dbClass._id,
    objectIdentityId: dbOid._id,
    securityIdentityId: sid._id,
    fieldName: null,
    aceOrder: 5,
    mask: 32,
    granting: true,
    grantingStrategy: 'all',
    auditSuccess: false,
    auditFailure: false,
  });
  
  SecurityAcl.Entries.insert({
    classId: dbClass._id,
    objectIdentityId: dbOid._id,
    securityIdentityId: sid._id,
    fieldName: null,
    aceOrder: 0,
    mask: 128,
    granting: true,
    grantingStrategy: 'all',
    auditSuccess: false,
    auditFailure: false,
  });
  
  SecurityAcl.Entries.insert({
    classId: dbClass._id,
    objectIdentityId: dbOid._id,
    securityIdentityId: sid._id,
    fieldName: 'title',
    aceOrder: 0,
    mask: 16,
    granting: true,
    grantingStrategy: 'all',
    auditSuccess: false,
    auditFailure: false,
  });
  
  SecurityAcl.Entries.insert({
    classId: dbClass._id,
    objectIdentityId: dbOid._id,
    securityIdentityId: sid._id,
    fieldName: 'title',
    aceOrder: 1,
    mask: 64,
    granting: true,
    grantingStrategy: 'all',
    auditSuccess: false,
    auditFailure: false,
  });
  
  var batch = [];
  batch.push(oid);
  
  var ancestorIds = aclService._getAncestorIds(batch);
  
  var data = aclService._lookupData(ancestorIds);
  
  test.length(data, 4, '_lookupData returns an array with 4 objects.');
  
  var oids = [];
  oids.push(oid);
  var oidLookup = [];
  
  var oid = null;
  for (var i = 0; i < oids.length; i++) { 
    oid = oids[i];
    oidLookupKey = oid.identifier()+oid.type();
    oidLookup[oidLookupKey] = oid;
  }
  
  var result = aclService._hydrateObjectIdentities(data, oidLookup);
  
  test.length(result, 1, 'It returns an array with 1 object.');
  test.isTrue(result[0][0] instanceof SecurityAcl.ObjectIdentity, "First element of result is a SecurityAcl.ObjectIdentity");
  test.isTrue(result[0][1] instanceof SecurityAcl.Acl, "Second element of result is a SecurityAcl.Acl");
  
  test.equal(result[0][0].identifier(), post._id, 'Identifier of oid is ok.');
  test.equal(result[0][0].type(), "posts", 'Type of oid is ok.');

  test.equal(result[0][1].id(), dbOid._id, 'The ACL id is ok.');
  test.isTrue(result[0][1].objectIdentity().equals(oid), "Acl returns the right Oid.");
  
  test.equal(Object.keys(result[0][1]._objectAces).length, 2, 'ACL returns two ACES.');
  test.equal(result[0][1]._objectAces[0]._mask, 128, 'Mask for ACE with aceOrder 0 is 128');
  test.equal(result[0][1]._objectAces[5]._mask, 32, 'Mask for ACE with aceOrder 5 is 32');
  test.equal(result[0][1]._objectFieldAces['title'][0]._mask, 16, 'Mask for ACE with fieldname title and aceOrder 0 is 16');
  test.equal(result[0][1]._objectFieldAces['title'][1]._mask, 64, 'Mask for ACE with fieldname title and aceOrder 1 is 64');
  test.equal(result[0][1]._classAces, {}, 'No class aces');
  test.equal(result[0][1]._classFieldAces, {}, 'No class field aces');
  
  SecurityAcl.ObjectIdentities.remove({});
  SecurityAcl.ObjectIdentitiesAncestors.remove({});
  SecurityAcl.Classes.remove({});
  SecurityAcl.Entries.remove({});
  
  // class-scope
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  aclService.createAcl(oid);
  
  var dbClass = SecurityAcl.Classes.findOne({ classType: oid.type() });
  
  SecurityAcl.Entries.insert({
    classId: dbClass._id,
    objectIdentityId: null,
    securityIdentityId: sid._id,
    fieldName: null,
    aceOrder: 0,
    mask: 256,
    granting: true,
    grantingStrategy: 'all',
    auditSuccess: false,
    auditFailure: false,
  });
  
  SecurityAcl.Entries.insert({
    classId: dbClass._id,
    objectIdentityId: null,
    securityIdentityId: sid._id,
    fieldName: 'title',
    aceOrder: 0,
    mask: 128,
    granting: true,
    grantingStrategy: 'all',
    auditSuccess: false,
    auditFailure: false,
  });
  
  var batch = [];
  batch.push(oid);
  
  var ancestorIds = aclService._getAncestorIds(batch);
  
  var data = aclService._lookupData(ancestorIds);
  
  test.length(data, 2, '_lookupData returns an array with 2 objects.');
  
  var oids = [];
  oids.push(oid);
  var oidLookup = [];
  
  for (var i = 0; i < oids.length; i++) { 
    var oid = oids[i];
    oidLookupKey = oid.identifier()+oid.type();
    oidLookup[oidLookupKey] = oid;
  }
  
  var result = aclService._hydrateObjectIdentities(data, oidLookup);
  
  test.length(result, 1, 'It returns an array with 1 object.');
  test.equal(Object.keys(result[0][1]._classAces).length, 1, 'ACL returns one class ACE.');
  
  test.equal(result[0][1]._oid._identifier, 'class', 'The identifier of oid is class');
  test.equal(result[0][1]._classAces[0]._mask, 256, 'Mask for ACE with aceOrder 0 is 256');
  test.equal(result[0][1]._classFieldAces['title'][0]._mask, 128, 'Mask for ACE with fieldname title and aceOrder 0 is 128');
  
  test.equal(result[0][1]._objectAces, {}, 'No object aces');
  test.equal(result[0][1]._objectFieldAces, {}, 'No object field aces');
  
  // Test parent ACL
  //
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var aclService = new SecurityAcl.Service();
  
  //data fixtures
  Posts.insert({
    text: 'test hydrate'
  });
  
  Posts.insert({
    text: 'test hydrate2'
  });
  
  var post = Posts.findOne({ 'text': 'test hydrate' });
  var post2 = Posts.findOne({ 'text': 'test hydrate2' });
  
  SecurityAcl.SecurityIdentities.insert({
    identifier: '/test/user-test@user-test.com',
    username: true
  });
  
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  aclService.createAcl(oid);
  
  var oid2 = SecurityAcl.objectIdentityFromDomainObject(post2);
  aclService.createAcl(oid2);
  
  var acl = aclService.findAcl(oid, []);
  var acl2 = aclService.findAcl(oid2, []);
  acl.setParentAcl(acl2);
  aclService.updateAcl(acl);
  
  var NewAclService = new SecurityAcl.Service();
  var acl = NewAclService.findAcl(oid, []);
  
  // we cannot check 'equal' the acl2 entirely because the listener is different.
  test.equal(acl.parentAcl().id(), acl2.id(), '_hydrateObjectIdentities manages the parent acl.');
});

Tinytest.add('AclService - findAcl', function (test) {
  //remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var aclService = new SecurityAcl.Service();
  
  //data fixtures
  Posts.insert({
    text: 'test findAcl'
  });
  
  var post = Posts.findOne({ 'text': 'test findAcl' });
  
  SecurityAcl.SecurityIdentities.insert({
    identifier: '/test/user-test@user-test.com',
    username: true
  });
  
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  aclService.createAcl(oid);
  
  var acl = aclService.findAcl(oid);
  test.isTrue(acl instanceof SecurityAcl.Acl, 'createAcl returns an ACL.');
  test.equal(acl.objectIdentity().identifier(), post._id, 'createAcl returns the right ACL.');
  test.equal(acl.objectIdentity().type(), 'posts', 'createAcl returns the right ACL.');
  
  // Test: findAcl returns the ACL and not the parent.
  //
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var aclService = new SecurityAcl.Service();
  
  // data fixtures
  Posts.insert({
    text: 'test findAcl'
  });
  
  Posts.insert({
    text: 'test findAcl2'
  });
  
  var post = Posts.findOne({ 'text': 'test findAcl' });
  var post2 = Posts.findOne({ 'text': 'test findAcl2' });
  
  SecurityAcl.SecurityIdentities.insert({
    identifier: '/test/user-test@user-test.com',
    username: true
  });
  
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  aclService.createAcl(oid);
  
  var oid2 = SecurityAcl.objectIdentityFromDomainObject(post2);
  aclService.createAcl(oid2);
  
  var acl = aclService.findAcl(oid, []);
  var acl2 = aclService.findAcl(oid2, []);
  
  acl.setParentAcl(acl2);
  aclService.updateAcl(acl);
  
  var NewAclService = new SecurityAcl.Service();
  var acl = NewAclService.findAcl(oid, []);
  // we cannot check 'equal' the acl2 entirely because the listener is different.
  test.equal(acl.parentAcl().id(), acl2.id(), 'findAcl returns the ACL and not the parent.');
  
});

Tinytest.add('AclService - findAcls', function (test) {
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var aclService = new SecurityAcl.Service();
  
  // data fixtures
  Posts.insert({
    text: 'test findAcls'
  });
  
  var post = Posts.findOne({ 'text': 'test findAcls' });
  
  SecurityAcl.SecurityIdentities.insert({
    identifier: '/test/user-test@user-test.com',
    username: true
  });
  
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  var acl = aclService.createAcl(oid);
  
  var result = aclService.findAcls([oid], []);
  test.isTrue(result instanceof Array, 'findAcls returns an array mapping the passed object identities to ACLs.');
  test.isTrue(result[0][0] instanceof SecurityAcl.ObjectIdentity, 'findAcls returns an oid.');
  test.isTrue(result[0][1] instanceof SecurityAcl.Acl, 'findAcls returns an ACL.');
  test.equal(result[0][0].identifier(), post._id, 'findAcls returns the right oid.');
  test.equal(result[0][0].type(), 'posts', 'findAcls returns the right oid.');
  
  // Test: tracking by listener
  test.length(acl._listeners, 1, 'There is one listener for the acl.');
  test.equal(acl._listeners[0], aclService, 'The listener is correctly set up.');
  
  
});



Tinytest.add('AclService - updateAcl', function (test) {
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var aclService = new SecurityAcl.Service();
  
  // data fixtures
  Posts.insert({
    text: 'test1 updateAcl'
  });
  
  Posts.insert({
    text: 'test2 updateAcl'
  });
  
  Posts.insert({
    text: 'test3 updateAcl'
  });
  
  var post = Posts.findOne({ 'text': 'test1 updateAcl' });
  var post2 = Posts.findOne({ 'text': 'test2 updateAcl' });
  var post3 = Posts.findOne({ 'text': 'test3 updateAcl' });
  
  SecurityAcl.SecurityIdentities.insert({
    identifier: '/test/user-test@user-test.com',
    username: true
  });
  
  
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  
  var permissionGrantingStrategy = new SecurityAcl.PermissionGrantingStrategy();
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [], true);
  
  test.throws(function () {
    aclService.updateAcl(acl);
  }, 'The ACL is not tracked by this service.');
  
  aclService.createAcl(oid);
  
  var oid2 = SecurityAcl.objectIdentityFromDomainObject(post2);
  aclService.createAcl(oid2);
  
  var acl = aclService.findAcl(oid, []);
  var acl2 = aclService.findAcl(oid2, []);
  
  acl.setEntriesInheriting(false);
  acl.setParentAcl(acl2);
  aclService.updateAcl(acl);
  
  test.equal(acl.isEntriesInheriting(), false, 'EntriesInheriting is false.');
  test.equal(acl.parentAcl(), acl2, 'The parent ACL is acl2.');
  
  // Test: test with new service to check if data is updated in DB.
  var NewAclService = new SecurityAcl.Service();
  var acl = NewAclService.findAcl(oid, []);
  // we cannot check entirely with 'equal' the acl2 because the listener is different.
  test.equal(acl.parentAcl().id(), acl2.id(), 'New AclService: the parent ACL is acl2.');
  
  // Test: regenerate ancestor relations
  var results = SecurityAcl.ObjectIdentitiesAncestors.find({
    'objectIdentityId': acl._id
  }).fetch();
  
  test.length(results, 2, 'It returns an array with 2 objects.');
  test.equal(results[0].ancestorId, acl._id, 'ancestor is correctly regenerated.');
  test.equal(results[1].ancestorId, acl2._id, 'ancestor is correctly regenerated.');
  
  // Test: regenerate ancestor relations with child ACL.
  var oid3 = SecurityAcl.objectIdentityFromDomainObject(post3);
  aclService.createAcl(oid3);
  var acl3 = aclService.findAcl(oid3, []);
  
  acl2.setParentAcl(acl3);
  aclService.updateAcl(acl2);
  
  var results = SecurityAcl.ObjectIdentitiesAncestors.find({
    'objectIdentityId': acl._id
  }).fetch();
  
  test.length(results, 3, 'It returns an array with 3 objects.');
  test.equal(results[0].ancestorId, acl._id, 'Ancestor is correctly regenerated.');
  test.equal(results[1].ancestorId, acl2._id, 'Ancestor is correctly regenerated.');
  test.equal(results[2].ancestorId, acl3._id, 'Ancestor is correctly regenerated.');
  
  // Test: updateAcl - insert classAces.
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  // class-scope
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  var acl = aclService.createAcl(oid);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  acl.insertClassAce(sid, 128);
  aclService.updateAcl(acl);
  
  var result = SecurityAcl.Entries.findOne();
  
  test.equal(result.mask, 128, 'An entry with mask 128 is created in database.');
  test.equal(result.objectIdentityId, null, 'An entry with objectIdentityId null is created in database.');
  
  // Test: updateAcl - update classAces.
  acl.updateClassAce(0, 64, null);
  aclService.updateAcl(acl);
  
  var result = SecurityAcl.Entries.findOne();
  
  test.equal(result.mask, 64, 'The mask has been updated with value 64.');
  
  // Test: updateAcl - delete classAces.
  acl.deleteClassAce(0);
  aclService.updateAcl(acl);
  
  var result = SecurityAcl.Entries.findOne();
  
  test.isUndefined(result, 'The ACE has been deleted.');
  
  // Test: updateAcl - insert classFieldAces.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  var acl = aclService.createAcl(oid);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  acl.insertClassFieldAce('field', sid, 128);
  aclService.updateAcl(acl);
  
  var result = SecurityAcl.Entries.findOne();
  
  test.equal(result.mask, 128, 'An entry with mask 128 is created in database.');
  test.equal(result.objectIdentityId, null, 'An entry with objectIdentityId null is created in database.');
  test.equal(result.fieldName, 'field', 'An entry with field is created in database.');
  
  // Test: updateAcl - update classFieldAces.
  acl.updateClassFieldAce(0, 'field', 64, null);
  aclService.updateAcl(acl);
  
  var result = SecurityAcl.Entries.findOne();
  
  test.equal(result.mask, 64, 'The mask has been updated with value 64.');
  
  // Test: updateAcl - delete classFieldAces.
  acl.deleteClassFieldAce(0, 'field');
  aclService.updateAcl(acl);
  
  var result = SecurityAcl.Entries.findOne();
  
  test.isUndefined(result, 'The ACE has been deleted.');
  
  // Test: updateAcl - insert objectAces.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  // object-scope
  Posts.insert({
    text: 'test createAcl'
  });
  
  var post = Posts.findOne();
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  var acl = aclService.createAcl(oid);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  acl.insertObjectAce(sid, 128);
  aclService.updateAcl(acl);
  
  var result = SecurityAcl.Entries.findOne();
  
  test.equal(result.mask, 128, 'An entry with mask 128 is created in database.');
  test.isNotNull(result.objectIdentityId, 'An entry with objectIdentityId not null is created in database.');
  
  // Test: updateAcl - update objectAces.
  acl.updateObjectAce(0, 64, null);
  aclService.updateAcl(acl);
  
  var result = SecurityAcl.Entries.findOne();
  
  test.equal(result.mask, 64, 'The mask has been updated with value 64.');
  
  // Test: updateAcl - delete objectAces.
  acl.deleteObjectAce(0);
  aclService.updateAcl(acl);
  
  var result = SecurityAcl.Entries.findOne();
  
  test.isUndefined(result, 'The ACE has been deleted.');
  
  // Test: updateAcl - insert objectFieldAces.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  // object-scope
  Posts.insert({
    text: 'test createAcl'
  });
  
  var post = Posts.findOne();
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  var acl = aclService.createAcl(oid);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  acl.insertObjectFieldAce('field', sid, 128);
  aclService.updateAcl(acl);
  
  var result = SecurityAcl.Entries.findOne();
  
  test.equal(result.mask, 128, 'An entry with mask 128 is created in database.');
  test.isNotNull(result.objectIdentityId, 'An entry with objectIdentityId not null is created in database.');
  test.equal(result.fieldName, 'field', 'An entry with field is created in database.');
  
  // Test: updateAcl - update objectFieldAces.
  acl.updateObjectFieldAce(0, 'field', 64, null);
  aclService.updateAcl(acl);
  
  var result = SecurityAcl.Entries.findOne();
  
  test.equal(result.mask, 64, 'The mask has been updated with value 64.');
  
  // Test: updateAcl - delete objectFieldAces.
  acl.deleteObjectFieldAce(0, 'field');
  aclService.updateAcl(acl);
  
  var result = SecurityAcl.Entries.findOne();
  
  test.isUndefined(result, 'The ACE has been deleted.');
});



Tinytest.add('AclService - findChildren', function (test) {
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var aclService = new SecurityAcl.Service();
  
  // data fixtures
  Posts.insert({
    text: 'test1 findChildren'
  });
  
  Posts.insert({
    text: 'test2 findChildren'
  });
  
  Posts.insert({
    text: 'test3 findChildren'
  });
  
  var post = Posts.findOne({ 'text': 'test1 findChildren' });
  var post2 = Posts.findOne({ 'text': 'test2 findChildren' });
  var post3 = Posts.findOne({ 'text': 'test3 findChildren' });
  
  SecurityAcl.SecurityIdentities.insert({
    identifier: '/test/user-test@user-test.com',
    username: true
  });
  
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  var acl = aclService.createAcl(oid);
  
  var oid2 = SecurityAcl.objectIdentityFromDomainObject(post2);
  var acl2 = aclService.createAcl(oid2);
  
  acl.setParentAcl(acl2);
  aclService.updateAcl(acl);
  
  test.throws(function () {
    aclService.findChildren('invalid oid');
  }, 'The parentOid must be an instance of SecurityAcl.ObjectIdentity.');
  
  test.throws(function () {
    aclService.findChildren(oid2, 'invalid boolean');
  }, 'The directChildrenOnly must be a boolean.');
  
  var children = aclService.findChildren(oid2);
  
  test.isTrue(children instanceof Array, 'findChildren returns an array with oids.');
  test.isTrue(children[0] instanceof SecurityAcl.ObjectIdentity, 'findChildren returns the oids.');
  test.equal(children[0].identifier(), post._id, 'findAChildren returns the right oid.');
  test.equal(children[0].type(), 'posts', 'findChilren returns the right oid.');
  
  var oid3 = SecurityAcl.objectIdentityFromDomainObject(post3);
  var acl3 = aclService.createAcl(oid3);
  
  acl2.setParentAcl(acl3);
  aclService.updateAcl(acl2);
  var children = aclService.findChildren(oid3);
  
  test.length(children, 2, 'It returns an array with 2 objects.');
  
  var result = children.filter(function(obj) {
    return String(obj.identifier()) == String(post._id);
  });
  
  test.length(result, 1, 'It returns an array with 1 object.');
  test.equal(result[0].identifier(), post._id, 'findChildren returns the right oid.');
  
  var result = children.filter(function(obj) {
    return String(obj.identifier()) == String(post2._id);
  });
  
  test.length(result, 1, 'It returns an array with 1 object.');
  test.equal(result[0].identifier(), post2._id, 'findChildren returns the right oid.');
  
  // Test: directChildrenOnly true
  var children = aclService.findChildren(oid3, true);
  test.equal(children[0].identifier(), post2._id, 'findChildren with option directChildrenOnly returns the right oid.');
  
  
});


Tinytest.add('AclService - propertyChanged', function (test) {
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  // data fixtures
  Posts.insert({
    text: 'test1 propertyChanged'
  });
  
  var post = Posts.findOne({ 'text': 'test1 propertyChanged' });
  
  var aclService = new SecurityAcl.Service();
  
  test.throws(function () {
    aclService.propertyChanged('invalid-sender','propertyName', 'oldValue', 'newValue');
  },'The sender must be an instance of SecurityAcl.Acl or SecurityAcl.Entry.');
  
  var oid = new SecurityAcl.ObjectIdentity('identifier', 'className');
  var permissionGrantingStrategy = new SecurityAcl.PermissionGrantingStrategy();
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [], true);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  var entry = new SecurityAcl.Entry(null, acl, sid, 'strategy', 128, true, true, true);
  
  
  test.equal(aclService.propertyChanged(entry,'propertyName', 'oldValue', 'newValue'), undefined, 'propertyChanged retruns undefined if the id of entry is null.');
  
  var entry = new SecurityAcl.Entry('id', acl, sid, 'strategy', 128, true, true, true);
  
  test.throws(function () {
    aclService.propertyChanged(entry,'propertyName', 'oldValue', 'newValue');
  },'The sender is not tracked by this service.');
  
  aclService._loadedAces['id'] = entry;
  aclService._propertyChanges[entry.acl().id()] = {}; // the service must track the ACL.
  aclService.propertyChanged(entry,'propertyName', 'oldValue', 'oldValue');
  
  test.isUndefined(aclService._propertyChanges[acl.id()]['aces'], 'propertyChanges for aces is undefined if the newValue is the same oldValue.');
  
  aclService.propertyChanged(entry,'propertyName', 'oldValue', 'newValue');
  
  test.equal(aclService._propertyChanges[acl.id()]['aces'][entry.id()]['ace']['_id'], entry.id(), 'propertyChanges has an ACE propertyName with the ACE values.');
  test.equal(aclService._propertyChanges[acl.id()]['aces'][entry.id()]['acePropertyChanges']['propertyName'][0], 'oldValue', 'propertyChanges has a propertyName for the ACE with oldValue.');
  test.equal(aclService._propertyChanges[acl.id()]['aces'][entry.id()]['acePropertyChanges']['propertyName'][1], 'newValue', 'propertyChanges has a propertyName for the ACE with newValue.');
  
  aclService.propertyChanged(entry,'propertyName', 'newValue', 'oldValue');
  
  test.isUndefined(aclService._propertyChanges[acl.id()]['aces'], 'propertyChanges for aces is undefined if the newValue becomes oldValue again.');
  
  var aclService = new SecurityAcl.Service();
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  var acl = aclService.createAcl(oid);
  
  aclService.propertyChanged(acl,'propertyName', 'oldValue', 'oldValue');
  
  test.isUndefined(aclService._propertyChanges[acl.id()]['propertyName'], 'propertyChanges for propertyName is undefined if the newValue is the same oldValue.');
  
  aclService.propertyChanged(acl,'propertyName', 'oldValue', 'newValue');
  
  test.equal(aclService._propertyChanges[acl.id()]['propertyName'][0], 'oldValue', 'propertyChanges has a propertyName for the ACL with oldValue.');
  test.equal(aclService._propertyChanges[acl.id()]['propertyName'][1], 'newValue', 'propertyChanges has a propertyName for the ACL with newValue.');
  
  aclService.propertyChanged(acl,'propertyName', 'newValue', 'oldValue');
  
  test.isUndefined(aclService._propertyChanges[acl.id()]['propertyName'], 'propertyChanges for propertyName is undefined if the newValue becomes oldValue again.');
  
  
});

Tinytest.add('AclService - _updateOldAceProperty', function (test) {
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  // data fixtures
  var aclService = new SecurityAcl.Service();
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  var acl = aclService.createAcl(oid);
  
  SecurityAcl.SecurityIdentities.insert({
    identifier: '/test/user/1',
    username: true,
  });
  
  var sid = SecurityAcl.SecurityIdentities.findOne({ identifier: '/test/user/1' });
  
  var dbClass = SecurityAcl.Classes.findOne({ classType: oid.type() });
  
  SecurityAcl.Entries.insert({
    classId: dbClass._id,
    objectIdentityId: null,
    securityIdentityId: sid._id,
    fieldName: null,
    aceOrder: 0,
    mask: 32,
    granting: true,
    grantingStrategy: 'all',
    auditSuccess: false,
    auditFailure: false,
  });
  
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  var dbEntry = SecurityAcl.Entries.findOne({ mask: 32 });
  var entry = new SecurityAcl.Entry(dbEntry._id, acl, sid, 'strategy', dbEntry.mask, true, false, false);
  aclService._loadedAces[entry.id()] = entry;
  
  var changes = [];
  var oldValue = {};
  oldValue[0] = entry;
  var newValue = {};
  changes[0] = oldValue;
  changes[1] = newValue;
  aclService._updateOldAceProperty('classAces', changes);
  
  test.isUndefined(SecurityAcl.Entries.findOne({  _id: dbEntry._id }), '_updateOldAceProperty removes the old entry if it doesn\'t exist anymore.');
  test.isUndefined(aclService._loadedAces[entry.id()], '_updateOldAceProperty removes the old entry in loadedAces array.');
  
});

Tinytest.add('AclService - _updateAces', function (test) {
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  // data fixtures
  var aclService = new SecurityAcl.Service();
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  var acl = aclService.createAcl(oid);
  
  SecurityAcl.SecurityIdentities.insert({
    identifier: '/test/user/1',
    username: 'user1'
  });
  
  var sid = SecurityAcl.SecurityIdentities.findOne({ username: 'user1' });
  var dbClass = SecurityAcl.Classes.findOne({ classType: oid.type() });
  
  SecurityAcl.Entries.insert({
    classId: dbClass._id,
    objectIdentityId: null,
    securityIdentityId: sid._id,
    fieldName: null,
    aceOrder: 0,
    mask: 32,
    granting: true,
    grantingStrategy: 'all',
    auditSuccess: false,
    auditFailure: false,
  });
  
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  var dbEntry = SecurityAcl.Entries.findOne({ mask: 32 });
  
  
  var ace = new SecurityAcl.Entry(dbEntry._id, acl, sid, 'strategy', 64, true, false, false);
  var aces = {};
  aces[ace.id()] = {};
  aces[ace.id()]['acePropertyChanges'] = {};
  aces[ace.id()]['acePropertyChanges']['mask'] = [32, 64];
  aces[ace.id()]['ace'] = ace;
  aclService._updateAces(aces);
  
  test.equal(SecurityAcl.Entries.findOne({ _id: dbEntry._id }).mask, 64, '_updateAces updates correctly the mask.');
  
  
});

Tinytest.add('AclService - _updateNewAceProperty', function (test) {
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  // data fixtures
  var aclService = new SecurityAcl.Service();
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  var acl = aclService.createAcl(oid);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  var entry = new SecurityAcl.Entry('id', acl, sid, 'strategy', 32, true, false, false);
  var changes = [];
  var oldValue = {};
  var newValue = {};
  
  newValue[0] = entry;
  changes[0] = oldValue;
  changes[1] = newValue;
  
  aclService._updateNewAceProperty('classAces', changes);
  
  test.isUndefined(SecurityAcl.Entries.findOne(), 'updateNewAceProperty doesn\'t create entry if ace id is not null.');
  
  var entry = new SecurityAcl.Entry(null, acl, sid, 'strategy', 32, true, false, false);
  var changes = [];
  var oldValue = {};
  var newValue = {};
  
  newValue[0] = entry;
  changes[0] = oldValue;
  changes[1] = newValue;
  
  aclService._updateNewAceProperty('classAces', changes);
  
  var result = SecurityAcl.Entries.findOne();
  
  test.equal(result['mask'], 32, 'updateNewAceProperty creates the entry (classAces).');
  test.equal(result['objectIdentityId'], null, 'updateNewAceProperty creates the entry (classAces).');
  test.equal(result['securityIdentityId'], SecurityAcl.SecurityIdentities.findOne()._id, 'updateNewAceProperty creates the sid of ACE.');
  test.equal(result['aceOrder'], 0, 'updateNewAceProperty creates the entry with aceOrder 0.');
  test.equal(result['fieldName'], null, 'updateNewAceProperty creates the entry (classAces).');
  test.equal(result['grantingStrategy'], 'strategy', 'updateNewAceProperty creates the entry (classAces).');
  test.equal(result['granting'], true, 'updateNewAceProperty creates the entry (classAces).');
  test.equal(result['auditSuccess'], false, 'updateNewAceProperty creates the entry (classAces).');
  test.equal(result['auditFailure'], false, 'updateNewAceProperty creates the entry (classAces).');
  
  test.equal(aclService._loadedAces[result._id]._id, result._id, 'updateNewAceProperty updates loadedAces in the service.');
  test.equal(aclService._loadedAces[result._id]._mask, 32, 'updateNewAceProperty updates loadedAces in the service.');
  
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var entry = new SecurityAcl.Entry(null, acl, sid, 'strategy', 32, true, false, false);
  var changes = [];
  var oldValue = {};
  var newValue = {};
  
  newValue[0] = entry;
  changes[0] = oldValue;
  changes[1] = newValue;
  
  aclService._updateNewAceProperty('objectAces', changes);
  
  var result = SecurityAcl.Entries.findOne();
  
  test.equal(result['objectIdentityId'], acl.id(), 'updateNewAceProperty creates the entry (objectAces).');
  
  
});

Tinytest.add('AclService - _updateOldFieldAceProperty', function (test) {
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  // data fixtures
  var aclService = new SecurityAcl.Service();
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  var acl = aclService.createAcl(oid);
  
  SecurityAcl.SecurityIdentities.insert({
    identifier: '/test/user/1',
    username: true,
  });
  
  var sid = SecurityAcl.SecurityIdentities.findOne({ identifier: '/test/user/1' });
  
  var dbClass = SecurityAcl.Classes.findOne({ classType: oid.type() });
  
  SecurityAcl.Entries.insert({
    classId: dbClass._id,
    objectIdentityId: null,
    securityIdentityId: sid._id,
    fieldName: 'field',
    aceOrder: 0,
    mask: 32,
    granting: true,
    grantingStrategy: 'all',
    auditSuccess: false,
    auditFailure: false,
  });
  
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  var dbEntry = SecurityAcl.Entries.findOne({ mask: 32 });
  var fieldEntry = new SecurityAcl.FieldEntry (dbEntry._id, acl, dbEntry.fieldName, sid, 'strategy', dbEntry.mask, true, false, false);
  
  aclService._loadedAces[fieldEntry.id()] = fieldEntry;
  
  var changes = [];
  var oldValue = {};
  oldValue[fieldEntry.field()] = {};
  oldValue[fieldEntry.field()][dbEntry.aceOrder] = fieldEntry;
  var newValue = {};
  changes[0] = oldValue;
  changes[1] = newValue;
  aclService._updateOldFieldAceProperty('classFieldAces', changes);
  
  test.isUndefined(SecurityAcl.Entries.findOne({  _id: dbEntry._id }), '_updateOldFieldAceProperty removes the old entry if it doesn\'t exist anymore.');
  test.isUndefined(aclService._loadedAces[fieldEntry.id()], '_updateOldFieldAceProperty removes the old entry in loadedAces array.');
  
});

Tinytest.add('AclService - _updateNewFieldAceProperty', function (test) {
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  // data fixtures
  var aclService = new SecurityAcl.Service();
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  var acl = aclService.createAcl(oid);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  var fieldEntry = new SecurityAcl.FieldEntry ('id', acl, 'field', sid, 'strategy', 32, true, false, false);
  
  var changes = [];
  var oldValue = {};
  var newValue = {};
  
  newValue[fieldEntry.field()] = {};
  newValue[fieldEntry.field()][0] = fieldEntry;
  changes[0] = oldValue;
  changes[1] = newValue;
  
  aclService._updateNewFieldAceProperty('classFieldAces', changes);
  
  test.isUndefined(SecurityAcl.Entries.findOne(), 'updateNewFieldAceProperty doesn\'t create fieldEntry if ace id is not null.');
  
  var fieldEntry = new SecurityAcl.FieldEntry (null, acl, 'field', sid, 'strategy', 32, true, false, false);
  
  var changes = [];
  var oldValue = {};
  var newValue = {};
  
  newValue[fieldEntry.field()] = {};
  newValue[fieldEntry.field()][0] = fieldEntry;
  changes[0] = oldValue;
  changes[1] = newValue;
  
  aclService._updateNewFieldAceProperty('classFieldAces', changes);
  
  var result = SecurityAcl.Entries.findOne();
  
  test.equal(result['mask'], 32, 'updateNewFieldAceProperty creates the entry (classAces).');
  test.equal(result['objectIdentityId'], null, 'updateNewFieldAceProperty creates the entry (classAces).');
  test.equal(result['securityIdentityId'], SecurityAcl.SecurityIdentities.findOne()._id, 'updateNewFieldAceProperty creates the sid of ACE.');
  test.equal(result['aceOrder'], 0, 'updateNewFieldAceProperty creates the entry with aceOrder 0.');
  test.equal(result['fieldName'], 'field', 'updateNewFieldAceProperty creates the entry (classAces).');
  test.equal(result['grantingStrategy'], 'strategy', 'updateNewFieldAceProperty creates the entry (classAces).');
  test.equal(result['granting'], true, 'updateNewFieldAceProperty creates the entry (classAces).');
  test.equal(result['auditSuccess'], false, 'updateNewFieldAceProperty creates the entry (classAces).');
  test.equal(result['auditFailure'], false, 'updateNewFieldAceProperty creates the entry (classAces).');
  
  test.equal(aclService._loadedAces[result._id]._id, result._id, 'updateNewFieldAceProperty updates loadedAces in the service.');
  test.equal(aclService._loadedAces[result._id]._mask, 32, 'updateNewFieldAceProperty updates loadedAces in the service.');
  
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var fieldEntry = new SecurityAcl.FieldEntry (null, acl, 'field', sid, 'strategy', 32, true, false, false);
  
  var changes = [];
  var oldValue = {};
  var newValue = {};
  
  newValue[fieldEntry.field()] = {};
  newValue[fieldEntry.field()][0] = fieldEntry;
  changes[0] = oldValue;
  changes[1] = newValue;
  
  aclService._updateNewFieldAceProperty('objectFieldAces', changes);
  
  var result = SecurityAcl.Entries.findOne();
  
  test.equal(result['objectIdentityId'], acl.id(), 'updateNewFieldAceProperty creates the entry (objectFieldAces).');
  
});


Tinytest.add('AclService - deleteAcl', function (test) {
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  // data fixtures
  Posts.insert({
    text: 'test deleteAcl'
  });
  
  var post = Posts.findOne({ text: 'test deleteAcl'});
  
  var aclService = new SecurityAcl.Service();
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  var acl = aclService.createAcl(oid);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  
  acl.insertObjectAce(sid, 128);
  aclService.updateAcl(acl);
  
  test.equal(acl.id(), SecurityAcl.ObjectIdentities.findOne({ _id: acl.id() })._id, 'the ObjectIdentity exists in database.');
  test.equal(acl.id(), SecurityAcl.Entries.findOne({ objectIdentityId: acl.id() }).objectIdentityId, 'the ACE exists in database.');
  test.equal(acl.id(), SecurityAcl.ObjectIdentitiesAncestors.findOne({ objectIdentityId: acl.id() }).objectIdentityId, 'the ancestor exists in database.');
  test.notEqual('undefined', typeof aclService._propertyChanges[acl.id()], 'the propertyChange has ACL.');
  
  
  test.throws(function () {
    aclService.deleteAcl('invalidOid');
  }, 'The oid must be an instance of SecurityAcl.ObjectIdentity.');
  
  aclService.deleteAcl(oid);
  
  test.isUndefined(SecurityAcl.ObjectIdentities.findOne({ _id: acl.id() }), 'the ObjectIdentity is removed from the database.');
  test.isUndefined(SecurityAcl.Entries.findOne({ objectIdentityId: acl.id() }), 'the ACE is removed from the database.');
  test.isUndefined(SecurityAcl.ObjectIdentitiesAncestors.findOne({ objectIdentityId: acl.id() }), 'the ancestor is removed from the database.');
  test.equal('undefined', typeof aclService._propertyChanges[acl.id()], 'the propertyChange has not ACL anymore.');
  
});


Tinytest.add('AclService - updateAcls', function (test) {
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  // data fixtures
  Posts.insert({
    text: 'test1 updateAcls'
  });
  
  Posts.insert({
    text: 'test2 updateAcls'
  });
  
  var post1 = Posts.findOne({ text: 'test1 updateAcls'});
  
  var aclService = new SecurityAcl.Service();
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  var oid1 = SecurityAcl.objectIdentityFromDomainObject(post1);
  var acl1 = aclService.createAcl(oid1);
  
  acl1.insertObjectAce(sid, 128);
  
  var post2 = Posts.findOne({ text: 'test2 updateAcls'});
  var oid2 = SecurityAcl.objectIdentityFromDomainObject(post2);
  var acl2 = aclService.createAcl(oid2);
  
  acl2.insertObjectAce(sid, 64);
  
  aclService.updateAcls();
  
  test.equal(acl1.id(), SecurityAcl.Entries.findOne({ objectIdentityId: acl1.id() }).objectIdentityId, 'All ACLs were updated.');
  test.equal(acl2.id(), SecurityAcl.Entries.findOne({ objectIdentityId: acl2.id() }).objectIdentityId, 'All ACLs were updated.');
  
});


Tinytest.add('AclService - deleteSecurityIdentity', function (test) {
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  // data fixtures
  Posts.insert({
    text: 'test deleteSecurityIdentity'
  });
  
  var post = Posts.findOne({ text: 'test deleteSecurityIdentity'});
  
  var aclService = new SecurityAcl.Service();
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  var acl = aclService.createAcl(oid);
  
  acl.insertObjectAce(sid, 128);
  aclService.updateAcl(acl);
  
  test.equal(acl.id(), SecurityAcl.Entries.findOne({ objectIdentityId: acl.id() }).objectIdentityId, 'the ACE exists in database.');
  test.equal('className-username', SecurityAcl.SecurityIdentities.findOne().identifier, 'the sid exists in database.');
  
  test.throws(function () {
    aclService.deleteSecurityIdentity('invalid-sid');
  }, 'The sid must be an instance of SecurityAcl.SecurityIdentity');
  
  aclService.deleteSecurityIdentity(sid);
  
  test.isUndefined(SecurityAcl.Entries.findOne(), 'the entry of sid is deleted from the database.');
  test.isUndefined(SecurityAcl.SecurityIdentities.findOne(), 'the sid is deleted from the database.');
  
  
  
});