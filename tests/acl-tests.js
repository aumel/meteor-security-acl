

Tinytest.add('SecurityAcl - Acl', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  //data fixtures
  Posts.insert({
    text: 'test Acl'
  });
  
  var post = Posts.findOne({ 'text': 'test Acl' });
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  var permissionGrantingStrategy = new SecurityAcl.PermissionGrantingStrategy();
  var emptyArray = [];
  var entriesInheriting = true;
  
  test.throws(function () {
    SecurityAcl.Acl();
  }, 'Use "new" to construct a SecurityAcl.Acl');
  
  test.throws(function () {
    new SecurityAcl.Acl(null, oid, permissionGrantingStrategy, emptyArray, entriesInheriting);
  }, 'The id cannot be null or undefined.');
  
  test.throws(function () {
    new SecurityAcl.Acl('id', 'invalidOid', permissionGrantingStrategy, emptyArray, entriesInheriting);
  }, 'The oid must be an instance of SecurityAcl.ObjectIdentity.');
  
  test.throws(function () {
    new SecurityAcl.Acl('id', oid, 'invalidStrategy', emptyArray, entriesInheriting);
  }, 'The permissionGrantingStrategy must be an instance of SecurityAcl.PermissionGrantingStrategy.');
  
  test.throws(function () {
    new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, 'invalidArray', entriesInheriting);
  }, 'The loadedSids must be an array.');
  
  test.throws(function () {
    new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, emptyArray, 'invalid');
  }, 'The entriesInheriting must be a boolean.');
  
  
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, emptyArray, true);
  
  test.equal(acl.id(), 'id', 'The ACL id is ok.');
  test.isTrue(acl.objectIdentity().equals(oid), "Acl returns the right Oid.");
  
  // Test setParentAcl 
  test.throws(function () {
    acl.setParentAcl('invalidAcl');
  }, 'The acl must be an instance of SecurityAcl.Acl.');
  
  var parentAcl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, emptyArray, true);
  parentAcl._id = null;
  
  test.throws(function () {
    acl.setParentAcl(parentAcl);
  }, 'The acl cannot be null and the id must be defined.');
  
  var parentAcl = new SecurityAcl.Acl('idParentAcl', oid, permissionGrantingStrategy, emptyArray, true);
  acl.setParentAcl(parentAcl);
  
  test.equal(acl.parentAcl().id(), 'idParentAcl', 'The parentAcl method returns the parent ACL.');
  test.equal(acl.parentAcl(), parentAcl, 'The parentAcl method returns the parent ACL.');
  
  // Test setClassAces/classAces 
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, emptyArray, true);
  
  acl.setClassAces('classAces');
  
  test.equal(acl.classAces(), 'classAces', 'setClassAces and classAces methods set and get value for classAces.');
  
  // Test setClassFieldAces/classFieldAces 
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, emptyArray, true);
  
  test.equal(acl.classFieldAces('field'), [], 'classFieldAces method returns an array if no classFieldAces.');
  
  var classFieldAces = {};
  classFieldAces['field'] = true;
  
  acl.setClassFieldAces(classFieldAces);
  
  test.equal(acl.classFieldAces('field'), true, 'setClassFieldAces and classFieldAces methods set and get value for classFieldAces.');
  
  // Test setObjectAces/objectAces 
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, emptyArray, true);
  
  acl.setObjectAces('objectAces');
  
  test.equal(acl.objectAces(), 'objectAces', 'setObjectAces and objectAces methods set and get value for objectAces.');
  
  // Test setObjectFieldAces/objectFieldAces 
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, emptyArray, true);
  
  test.equal(acl.objectFieldAces('field'), [], 'objectFieldAces method returns an array if no objectFieldAces.');
  
  var objectFieldAces = {};
  objectFieldAces['field'] = true;
  
  acl.setObjectFieldAces(objectFieldAces);
  
  test.equal(acl.objectFieldAces('field'), true, 'setObjectFieldAces and objectFieldAces methods set and get value for objectFieldAces.');
  
  
  // Test isSidLoaded
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, emptyArray, true);
  
  test.throws(function () {
    acl.isSidLoaded();
  }, 'Sid must be an instance of SecurityAcl.SecurityIdentity.');
  
  test.throws(function () {
    acl.isSidLoaded(['invalidSids']);
  }, 'Sid must be an instance of SecurityAcl.SecurityIdentity.');
  
  test.isTrue(acl.isSidLoaded([]), 'If parameter is an empty array, isSidLoaded returns true.');
  
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [sid], true);
  test.isTrue(acl.isSidLoaded([sid]), 'isSidLoaded returns true if sid is loaded in the ACL (array with one sid for parameter).');
  test.isTrue(acl.isSidLoaded(sid), 'isSidLoaded returns true if sid is loaded in the ACL (sid parameter).');
  
  var sid2 = new SecurityAcl.UserSecurityIdentity('username2', 'className');
  test.isFalse(acl.isSidLoaded([sid2]), 'isSidLoaded returns false if sid is not loaded in the ACL.');
  
  var sid1 = new SecurityAcl.UserSecurityIdentity('username1', 'className');
  var sid2 = new SecurityAcl.UserSecurityIdentity('username2', 'className');
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [sid1, sid2], true);
  test.isTrue(acl.isSidLoaded([sid2]), 'isSidLoaded returns true if sid is loaded in the ACL (array of sids for parameter).');
  
  var sid3 = new SecurityAcl.UserSecurityIdentity('username3', 'className');
  test.isFalse(acl.isSidLoaded([sid3]), 'isSidLoaded returns false if sid is not loaded in the ACL.');
  
  // Test addPropertyChangedListener
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [sid], true);
  
  test.throws(function () {
    acl.addPropertyChangedListener('invalid-acl-service');
  }, 'The argument must be an instance of SecurityAcl.Service.');
  
  var aclService = new SecurityAcl.Service();
  acl.addPropertyChangedListener(aclService);
  
  test.equal(acl._listeners[0], aclService, 'The listener is set up correctly.');
  
  // Test onPropertyChanged
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [sid], true);
  
  var aclService = new SecurityAcl.Service();
  aclService._propertyChanges[acl.id()] = {}; // the service must track the ACL.
  acl.addPropertyChangedListener(aclService);
  acl.setEntriesInheriting(false);
  
  test.equal(aclService._propertyChanges[acl.id()]['entriesInheriting'][0], true, 'The aclService tracks the changes correctly.');
  test.equal(aclService._propertyChanges[acl.id()]['entriesInheriting'][1], false, 'The aclService tracks the changes correctly.');
  
  var acl2 = new SecurityAcl.Acl('id2', oid, permissionGrantingStrategy, [sid], true);
  acl.setParentAcl(acl2);
  
  test.equal(aclService._propertyChanges[acl.id()]['parentAcl'][0], null, 'The aclService tracks the changes correctly.');
  test.equal(aclService._propertyChanges[acl.id()]['parentAcl'][1], acl2, 'The aclService tracks the changes correctly.');
  
  // Test insertClassAce
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [sid], true);
  var aclService = new SecurityAcl.Service();
  aclService._propertyChanges[acl.id()] = {}; // the service must track the ACL.
  acl.addPropertyChangedListener(aclService);
  
  test.throws(function () {
    acl.insertClassAce('invalid-sid', 32, 0);
  }, 'The sid must be an instance of SecurityAcl.SecurityIdentity.');
  
  test.throws(function () {
    acl.insertClassAce(sid, 32, '0');
  }, 'The index must be an integer.');
  
  test.throws(function () {
    acl.insertClassAce(sid, 32, -1);
  }, 'The index must be in the interval');
  
  test.throws(function () {
    acl.insertClassAce(sid, 32, 1);
  }, 'The index must be in the interval');
  
  test.throws(function () {
    acl.insertClassAce(sid, 'invalid-mask', 0);
  }, 'The mask must be an integer.');
  
  test.throws(function () {
    acl.insertClassAce(sid, 3.5, 0);
  }, 'The mask must be an integer.');
  
  acl.insertClassAce(sid, 32, 0);
  
  test.equal(Object.keys(acl._classAces).length, 1, 'There is 1 class ACE.');
  test.equal(acl._classAces[0]._mask, 32, 'The ACE has a mask 32.');
  
  test.equal(aclService._propertyChanges[acl.id()]['classAces'].length, 2, 'There are changes in the listener.');
  test.equal(aclService._propertyChanges[acl.id()]['classAces'][0], {}, 'The old value is an empty object.');
  test.equal(Object.keys(aclService._propertyChanges[acl.id()]['classAces'][1]).length, 1, 'There is one ACE.');
  test.equal(aclService._propertyChanges[acl.id()]['classAces'][1][0]['_mask'], 32, 'ACE with a mask 32.');
  test.isTrue(typeof aclService._propertyChanges[acl.id()]['classAces'][1][0], SecurityAcl.Entry, 'The listener tracks correctly the ACE.');
  
  acl.insertClassAce(sid, 64, 0);
  
  test.equal(Object.keys(acl._classAces).length, 2, 'There are 2 class ACES.');
  test.equal(acl._classAces[0]._mask, 64, 'The first ACE has a mask 64.');
  test.equal(acl._classAces[1]._mask, 32, 'The second ACE has a mask 32.');
  
  test.equal(aclService._propertyChanges[acl.id()]['classAces'].length, 2, 'There are changes in the listener.');
  test.equal(aclService._propertyChanges[acl.id()]['classAces'][0], {}, 'The original old value is an empty object.');
  test.equal(Object.keys(aclService._propertyChanges[acl.id()]['classAces'][1]).length, 2, 'There are two ACEs.');
  test.equal(aclService._propertyChanges[acl.id()]['classAces'][1][0]['_mask'], 64, 'ACE with a mask 64.');
  test.isTrue(typeof aclService._propertyChanges[acl.id()]['classAces'][1][0], SecurityAcl.Entry, 'The listener tracks correctly the ACE.');
  test.equal(aclService._propertyChanges[acl.id()]['classAces'][1][1]['_mask'], 32, 'ACE with a mask 32.');
  
  test.isUndefined(aclService._propertyChanges[acl.id()]['aces'], 'There is no property aces because the entry id is null.');
  
  
  // test insertClassAce with an existing ACE from database
  
  // data fixtures
  var aclService = new SecurityAcl.Service();
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  aclService.createAcl(oid);
  
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
  
  var aclService = new SecurityAcl.Service();
  var acl = aclService.findAcl(oid, []);
  
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  
  acl.insertClassAce(sid, 64, 0);
  
  var oldValue = aclService._propertyChanges[acl.id()]['classAces'][0][0];
  
  test.equal(oldValue._mask, 32, 'The mask of oldValue for ACE is 32.');
  
  var newAce = aclService._propertyChanges[acl.id()]['classAces'][1][0];
  
  test.equal(newAce._mask, 64, 'The mask of ACE is 64.');
  test.isUndefined(aclService._propertyChanges[acl.id()]['aces'][newAce._id], 'There is no propertyChanges for a new ACE.');
  
  var modifiedAce = aclService._propertyChanges[acl.id()]['classAces'][1][1];
  
  test.equal(modifiedAce._mask, 32, 'The mask of ACE is 32.');
  test.equal(aclService._propertyChanges[acl.id()]['aces'][modifiedAce._id]['acePropertyChanges']['aceOrder'], [0,1], 'There is a propertyChanges aceOrder for an existing ACE.');
  
  // Test insertClassFieldAce
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [sid], true);
  var aclService = new SecurityAcl.Service();
  aclService._propertyChanges[acl.id()] = {}; // the service must track the ACL.
  acl.addPropertyChangedListener(aclService);
  
  test.throws(function () {
    acl.insertClassFieldAce('', sid, 32, 0);
  }, 'Field cannot be empty.');
  
  test.throws(function () {
    acl.insertClassFieldAce('field', 'invalid-sid', 32, 0);
  }, 'The sid must be an instance of SecurityAcl.SecurityIdentity.');
  
  test.throws(function () {
    acl.insertClassFieldAce('field', sid, 'invalid-mask', 0);
  }, 'The mask must be an integer.');
  
  test.throws(function () {
    acl.insertClassFieldAce('field', sid, 32, 'invalid-index');
  }, 'The index must be an integer.');
  
  test.throws(function () {
    acl.insertClassFieldAce('field', sid, 32, -1);
  }, 'The index must be in the interval');
  
  test.throws(function () {
    acl.insertClassFieldAce('field', sid, 32, 1);
  }, 'The index must be in the interval');
  
  acl.insertClassFieldAce('field', sid, 32, 0);
  
  test.equal(Object.keys(acl._classFieldAces['field']).length, 1, 'There is 1 class ACE.');
  test.equal(acl._classFieldAces['field'][0]._mask, 32, 'The ACE has a mask 32.');
  
  test.equal(aclService._propertyChanges[acl.id()]['classFieldAces'].length, 2, 'There are changes in the listener.');
  test.equal(aclService._propertyChanges[acl.id()]['classFieldAces'][0]['field'], {}, 'The old value is a field key with an empty object.');
  test.equal(Object.keys(aclService._propertyChanges[acl.id()]['classFieldAces'][1]).length, 1, 'There is one ACE.');
  test.equal(aclService._propertyChanges[acl.id()]['classFieldAces'][1]['field'][0]['_mask'], 32, 'ACE with a mask 32.');
  test.isTrue(typeof aclService._propertyChanges[acl.id()]['classFieldAces'][1]['field'][0], SecurityAcl.Entry, 'The listener tracks correctly the ACE.');
  
  acl.insertClassFieldAce('field', sid, 64, 0);
  
  test.equal(Object.keys(acl._classFieldAces['field']).length, 2, 'There are 2 class ACES.');
  test.equal(acl._classFieldAces['field'][0]._mask, 64, 'The first ACE has a mask 64.');
  test.equal(acl._classFieldAces['field'][1]._mask, 32, 'The second ACE has a mask 32.');
  
  test.equal(aclService._propertyChanges[acl.id()]['classFieldAces'].length, 2, 'There are changes in the listener.');
  test.equal(aclService._propertyChanges[acl.id()]['classFieldAces'][0]['field'], {}, 'The original old value is a field key with an empty object.');
  test.equal(Object.keys(aclService._propertyChanges[acl.id()]['classFieldAces'][1]['field']).length, 2, 'There are two ACEs.');
  test.equal(aclService._propertyChanges[acl.id()]['classFieldAces'][1]['field'][0]['_mask'], 64, 'ACE with a mask 64.');
  test.isTrue(typeof aclService._propertyChanges[acl.id()]['classFieldAces'][1]['field'][0], SecurityAcl.Entry, 'The listener tracks correctly the ACE.');
  test.equal(aclService._propertyChanges[acl.id()]['classFieldAces'][1]['field'][1]['_mask'], 32, 'ACE with a mask 32.');
  test.isUndefined(aclService._propertyChanges[acl.id()]['aces'], 'There is no property aces because the entry id is null.');
  
  // Test insertClassFieldAce with an existing ACE from database
  
  // data fixtures
  var aclService = new SecurityAcl.Service();
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  aclService.createAcl(oid);
  
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
    fieldName: 'field',
    aceOrder: 0,
    mask: 32,
    granting: true,
    grantingStrategy: 'all',
    auditSuccess: false,
    auditFailure: false,
  });
  
  var aclService = new SecurityAcl.Service();
  var acl = aclService.findAcl(oid, []);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  
  acl.insertClassFieldAce('field', sid, 64, 0);
  
  var oldValue = aclService._propertyChanges[acl.id()]['classFieldAces'][0]['field'][0];
  
  test.equal(oldValue._mask, 32, 'The mask of oldValue for ACE is 32.');
  
  var newAce = aclService._propertyChanges[acl.id()]['classFieldAces'][1]['field'][0];
  
  test.equal(newAce._mask, 64, 'The mask of ACE is 64.');
  test.isUndefined(aclService._propertyChanges[acl.id()]['aces'][newAce._id], 'There is no propertyChanges for a new ACE.');
  
  var modifiedAce = aclService._propertyChanges[acl.id()]['classFieldAces'][1]['field'][1];
  
  test.equal(modifiedAce._mask, 32, 'The mask of ACE is 32.');
  test.equal(aclService._propertyChanges[acl.id()]['aces'][modifiedAce._id]['acePropertyChanges']['aceOrder'], [0,1], 'There is a propertyChanges aceOrder for an existing ACE.');
  
  // Test insertObjectAce
  
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [sid], true);
  var aclService = new SecurityAcl.Service();
  aclService._propertyChanges[acl.id()] = {}; // the service must track the ACL.
  acl.addPropertyChangedListener(aclService);
  
  test.throws(function () {
    acl.insertObjectAce('invalid-sid', 32, 0);
  }, 'The sid must be an instance of SecurityAcl.SecurityIdentity.');
  
  test.throws(function () {
    acl.insertObjectAce(sid, 32, '0');
  }, 'The index must be an integer.');
  
  test.throws(function () {
    acl.insertObjectAce(sid, 32, -1);
  }, 'The index must be in the interval');
  
  test.throws(function () {
    acl.insertObjectAce(sid, 32, 1);
  }, 'The index must be in the interval');
  
  test.throws(function () {
    acl.insertObjectAce(sid, 'invalid-mask', 0);
  }, 'The mask must be an integer.');
  
  test.throws(function () {
    acl.insertObjectAce(sid, 3.5, 0);
  }, 'The mask must be an integer.');
  
  
  acl.insertObjectAce(sid, 32, 0);
  
  test.equal(Object.keys(acl._objectAces).length, 1, 'There is 1 object ACE.');
  test.equal(acl._objectAces[0]._mask, 32, 'The ACE has a mask 32.');
  
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'].length, 2, 'There are changes in the listener.');
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'][0], {}, 'The old value is an empty object.');
  test.equal(Object.keys(aclService._propertyChanges[acl.id()]['objectAces'][1]).length, 1, 'There is one ACE.');
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'][1][0]['_mask'], 32, 'ACE with a mask 32.');
  test.isTrue(typeof aclService._propertyChanges[acl.id()]['objectAces'][1][0], SecurityAcl.Entry, 'The listener tracks correctly the ACE.');
  

  acl.insertObjectAce(sid, 64, 0);
  
  test.equal(Object.keys(acl._objectAces).length, 2, 'There are 2 object ACES.');
  test.equal(acl._objectAces[0]._mask, 64, 'The first ACE has a mask 64.');
  test.equal(acl._objectAces[1]._mask, 32, 'The second ACE has a mask 32.');
  
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'].length, 2, 'There are changes in the listener.');
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'][0], {}, 'The original old value is an empty object.');
  test.equal(Object.keys(aclService._propertyChanges[acl.id()]['objectAces'][1]).length, 2, 'There are two ACEs.');
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'][1][0]['_mask'], 64, 'ACE with a mask 64.');
  test.isTrue(typeof aclService._propertyChanges[acl.id()]['objectAces'][1][0], SecurityAcl.Entry, 'The listener tracks correctly the ACE.');
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'][1][1]['_mask'], 32, 'ACE with a mask 32.');
  
  test.isUndefined(aclService._propertyChanges[acl.id()]['aces'], 'There is no property aces because the entry id is null.');
  
  // Test insertObjectAce with an existing ACE from database
  
  // remove all data in database before testing.
  SecurityAclTestHelpers.cleanUpDatabase();
  
  // data fixtures
  var aclService = new SecurityAcl.Service();
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  aclService.createAcl(oid);
  
  SecurityAcl.SecurityIdentities.insert({
    identifier: '/test/user/1',
    username: 'user1'
  });
  
  var sid = SecurityAcl.SecurityIdentities.findOne({ username: 'user1' });
  var dbClass = SecurityAcl.Classes.findOne({ classType: oid.type() });
  
  SecurityAcl.Entries.insert({
    classId: dbClass._id,
    objectIdentityId: SecurityAcl.ObjectIdentities.findOne()._id,
    securityIdentityId: sid._id,
    fieldName: null,
    aceOrder: 0,
    mask: 32,
    granting: true,
    grantingStrategy: 'all',
    auditSuccess: false,
    auditFailure: false,
  });
  
  var aclService = new SecurityAcl.Service();
  var acl = aclService.findAcl(oid, []);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  
  acl.insertObjectAce(sid, 64, 0);
  
  var oldValue = aclService._propertyChanges[acl.id()]['objectAces'][0][0];
  
  test.equal(oldValue._mask, 32, 'The mask of oldValue for ACE is 32.');
  
  var newAce = aclService._propertyChanges[acl.id()]['objectAces'][1][0];
  
  test.equal(newAce._mask, 64, 'The mask of ACE is 64.');
  test.isUndefined(aclService._propertyChanges[acl.id()]['aces'][newAce._id], 'There is no propertyChanges for a new ACE.');
  
  var modifiedAce = aclService._propertyChanges[acl.id()]['objectAces'][1][1];
  
  test.equal(modifiedAce._mask, 32, 'The mask of ACE is 32.');
  test.equal(aclService._propertyChanges[acl.id()]['aces'][modifiedAce._id]['acePropertyChanges']['aceOrder'], [0,1], 'There is a propertyChanges aceOrder for an existing ACE.');
  
  // Test insertObjectFieldAce
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [sid], true);
  var aclService = new SecurityAcl.Service();
  aclService._propertyChanges[acl.id()] = {}; // the service must track the ACL.
  acl.addPropertyChangedListener(aclService);
  
  test.throws(function () {
    acl.insertObjectFieldAce('', sid, 32, 0);
  }, 'Field cannot be empty.');
  
  test.throws(function () {
    acl.insertObjectFieldAce('field', 'invalid-sid', 32, 0);
  }, 'The sid must be an instance of SecurityAcl.SecurityIdentity.');
  
  test.throws(function () {
    acl.insertObjectFieldAce('field', sid, 'invalid-mask', 0);
  }, 'The mask must be an integer.');
  
  test.throws(function () {
    acl.insertObjectFieldAce('field', sid, 32, 'invalid-index');
  }, 'The index must be an integer.');
  
  test.throws(function () {
    acl.insertObjectFieldAce('field', sid, 32, -1);
  }, 'The index must be in the interval');
  
  test.throws(function () {
    acl.insertObjectFieldAce('field', sid, 32, 1);
  }, 'The index must be in the interval');
  
  acl.insertObjectFieldAce('field', sid, 32, 0);
  
  test.equal(Object.keys(acl._objectFieldAces['field']).length, 1, 'There is 1 class ACE.');
  test.equal(acl._objectFieldAces['field'][0]._mask, 32, 'The ACE has a mask 32.');
  
  test.equal(aclService._propertyChanges[acl.id()]['objectFieldAces'].length, 2, 'There are changes in the listener.');
  test.equal(aclService._propertyChanges[acl.id()]['objectFieldAces'][0]['field'], {}, 'The old value is a field key with an empty object.');
  test.equal(Object.keys(aclService._propertyChanges[acl.id()]['objectFieldAces'][1]).length, 1, 'There is one ACE.');
  test.equal(aclService._propertyChanges[acl.id()]['objectFieldAces'][1]['field'][0]['_mask'], 32, 'ACE with a mask 32.');
  test.isTrue(typeof aclService._propertyChanges[acl.id()]['objectFieldAces'][1]['field'][0], SecurityAcl.Entry, 'The listener tracks correctly the ACE.');
  
  acl.insertObjectFieldAce('field', sid, 64, 0);
  
  test.equal(Object.keys(acl._objectFieldAces['field']).length, 2, 'There are 2 class ACES.');
  test.equal(acl._objectFieldAces['field'][0]._mask, 64, 'The first ACE has a mask 64.');
  test.equal(acl._objectFieldAces['field'][1]._mask, 32, 'The second ACE has a mask 32.');
  
  test.equal(aclService._propertyChanges[acl.id()]['objectFieldAces'].length, 2, 'There are changes in the listener.');
  test.equal(aclService._propertyChanges[acl.id()]['objectFieldAces'][0]['field'], {}, 'The original old value is a field key with an empty object.');
  test.equal(Object.keys(aclService._propertyChanges[acl.id()]['objectFieldAces'][1]['field']).length, 2, 'There are two ACEs.');
  test.equal(aclService._propertyChanges[acl.id()]['objectFieldAces'][1]['field'][0]['_mask'], 64, 'ACE with a mask 64.');
  test.isTrue(typeof aclService._propertyChanges[acl.id()]['objectFieldAces'][1]['field'][0], SecurityAcl.Entry, 'The listener tracks correctly the ACE.');
  test.equal(aclService._propertyChanges[acl.id()]['objectFieldAces'][1]['field'][1]['_mask'], 32, 'ACE with a mask 32.');
  test.isUndefined(aclService._propertyChanges[acl.id()]['aces'], 'There is no property aces because the entry id is null.');
  
  // Test insertObjectFieldAce with an existing ACE from database
  
  // data fixtures
  var aclService = new SecurityAcl.Service();
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  aclService.createAcl(oid);
  
  SecurityAcl.SecurityIdentities.insert({
    identifier: '/test/user/1',
    username: 'user1'
  });
  
  var sid = SecurityAcl.SecurityIdentities.findOne({ username: 'user1' });
  var dbClass = SecurityAcl.Classes.findOne({ classType: oid.type() });
  
  SecurityAcl.Entries.insert({
    classId: dbClass._id,
    objectIdentityId: SecurityAcl.ObjectIdentities.findOne()._id,
    securityIdentityId: sid._id,
    fieldName: 'field',
    aceOrder: 0,
    mask: 32,
    granting: true,
    grantingStrategy: 'all',
    auditSuccess: false,
    auditFailure: false,
  });
  
  var aclService = new SecurityAcl.Service();
  var acl = aclService.findAcl(oid, []);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  
  acl.insertObjectFieldAce('field', sid, 64, 0);
  
  var oldValue = aclService._propertyChanges[acl.id()]['objectFieldAces'][0]['field'][0];
  
  test.equal(oldValue._mask, 32, 'The mask of oldValue for ACE is 32.');
  
  var newAce = aclService._propertyChanges[acl.id()]['objectFieldAces'][1]['field'][0];
  
  test.equal(newAce._mask, 64, 'The mask of ACE is 64.');
  test.isUndefined(aclService._propertyChanges[acl.id()]['aces'][newAce._id], 'There is no propertyChanges for a new ACE.');
  
  var modifiedAce = aclService._propertyChanges[acl.id()]['objectFieldAces'][1]['field'][1];
  
  test.equal(modifiedAce._mask, 32, 'The mask of ACE is 32.');
  test.equal(aclService._propertyChanges[acl.id()]['aces'][modifiedAce._id]['acePropertyChanges']['aceOrder'], [0,1], 'There is a propertyChanges aceOrder for an existing ACE.');
  
  
  // Test updateClassAce
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [sid], true);
  var aclService = new SecurityAcl.Service();
  aclService._propertyChanges[acl.id()] = {}; // the service must track the ACL.
  acl.addPropertyChangedListener(aclService);
  
  test.throws(function () {
    acl.updateClassAce('invalid-index', 32, 'strategy');
  }, 'The index must be an integer.');
  
  test.throws(function () {
    acl.updateClassAce(0, 32, 'strategy');
  }, 'The index 0 does not exist.');
  
  test.throws(function () {
    acl.updateClassAce(0, 'invalid-mask', 'strategy');
  }, 'The mask must be an integer.');
  
  acl.insertClassAce(sid, 32, 0);
  acl.updateClassAce(0, 64, null);
  
  test.equal(acl._classAces[0]._mask, 64, 'updateClassAce() updated the mask 64.');
  test.equal(acl._classAces[0]._strategy, 'ALL', 'the strategy of ACE is ALL.');
  
  test.equal(aclService._propertyChanges[acl.id()]['classAces'].length, 2, 'There are changes in the listener.');
  test.equal(aclService._propertyChanges[acl.id()]['classAces'][0], {}, 'The old value is an empty object.');
  test.equal(aclService._propertyChanges[acl.id()]['classAces'][1][0]['_mask'], 64, 'ACE with a mask 32.');
  
  acl.updateClassAce(0, 64, 'new strategy');
  
  test.equal(acl._classAces[0]._strategy, 'new strategy', 'the strategy of ACE is \'new strategy\'.');
  test.equal(aclService._propertyChanges[acl.id()]['classAces'][1][0]['_strategy'], 'new strategy', 'ACE with \'new strategy\'.');
  
  // Test updateClassFieldAce
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [sid], true);
  var aclService = new SecurityAcl.Service();
  aclService._propertyChanges[acl.id()] = {}; // the service must track the ACL.
  acl.addPropertyChangedListener(aclService);
  
  test.throws(function () {
    acl.updateClassFieldAce('invalid-index', 'field', 32, 'strategy');
  }, 'The index must be an integer.');
  
  test.throws(function () {
    acl.updateClassFieldAce(0, 'field', 32, 'strategy');
  }, 'The index 0 does not exist.');
  
  acl.insertClassFieldAce('field', sid, 64, 0);
  
  test.throws(function () {
    acl.updateClassFieldAce(0, 'invalid-field', 32, 'strategy');
  }, 'The index 0 does not exist.');
  
  test.throws(function () {
    acl.updateClassFieldAce(0, 'field', 'invalid-mask', 'strategy');
  }, 'The mask must be an integer.');
  
  acl.updateClassFieldAce(0, 'field', 32, null);
  
  test.equal(Object.keys(acl._classFieldAces['field']).length, 1, 'There is 1 class ACE.');
  test.equal(acl._classFieldAces['field'][0]._mask, 32, 'The ACE has a mask 32.');
  
  test.equal(acl._classFieldAces['field'][0]._strategy, 'ALL', 'the strategy of ACE is ALL.');
  
  acl.updateClassFieldAce(0, 'field', 32, 'new strategy');
  
  test.equal(acl._classFieldAces['field'][0]._strategy, 'new strategy', 'the strategy of ACE is \'new strategy\'.');
  test.equal(aclService._propertyChanges[acl.id()]['classFieldAces'][1]['field'][0]['_strategy'], 'new strategy', 'ACE with \'new strategy\'.');
  
  // Test updateObjectAce
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [sid], true);
  var aclService = new SecurityAcl.Service();
  aclService._propertyChanges[acl.id()] = {}; // the service must track the ACL.
  acl.addPropertyChangedListener(aclService);
  
  test.throws(function () {
    acl.updateObjectAce('invalid-index', 32, 'strategy');
  }, 'The index must be an integer.');
  
  test.throws(function () {
    acl.updateObjectAce(0, 32, 'strategy');
  }, 'The index 0 does not exist.');
  
  test.throws(function () {
    acl.updateObjectAce(0, 'invalid-mask', 'strategy');
  }, 'The mask must be an integer.');
  
  acl.insertObjectAce(sid, 32, 0);
  acl.updateObjectAce(0, 64, null);
  
  test.equal(acl._objectAces[0]._mask, 64, 'updateObjectAce() updated the mask 64.');
  test.equal(acl._objectAces[0]._strategy, 'ALL', 'the strategy of ACE is ALL.');
  
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'].length, 2, 'There are changes in the listener.');
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'][0], {}, 'The old value is an empty object.');
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'][1][0]['_mask'], 64, 'ACE with a mask 32.');
  
  acl.updateObjectAce(0, 64, 'new strategy');
  
  test.equal(acl._objectAces[0]._strategy, 'new strategy', 'the strategy of ACE is \'new strategy\'.');
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'][1][0]['_strategy'], 'new strategy', 'ACE with \'new strategy\'.');
  
  // Test updateObjectFieldAce
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [sid], true);
  var aclService = new SecurityAcl.Service();
  aclService._propertyChanges[acl.id()] = {}; // the service must track the ACL.
  acl.addPropertyChangedListener(aclService);
  
  test.throws(function () {
    acl.updateObjectFieldAce('invalid-index', 'field', 32, 'strategy');
  }, 'The index must be an integer.');
  
  test.throws(function () {
    acl.updateObjectFieldAce(0, 'field', 32, 'strategy');
  }, 'The index 0 does not exist.');
  
  acl.insertObjectFieldAce('field', sid, 64, 0);
  
  test.throws(function () {
    acl.updateObjectFieldAce(0, 'invalid-field', 32, 'strategy');
  }, 'The index 0 does not exist.');
  
  test.throws(function () {
    acl.updateObjectFieldAce(0, 'field', 'invalid-mask', 'strategy');
  }, 'The mask must be an integer.');
  
  acl.updateObjectFieldAce(0, 'field', 32, null);
  
  test.equal(Object.keys(acl._objectFieldAces['field']).length, 1, 'There is 1 object ACE.');
  test.equal(acl._objectFieldAces['field'][0]._mask, 32, 'The ACE has a mask 32.');
  
  test.equal(acl._objectFieldAces['field'][0]._strategy, 'ALL', 'the strategy of ACE is ALL.');
  
  acl.updateObjectFieldAce(0, 'field', 32, 'new strategy');
  
  test.equal(acl._objectFieldAces['field'][0]._strategy, 'new strategy', 'the strategy of ACE is \'new strategy\'.');
  test.equal(aclService._propertyChanges[acl.id()]['objectFieldAces'][1]['field'][0]['_strategy'], 'new strategy', 'ACE with \'new strategy\'.');
  
  // Test deleteClassAce
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [sid], true);
  var aclService = new SecurityAcl.Service();
  aclService._propertyChanges[acl.id()] = {}; // the service must track the ACL.
  acl.addPropertyChangedListener(aclService);
  
  test.throws(function () {
    acl.deleteClassAce('invalid-index');
  }, 'The index must be an integer.');
  
  test.throws(function () {
    acl.deleteClassAce(0);
  }, 'The index 0 does not exist.');
  
  acl.insertClassAce(sid, 32, 0);
  acl.deleteClassAce(0);
  
  test.equal(acl._classAces, {}, 'the ACL classAces is empty.');
  
  test.equal(aclService._propertyChanges[acl.id()]['classAces'][0], {}, 'The old value is an empty object.');
  test.equal(aclService._propertyChanges[acl.id()]['classAces'][1], {}, 'The new value is an empty object.');
  
  acl.insertClassAce(sid, 32, 0);
  acl.insertClassAce(sid, 64, 1);
  acl.insertClassAce(sid, 128, 2);
  acl.insertClassAce(sid, 256, 3);
  acl.deleteClassAce(1);
  
  test.equal(acl._classAces[0]._mask, 32, 'The mask of ACE with index 0 is 32.');
  test.equal(acl._classAces[1]._mask, 128, 'The mask of ACE with index 1 is 128.');
  test.equal(acl._classAces[2]._mask, 256, 'The mask of ACE with index 2 is 256.');
  test.equal(acl._classAces[3], undefined, 'The ACE with index 3 is undefined.');
  
  test.equal(aclService._propertyChanges[acl.id()]['classAces'][0], {}, 'The old value is an empty object.');
  test.equal(aclService._propertyChanges[acl.id()]['classAces'][1][0]['_mask'], 32, 'ACE with a mask 32.');
  test.equal(aclService._propertyChanges[acl.id()]['classAces'][1][1]['_mask'], 128, 'ACE with a mask 128.');
  test.equal(aclService._propertyChanges[acl.id()]['classAces'][1][2]['_mask'], 256, 'ACE with a mask 256.');
  
  // Test deleteClassFieldAce
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [sid], true);
  var aclService = new SecurityAcl.Service();
  aclService._propertyChanges[acl.id()] = {}; // the service must track the ACL.
  acl.addPropertyChangedListener(aclService);
  
  test.throws(function () {
    acl.deleteClassFieldAce('invalid-index', 'field');
  }, 'The index must be an integer.');
  
  test.throws(function () {
    acl.deleteClassFieldAce(0, '');
  }, 'Field cannot be empty.');
  
  test.throws(function () {
    acl.deleteClassFieldAce(0, 'field');
  }, 'The index 0 does not exist.');
  
  acl.insertClassFieldAce('field', sid, 32, 0);
  
  test.throws(function () {
    acl.deleteClassFieldAce(1, 'field');
  }, 'The index 1 does not exist.');
  
  acl.deleteClassFieldAce(0, 'field');
  
  test.equal(acl._classFieldAces['field'][0], undefined, 'the ACL classFieldAces is empty for field.');
  
  test.equal(aclService._propertyChanges[acl.id()]['classFieldAces'][0]['field'], {}, 'The old value is an empty object.');
  test.equal(aclService._propertyChanges[acl.id()]['classFieldAces'][1]['field'], {}, 'The new value is an empty object.');
  
  acl.insertClassFieldAce('field', sid, 32, 0);
  acl.insertClassFieldAce('field', sid, 64, 1);
  acl.insertClassFieldAce('field', sid, 128, 2);
  acl.insertClassFieldAce('field', sid, 256, 3);
  acl.deleteClassFieldAce(1, 'field');
  
  test.equal(acl._classFieldAces['field'][0]._mask, 32, 'The mask of ACE with index 0 is 32.');
  test.equal(acl._classFieldAces['field'][1]._mask, 128, 'The mask of ACE with index 1 is 128.');
  test.equal(acl._classFieldAces['field'][2]._mask, 256, 'The mask of ACE with index 2 is 256.');
  test.equal(acl._classFieldAces['field'][3], undefined, 'The ACE with index 3 is undefined.');
  
  test.equal(aclService._propertyChanges[acl.id()]['classFieldAces'][0]['field'], {}, 'The old value is an empty object.');
  test.equal(aclService._propertyChanges[acl.id()]['classFieldAces'][1]['field'][0]['_mask'], 32, 'ACE with a mask 32.');
  test.equal(aclService._propertyChanges[acl.id()]['classFieldAces'][1]['field'][1]['_mask'], 128, 'ACE with a mask 128.');
  test.equal(aclService._propertyChanges[acl.id()]['classFieldAces'][1]['field'][2]['_mask'], 256, 'ACE with a mask 256.');
  
  // Test  deleteObjectAce
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [sid], true);
  var aclService = new SecurityAcl.Service();
  aclService._propertyChanges[acl.id()] = {}; // the service must track the ACL.
  acl.addPropertyChangedListener(aclService);
  
  test.throws(function () {
    acl.deleteObjectAce('invalid-index');
  }, 'The index must be an integer.');
  
  test.throws(function () {
    acl.deleteObjectAce(0);
  }, 'The index 0 does not exist.');
  
  acl.insertObjectAce(sid, 32, 0);
  acl.deleteObjectAce(0);
  
  test.equal(acl._objectAces, {}, 'the ACL objectAces is empty.');
  
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'][0], {}, 'The old value is an empty object.');
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'][1], {}, 'The new value is an empty object.');
  
  acl.insertObjectAce(sid, 32, 0);
  acl.insertObjectAce(sid, 64, 1);
  acl.insertObjectAce(sid, 128, 2);
  acl.insertObjectAce(sid, 256, 3);
  acl.deleteObjectAce(1);
  
  test.equal(acl._objectAces[0]._mask, 32, 'The mask of ACE with index 0 is 32.');
  test.equal(acl._objectAces[1]._mask, 128, 'The mask of ACE with index 1 is 128.');
  test.equal(acl._objectAces[2]._mask, 256, 'The mask of ACE with index 2 is 256.');
  test.equal(acl._objectAces[3], undefined, 'The ACE with index 3 is undefined.');
  
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'][0], {}, 'The old value is an empty object.');
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'][1][0]['_mask'], 32, 'ACE with a mask 32.');
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'][1][1]['_mask'], 128, 'ACE with a mask 128.');
  test.equal(aclService._propertyChanges[acl.id()]['objectAces'][1][2]['_mask'], 256, 'ACE with a mask 256.');
  
  // Test deleteClassFieldAce
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var acl = new SecurityAcl.Acl('id', oid, permissionGrantingStrategy, [sid], true);
  var aclService = new SecurityAcl.Service();
  aclService._propertyChanges[acl.id()] = {}; // the service must track the ACL.
  acl.addPropertyChangedListener(aclService);
  
  test.throws(function () {
    acl.deleteObjectFieldAce('invalid-index', 'field');
  }, 'The index must be an integer.');
  
  test.throws(function () {
    acl.deleteObjectFieldAce(0, '');
  }, 'Field cannot be empty.');
  
  test.throws(function () {
    acl.deleteObjectFieldAce(0, 'field');
  }, 'The index 0 does not exist.');
  
  acl.insertObjectFieldAce('field', sid, 32, 0);
  
  test.throws(function () {
    acl.deleteObjectFieldAce(1, 'field');
  }, 'The index 1 does not exist.');
  
  acl.deleteObjectFieldAce(0, 'field');
  
  test.equal(acl._objectFieldAces['field'][0], undefined, 'the ACL ObjectFieldAces is empty for field.');
  
  test.equal(aclService._propertyChanges[acl.id()]['objectFieldAces'][0]['field'], {}, 'The old value is an empty object.');
  test.equal(aclService._propertyChanges[acl.id()]['objectFieldAces'][1]['field'], {}, 'The new value is an empty object.');
  
  acl.insertObjectFieldAce('field', sid, 32, 0);
  acl.insertObjectFieldAce('field', sid, 64, 1);
  acl.insertObjectFieldAce('field', sid, 128, 2);
  acl.insertObjectFieldAce('field', sid, 256, 3);
  acl.deleteObjectFieldAce(1, 'field');
  
  test.equal(acl._objectFieldAces['field'][0]._mask, 32, 'The mask of ACE with index 0 is 32.');
  test.equal(acl._objectFieldAces['field'][1]._mask, 128, 'The mask of ACE with index 1 is 128.');
  test.equal(acl._objectFieldAces['field'][2]._mask, 256, 'The mask of ACE with index 2 is 256.');
  test.equal(acl._objectFieldAces['field'][3], undefined, 'The ACE with index 3 is undefined.');
  
  test.equal(aclService._propertyChanges[acl.id()]['objectFieldAces'][0]['field'], {}, 'The old value is an empty object.');
  test.equal(aclService._propertyChanges[acl.id()]['objectFieldAces'][1]['field'][0]['_mask'], 32, 'ACE with a mask 32.');
  test.equal(aclService._propertyChanges[acl.id()]['objectFieldAces'][1]['field'][1]['_mask'], 128, 'ACE with a mask 128.');
  test.equal(aclService._propertyChanges[acl.id()]['objectFieldAces'][1]['field'][2]['_mask'], 256, 'ACE with a mask 256.');
  
  // Test: isGranted
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var aclService = new SecurityAcl.Service();
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  var acl = aclService.createAcl(oid);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  var sids = [sid];
  var masks = [3];
  
  test.throws(function () {
    acl.isGranted(masks, sids, false);
  }, 'No ACE found.');
  
  // we add an ACE
  acl.insertClassAce(sid, 3);
  aclService.updateAcl(acl);
  
  var masks = [1];
  
  test.isTrue(acl.isGranted(masks, sids, false),'It returns true for ACE mask 3.');
  
  var masks = [2];
  
  test.isTrue(acl.isGranted(masks, sids, false),'It returns true for ACE mask 3.');
  
  var masks = [3];
  
  test.isTrue(acl.isGranted(masks, sids, false),'It returns true for ACE mask 3.');
  
  var masks = [4];
  
  test.throws(function () {
    acl.isGranted(masks, sids, false);
  }, 'No ACE found.');
  
  // we add parentAcl
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts2');
  var parentAcl = aclService.createAcl(oid);
  parentAcl.insertClassAce(sid, 7);
  aclService.updateAcl(parentAcl);
  acl.setParentAcl(parentAcl);
  aclService.updateAcl(acl);
  
  var masks = [4];
  
  test.isTrue(acl.isGranted(masks, sids, false),'It returns true with parentAcl and ACE mask 7.');
  
  // Test: isFieldGranted
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var aclService = new SecurityAcl.Service();
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  var acl = aclService.createAcl(oid);
  var sid = new SecurityAcl.UserSecurityIdentity('username', 'className');
  var sids = [sid];
  var masks = [3];
  
  test.throws(function () {
    acl.isFieldGranted('field', masks, sids, false);
  }, 'No ACE found.');
  
  // we add an ACE
  acl.insertClassFieldAce('field', sid, 3);
  aclService.updateAcl(acl);
  
  var masks = [1];
  
  test.isTrue(acl.isFieldGranted('field', masks, sids, false),'It returns true for ACE mask 3.');
  
  var masks = [2];
  
  test.isTrue(acl.isFieldGranted('field', masks, sids, false),'It returns true for ACE mask 3.');
  
  var masks = [3];
  
  test.isTrue(acl.isFieldGranted('field', masks, sids, false),'It returns true for ACE mask 3.');
  
  var masks = [4];
  
  test.throws(function () {
    acl.isFieldGranted('field', masks, sids, false);
  }, 'No ACE found.');
  
  // we add parentAcl
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts2');
  var parentAcl = aclService.createAcl(oid);
  parentAcl.insertClassFieldAce('field', sid, 7);
  aclService.updateAcl(parentAcl);
  acl.setParentAcl(parentAcl);
  aclService.updateAcl(acl);
  
  var masks = [4];
  
  test.isTrue(acl.isFieldGranted('field', masks, sids, false),'It returns true with parentAcl and ACE mask 7.');
  
  
});