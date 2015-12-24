
Tinytest.add('SecurityAcl - ObjectIdentity', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  // data-fixtures
  Posts.insert({
    text: 'test'
  });
  
  var post = Posts.findOne();
  
  
  test.throws(function () {
    SecurityAcl.ObjectIdentity(post, 'posts');
  }, 'Use "new" to construct a SecurityAcl.ObjectIdentity');
  
  test.throws(function () {
    new SecurityAcl.ObjectIdentity(post);
  }, 'The className cannot be null or undefined.');
  
  test.throws(function () {
    new SecurityAcl.ObjectIdentity(post, null);
  }, 'The className cannot be null or undefined.');
  
  test.throws(function () {
    new SecurityAcl.ObjectIdentity(post, undefined);
  }, 'The className cannot be null or undefined.');
  
  test.throws(function () {
    new SecurityAcl.ObjectIdentity(null, 'posts');
  }, 'The identifier cannot be null or undefined.');
  
  test.throws(function () {
    new SecurityAcl.ObjectIdentity(undefined, 'posts');
  }, 'The identifier cannot be null or undefined.');
  
  var oid = new SecurityAcl.ObjectIdentity(post._id._str, 'posts');
  test.equal(oid.type(), 'posts', 'oid type correctly defined');
  test.equal(oid.identifier(), post._id._str, 'oid identifier correctly defined');
  
  var oid = new SecurityAcl.ObjectIdentity('class', 'posts');
  
  test.equal(oid.identifier(), 'class', 'If the identifier is a class-scope');
  
  test.equal(oid.equals(oid), true, 'the equals method return true if the given oid is equal');
});

Tinytest.add('SecurityAcl - objectIdentityFromDomainObject', function (test) {
  
  test.throws(function () {
    SecurityAcl.objectIdentityFromDomainObject();
  }, 'The domainObject cannot be null or undefined');
  
  var invalidPost = 'test';
  test.throws(function () {
    SecurityAcl.objectIdentityFromDomainObject(invalidPost);
  }, 'The domainObject is not valid. The property _id cannot be null or undefined.');
  
  var invalidPost = {};
  invalidPost._id = 'id';
  invalidPost.className = function() {
    return null;
  };
  
  test.throws(function () {
    SecurityAcl.objectIdentityFromDomainObject(invalidPost);
  }, 'The domainObject must have a getDomainObjectName method.');
  
  test.throws(function () {
    SecurityAcl.objectIdentityFromDomainObject('invalidPost');
  }, 'The domainObject is not valid. The property _id cannot be null or undefined.');
  
  var post = Posts.findOne();
  var oid = SecurityAcl.objectIdentityFromDomainObject(post);
  test.equal(oid.identifier(), post._id, 'The identifier (objectId) is equal to _id of domainObject.');
  
  var postWithoutIdStr = {};
  postWithoutIdStr._id = 'test';
  postWithoutIdStr.getDomainObjectName = function() {
    return 'posts';
  };
  
  var oid = SecurityAcl.objectIdentityFromDomainObject(postWithoutIdStr);
  
  test.equal(oid.identifier(), 'test', 'The identifier (string) is equal to _id of domainObject.');
});


Tinytest.add('SecurityAcl - objectIdentityFromDomainObject (support ES6)', function (test) {
  
  //ES2015 (ES6) class
  class DomainObject {
    constructor() {
      this._id = 'id';
    }
  }
  
  var domainObject = new DomainObject();
  
  var oid = SecurityAcl.objectIdentityFromDomainObject(domainObject);
  
  test.equal(oid.type(), 'DomainObject', 'The type of oid is the class name of domainObject.');

  
});