
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}

// transform Meteor.users document and add getClassName function
var transformUser = function (doc) { 
  doc.getDomainObjectName = function () {
    return Meteor.users._name;
  };
  return doc;
};

if (typeof Meteor.users !== 'undefined' &&
    typeof Meteor.users.find !== 'undefined' &&
    typeof Meteor.users.findOne !== 'undefined') {
  //keep references to the original functions
  var find = Meteor.users.find;
  var findOne = Meteor.users.findOne;

  // overriding find function
  Meteor.users.find = function (selector, options) {
    selector = selector || {};
    options = options || {};
    
    return find.call(this, selector, _.extend({transform: transformUser}, options));
  };

  // overriding findOne function
  Meteor.users.findOne = function (selector, options) {
    selector = selector || {};
    options = options || {};
    return findOne.call(this, selector, _.extend({transform: transformUser}, options));
  };
}


// FIXME add indexes to collections

// create the collections
/**
 * @summary A [Mongo.Collection](#collections) containing acl_collections documents.
 * @type {Mongo.Collection}
 */
SecurityAcl.Classes = new Mongo.Collection("acl_classes", {
  idGeneration: 'MONGO',
  _preventAutopublish: true
});

/**
 * @summary A [Mongo.Collection](#collections) containing acl_object_identities documents.
 * @type {Mongo.Collection}
 */
SecurityAcl.ObjectIdentities = new Mongo.Collection("acl_object_identities", {
  idGeneration: 'MONGO',
  _preventAutopublish: true
});

/**
 * @summary A [Mongo.Collection](#collections) acl_object_identities_ancestors documents.
 * @type {Mongo.Collection}
 */
SecurityAcl.ObjectIdentitiesAncestors = new Mongo.Collection("acl_object_ancestors", {
  idGeneration: 'MONGO',
  _preventAutopublish: true
});

/**
 * @summary A [Mongo.Collection](#collections) acl_entries documents.
 * @type {Mongo.Collection}
 */
SecurityAcl.Entries = new Mongo.Collection("acl_entries", {
  idGeneration: 'MONGO',
  _preventAutopublish: true
});

/**
 * @summary A [Mongo.Collection](#collections) acl_security_identities documents.
 * @type {Mongo.Collection}
 */
SecurityAcl.SecurityIdentities = new Mongo.Collection("acl_security_identities", {
  idGeneration: 'MONGO',
  _preventAutopublish: true
});


