
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}


/**
 * Constructs an ObjectIdentity for the given domain object.
 *
 * @param {Object} domainObject
 *
 * @return {Object} ObjectIdentity
 */
SecurityAcl.objectIdentityFromDomainObject = function (domainObject) {
  
  if (domainObject === null || typeof domainObject === 'undefined') {
    throw new Meteor.Error(
      'invalid-argument',
      'The domainObject cannot be null or undefined.');
  }
  
  if ((domainObject._id === null || typeof domainObject._id === 'undefined')) {
    throw new Meteor.Error(
      'invalid-argument',
      'The domainObject is not valid. The property _id cannot be null or undefined.');
  }
  
  if (domainObject.constructor.name === 'Object') {
  
    if (typeof domainObject.getDomainObjectName !== 'function') {
      throw new Meteor.Error(
        'invalid-argument',
        'The domainObject must have a getDomainObjectName method.');
    }
    
    if (domainObject.getDomainObjectName === null) {
      throw new Meteor.Error(
        'invalid-argument',
        'The domainObject is invalid.' +
        'The getDomainObjectName method cannot return null.');
    }
    
    return new SecurityAcl.ObjectIdentity(
      domainObject._id, 
      domainObject.getDomainObjectName());
  
  } else {
    // Support ES6:  use the object.constructor.name
    return new SecurityAcl.ObjectIdentity(
      domainObject._id,
      domainObject.constructor.name);
  }
};

/**
 * Represents the identity of an individual domain object instance.
 * 
 * @param {String} identifier
 * @param {String} className
 */
SecurityAcl.ObjectIdentity = function (identifier, className) {
  
  var self = this;
  
  if (! (self instanceof SecurityAcl.ObjectIdentity)) {
    throw new Error('Use "new" to construct a SecurityAcl.ObjectIdentity');
  }
    
  
  if (className === null || typeof className === 'undefined') {
    throw new Meteor.Error(
      'invalid-argument',
      'The className cannot be null or undefined.');
  }
  
  if (identifier === null || typeof identifier === 'undefined') {
    throw new Meteor.Error(
      'invalid-argument',
      'The identifier cannot be null or undefined.');
  }
  
  self._identifier = identifier;
  self._type = className;
  
  return;
};

// Main API for ObjectIdentity

// Returns the identifier of ObjectIdentity
SecurityAcl.ObjectIdentity.prototype.identifier = function () {
  var self = this;
  return self._identifier;
};

// Returns the type of ObjectIdentity
SecurityAcl.ObjectIdentity.prototype.type = function () {
  var self = this;
  return self._type;
};

// Compares the ObjectIdentity with another oid
SecurityAcl.ObjectIdentity.prototype.equals = function (oid) {
  var self = this;
  // comparing identifier with objectId leads to problems, 
  // so we must cast to String
  return String(self._identifier) === String(oid.identifier()) &&
    self._type === oid.type();
};