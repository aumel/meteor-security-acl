
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}

/**
 * Creates a user security identity from a User.
 *
 * @param {Object}  user
 *
 * @return {Object} UserSecurityIdentity
 */
SecurityAcl.userSecurityIdentityFromAccount = function (user) {
  if (typeof user.getClassName !== 'undefined' &&
      typeof user.getClassName === 'function') {
    return new SecurityAcl.UserSecurityIdentity(user.username, user.getClassName());
  }
  
  // Support ES6 (ES2015) constructor.name
  if (user.constructor.name !== 'Object') {
    return new SecurityAcl.UserSecurityIdentity(user.username, user.constructor.name);
  }
  
  // For user object without getClassName method or ES6 implementation, 
  // we use 'meteor\users' for classname by default.
  return new SecurityAcl.UserSecurityIdentity(user.username, 'meteor\\users');
};


/**
 * A SecurityIdentity implementation used for actual users.
 * 
 * @param {String} username
 * @param {String} className
 */
SecurityAcl.UserSecurityIdentity = function (username, className) {
  var self = this;
  
  if (! (self instanceof SecurityAcl.UserSecurityIdentity)) {
    throw new Error('Use "new" to construct a SecurityAcl.UserSecurityIdentity');
  }
    
  
  if (username === null || typeof username === 'undefined') {
    throw new Meteor.Error(
      'invalid-argument',
      'Username cannot be null or undefined.');
  }
    
  
  if (className === null || typeof className === 'undefined') {
    throw new Meteor.Error(
      'invalid-argument',
      'ClassName cannot be null or undefined.');
  }
    
  
  self._username = username;
  self._className = className;
  
};

// UserSecurityIdentity inherits from SecurityIdentity
SecurityAcl.UserSecurityIdentity.prototype = Object.create(
    SecurityAcl.SecurityIdentity.prototype);


// Main API for UserSecurityIdentity

// Returns the username of UserSecurityIdentity
SecurityAcl.UserSecurityIdentity.prototype.username = function () {
  var self = this;
  return self._username;
};

// Returns the className of UserSecurityIdentity
SecurityAcl.UserSecurityIdentity.prototype.className = function () {
  var self = this;
  return self._className;
};

// Compares the UserSecurityIdentity with another UserSecurityIdentity 
SecurityAcl.UserSecurityIdentity.prototype.equals = function (sid) {
  var self = this;
  
  if (! (sid instanceof SecurityAcl.UserSecurityIdentity)) {
    return false;
  }
  
  return self.username() === sid.username() &&
    self.className() === sid.className();
};



