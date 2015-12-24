
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}

/**
 * A SecurityIdentity implementation for roles.
 * 
 * @param {String} role
 */
SecurityAcl.RoleSecurityIdentity = function (role) {
  var self = this;
  
  if (! (self instanceof SecurityAcl.RoleSecurityIdentity)) {
    throw new Error('Use "new" to construct a SecurityAcl.RoleSecurityIdentity');
  }
    
  
  if (role === null || typeof role === 'undefined') {
    throw new Meteor.Error('invalid-argument', 'Role cannot be null or undefined.');
  }
    
  
  self._role = role;
  
};

// RoleSecurityIdentity inherits from SecurityIdentity
SecurityAcl.RoleSecurityIdentity.prototype = Object.create(
    SecurityAcl.SecurityIdentity.prototype);


// Main API for RoleSecurityIdentity

// Returns the role of RoleSecurityIdentity
SecurityAcl.RoleSecurityIdentity.prototype.role = function () {
  var self = this;
  return self._role;
};


// Compares the RoleSecurityIdentity with another RoleSecurityIdentity 
SecurityAcl.RoleSecurityIdentity.prototype.equals = function (sid) {
  var self = this;
  
  if (! (sid instanceof SecurityAcl.RoleSecurityIdentity)) {
    return false;
  }
  
  return self.role() === sid.role();
};
