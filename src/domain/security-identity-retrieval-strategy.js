
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}

/**
 * Retrieving security identities from user.
 *
 */
SecurityAcl.SidRetrievalStrategy = function () {
  var self = this;
  
  if (! (self instanceof SecurityAcl.SidRetrievalStrategy)) {
    throw new Error('Use "new" to construct a SecurityAcl.SidRetrievalStrategy');
  }
    
};

// Main API for SecurityIdentityRetrievalStrategy

/**
 * Retrieves the available security identities for the given token.
 *
 * The order in which the security identities are returned is significant.
 * Typically, security identities should be ordered from most specific to
 * least specific.
 *
 * @param {Object}  user
 *
 * @return {Array}  An array of SecurityIdentity implementations
 */
SecurityAcl.SidRetrievalStrategy.prototype.getSecurityIdentities = function (user) {
  
  var sids = [];
  
  // add user security identity
  try {
    sids.push(SecurityAcl.userSecurityIdentityFromAccount(user));
  } catch (e) {
    // ignore, user has no user security identity
  }
  
  // add all reachable roles
  // compatible with https://github.com/alanning/meteor-roles
  // check if field 'roles' exists in the user object
  if (user.roles !== 'undefined') {
    var role = null;
    if (user.roles instanceof Array) {
      for (var i=0; i < user.roles.length; i++) {
        role = user.roles[i];
        sids.push(new SecurityAcl.RoleSecurityIdentity(role));
      }
    } else if ('object' === typeof user.roles) {
      // if roles defined with properties
      var roles = Object.getOwnPropertyNames(user.roles);
      for (var key in roles) {
        if(!roles.hasOwnProperty(key)) {
          continue;
        }
        
        role = roles[key];
        sids.push(new SecurityAcl.RoleSecurityIdentity(role));
      }
    }
  }
  
  return sids;
  
};