
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}

/**
 * AuthorizationChecker is the main authorization point of the SecurityAcl.
 *
 */
SecurityAcl.AuthorizationChecker = function () {
  var self = this;
  
  if (! (self instanceof SecurityAcl.AuthorizationChecker)) {
    throw new Error('Use "new" to construct a SecurityAcl.AuthorizationChecker');
  }
    
  
  self._authenticatedUser = null;
  
};

SecurityAcl.AuthorizationChecker.prototype._getVoter = function () {
  
  // get the voter
  var aclService =  new SecurityAcl.Service();
  var oidRetrievalStrategy = new SecurityAcl.OidRetrievalStrategy();
  var sidRetrievalStrategy = new SecurityAcl.SidRetrievalStrategy();
  var permissionMap = new SecurityAcl.PermissionMap();
  var voter = new SecurityAcl.AclVoter(aclService, oidRetrievalStrategy,
                                        sidRetrievalStrategy, permissionMap);
  
  return voter;
};


// Main API for AuthorizationChecker

/**
 * Checks if the attributes are granted against the current authenticated user
 * and optionally supplied object.
 *
 * @param {mixed}    attributes
 * @param {mixed}    object
 * 
 * @throws no-user-found-exception
 *
 * @return {Boolean}
 */
SecurityAcl.AuthorizationChecker.prototype.isGranted = function (attributes, object) {
  var self = this;
  
  if (! (attributes instanceof Array)) {
    attributes = [attributes];
  }
  
  // we check the authenticated user
  if (null === self._authenticatedUser && null !== Meteor.user()) {
    self.setAuthenticatedUser(Meteor.user());
  }
  
  if (null === self._authenticatedUser ||
      typeof self._authenticatedUser === 'undefined') {
    throw new Meteor.Error('no-user-found-exception', 'The user cannot be null.');
  }
  
  return self._decide(self._authenticatedUser, attributes, object);
};

/**
 * Grants access if any vote returns an affirmative response.
 *
 * If all votes abstained, the decision will be false.
 */
SecurityAcl.AuthorizationChecker.prototype._decide = function (user, attributes, object) {
  var self = this;
  
  if (typeof object === 'undefined') {
    object = null;
  }
  
  var deny = 0;
  var voter = self._getVoter();
  
  var result =  voter.vote(user, object, attributes);
  
  switch (result) {
    case voter.ACCESS_GRANTED:
      return true;
    case voter.ACCESS_DENIED:
      ++deny;
      break;
    default:
      break;
  }
  
  if (deny > 0) {
    return false;
  }
  
  return false;
};


/**
 * Set the authenticated user.
 * 
 * @param {Object}  user
 */
SecurityAcl.AuthorizationChecker.prototype.setAuthenticatedUser = function (user) {
  var self = this;
  
  if (typeof user === 'undefined') {
    throw new Meteor.Error('invalid-argument', 'The user cannot be undefined.');
  }
  
  if (typeof user.username === 'undefined') {
    throw new Meteor.Error('invalid-argument', 'The user.username cannot be undefined.');
  }
  
  self._authenticatedUser = user;
};

