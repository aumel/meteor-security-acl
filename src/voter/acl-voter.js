
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}

/**
 * This voter can be used as a base class for implementing your own permissions.
 *
 */
SecurityAcl.AclVoter = function (aclService, oidRetrievalStrategy,
                                  sidRetrievalStrategy, permissionMap,
                                  logger, allowIfObjectIdentityUnavailable) {
  var self = this;
  
  if (! (self instanceof SecurityAcl.AclVoter)) {
    throw new Error('Use "new" to construct a SecurityAcl.AclVoter');
  }
  
  if (typeof logger === 'undefined') {
    logger = null;
  }
  
  if (typeof allowIfObjectIdentityUnavailable === 'undefined') {
    allowIfObjectIdentityUnavailable =  true;
  }
  
  if (! (aclService instanceof SecurityAcl.Service)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The aclService must be an instance of AclService.');
  }
    
  if (! (oidRetrievalStrategy instanceof SecurityAcl.OidRetrievalStrategy)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The oidRetrievalStrategy must be an instance of ' +
      'SecurityAcl.OidRetrievalStrategy.');
  }
    
  if (! (sidRetrievalStrategy instanceof SecurityAcl.SidRetrievalStrategy)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The sidRetrievalStrategy must be an instance of ' +
      'SecurityAcl.SidRetrievalStrategy.');
  }
    
  if (! (permissionMap instanceof SecurityAcl.PermissionMap)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The permissionMap must be an instance of SecurityAcl.PermissionMap.');
  }
    
  
  self._aclService = aclService;
  self._oidRetrievalStrategy = oidRetrievalStrategy;
  self._sidRetrievalStrategy = sidRetrievalStrategy;
  self._permissionMap = permissionMap;
  self._logger = logger;
  self._allowIfObjectIdentityUnavailable = allowIfObjectIdentityUnavailable;
  self._authenticatedUser = null;
  
  self.ACCESS_GRANTED = 1;
  self.ACCESS_ABSTAIN = 0;
  self.ACCESS_DENIED = -1;
  
};

/**
 * Returns the vote for the given parameters.
 *
 * This method must return one of the following constants:
 * ACCESS_GRANTED, ACCESS_DENIED, or ACCESS_ABSTAIN.
 *
 * @param {Object}          user
 * @param {Object|null}     The object to secure
 * @param {Array}           An array of attributes
 *
 * @return {Integer} either ACCESS_GRANTED, ACCESS_ABSTAIN, or ACCESS_DENIED
 */
SecurityAcl.AclVoter.prototype.vote = function (user, object, attributes) {
  var self = this;
  
  for (var key in attributes) {
    if(!attributes.hasOwnProperty(key)) {
      continue;
    }
    
    var attribute = attributes[key].toUpperCase();
    
    if (! self.supportsAttribute(attribute)) {
      continue;
    }
    
    var masks = self._permissionMap.getMasks(attribute);
    
    if (null === masks) {
      continue;
    }
    
    var field = null;
    var debug = null;
    if (null === object) {
      if (null !== self._logger) {
        debug = self._allowIfObjectIdentityUnavailable ? 'grant access' : 'abstain';
        self._logger.debug('Object identity unavailable. Voting to '+debug+'.');
      }
      return  self._allowIfObjectIdentityUnavailable ?
        self.ACCESS_GRANTED : self.ACCESS_ABSTAIN;
    } else if (object instanceof SecurityAcl.FieldVote) {
      field = object.field();
      object = object.domainObject();
    } else {
      field = null;
    }
    
    var oid = null;
    if (object instanceof SecurityAcl.ObjectIdentity) {
      oid = object;
    } else if (typeof object === 'string') {
      // oid for class-scope
      oid = new SecurityAcl.ObjectIdentity('class', object);
    } else if (null === self._oidRetrievalStrategy.getObjectIdentity(object)) {
      if (null !== self._logger) {
        debug = self._allowIfObjectIdentityUnavailable ? 'grant access' : 'abstain';
        self._logger.debug('Object identity unavailable. Voting to '+debug+'.');
      }
      return self._allowIfObjectIdentityUnavailable ?
        self.ACCESS_GRANTED : self.ACCESS_ABSTAIN;
    } else {
      oid = self._oidRetrievalStrategy.getObjectIdentity(object);
    }
    
    if (null === oid) {
      throw new Meteor.Error('object-identity-not-found', 'The oid was not found.');
    }
    
    if (! self.supportsClass(oid.type())) {
      if (null !== self._logger) {
        self._logger.debug('Domain object name not supported. Voting to abstain.');
      }
      return self.ACCESS_ABSTAIN;
    }
    
    var sids = self._sidRetrievalStrategy.getSecurityIdentities(user);
    
    try {
      var acl = self._aclService.findAcl(oid, sids);
      
      if (null === field && acl.isGranted(masks, sids, false)) {
        if (null !== self._logger) {
          self._logger.debug('ACL found, permission granted. Voting to grant access.');
        }
        return self.ACCESS_GRANTED;
      } else if (null !== field && acl.isFieldGranted(field, masks, sids, false)) {
        if (null !== self._logger) {
          self._logger.debug('ACL found, permission granted. Voting to grant access.');
        }
        return self.ACCESS_GRANTED;
      }
      if (null !== self._logger) {
        self._logger.debug('ACL found, insufficient permissions. Voting to deny access.');
      }
      return self.ACCESS_DENIED;
    } catch (e) {
      // e.error must be:
      // - acl-not-found-exception
      // - no-ace-found-exception
      
      if(e.error === 'acl-not-found-exception') {
        if (null !== self._logger) {
          self._logger.debug(
            'No ACL found for the object identity. Voting to deny access.');
        }
      }
      
      if (e.error === 'no-ace-found-exception') {
        if (null !== self._logger) {
          self._logger.debug('ACL found, no ACE applicable. Voting to deny access.');
        }
      }
      
      return self.ACCESS_DENIED;
    }
  }
  
  if (null !== self._logger) {
    self._logger.debug('No attribute was supported. Voting to abstain.');
  }
  
  // no attribute was supported
  return self.ACCESS_ABSTAIN;
};

/**
 * Checks if the AuthorizationChecker supports the given attribute.
 *
 * @param {String} $attribute An attribute
 *
 * @return {Boolean} true if this AuthorizationChecker supports the attribute
 *
 */
SecurityAcl.AclVoter.prototype.supportsAttribute = function (attribute) {
  var self = this;
  
  return (typeof attribute === 'string') && self._permissionMap.contains(attribute);
};

/**
 * You can override this method when writing a voter for a specific domain
 * class.
 *
 * @param {String}  className
 *
 * @return {Boolean}
 */
SecurityAcl.AclVoter.prototype.supportsClass = function (className) {
  
  if(className) {
    return true;
  }
  
  return true;
};