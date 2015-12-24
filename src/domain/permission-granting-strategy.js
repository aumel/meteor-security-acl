
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}

/**
 * The permission granting strategy to apply to the access control list.
 *
 */
SecurityAcl.PermissionGrantingStrategy = function () {
  var self = this;
  
  if (! (self instanceof SecurityAcl.PermissionGrantingStrategy)) {
    throw new Error('Use "new" to construct a SecurityAcl.PermissionGrantingStrategy');
  }
  
  self.EQUAL = 'EQUAL';
  self.ALL = 'ALL';
  self.ANY = 'ANY';
};

// Main API for PermissionGrantingStrategy

/**
 * Determines whether access to a domain object is to be granted.
 *
 * @param {Object}   acl
 * @param {Array}    masks
 * @param {Array}    sids
 * @param {Boolean}  adminMode (administrativeMode)
 *
 * @return {Boolean}
 */
SecurityAcl.PermissionGrantingStrategy.prototype.isGranted = function (acl, masks,
                                                                       sids, 
                                                                       adminMode) {
  var self = this;
  
  if (typeof acl === 'undefined') {
    adminMode = false;
  }
  
  if (! (acl instanceof SecurityAcl.Acl)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The acl must be an instance of SecurityAcl.Acl.');
  }
    
  
  try {
    try {
      var aces = acl.objectAces();
      
      if (!aces) {
        throw new Meteor.Error('no-ace-found-exception', 'No ACE found.');
      }
      
      return self._hasPermissions(acl, aces, masks, sids, adminMode);
    } catch (e) {
      var aces = acl.classAces();
      
      if (!aces) {
        throw e;
      }
      
      return self._hasPermissions(acl, aces, masks, sids, adminMode);
    }
    
  } catch (e) {
    var parentAcl = acl.parentAcl();
    if (acl.isEntriesInheriting() && null !== parentAcl) {
      return parentAcl.isGranted(masks, sids, adminMode);
    }
    
    throw e;
  }
};

/**
 * Determines whether access to a domain object's field is to be granted.
 *
 * @param {Object}     acl
 * @param {String}     field
 * @param {Array}      masks
 * @param {Array}      sids
 * @param {Boolean}    adminMode (administrativeMode)
 *
 * @return {Boolean}
 */
SecurityAcl.PermissionGrantingStrategy.prototype.isFieldGranted = function (acl, field,
                                                                            masks, sids,
                                                                            adminMode) {
  var self = this;
  
  try {
    try {
      var aces = acl.objectFieldAces(field);
      if (!aces) {
        throw new Meteor.Error('no-ace-found-exception', 'No ACE found.');
      }
      
      return self._hasPermissions(acl, aces, masks, sids, adminMode);
    } catch (e) {
      var aces = acl.classFieldAces(field);
      if (!aces) {
        throw e;
      }
      
      return self._hasPermissions(acl, aces, masks, sids, adminMode);
    }
  } catch(e) {
    var parentAcl = acl.parentAcl();
    if (acl.isEntriesInheriting() && null !== parentAcl) {
      return parentAcl.isFieldGranted(field, masks, sids, adminMode);
    }
    
    throw e;
  }
  
};

/**
 * Makes an authorization decision.
 *
 * The order of ACEs, and SIDs is significant; the order of permission masks
 * not so much. It is important to note that the more specific security
 * identities should be at the beginning of the SIDs array in order for this
 * strategy to produce intuitive authorization decisions.
 *
 * First, we will iterate over permissions, then over security identities.
 * For each combination of permission, and identity we will test the
 * available ACEs until we find one which is applicable.
 *
 * The first applicable ACE will make the ultimate decision for the
 * permission/identity combination. If it is granting, this method will return
 * true, if it is denying, the method will continue to check the next
 * permission/identity combination.
 *
 * This process is repeated until either a granting ACE is found, or no
 * permission/identity combinations are left. Finally, we will either throw
 * an no-ace-found-exception, or deny access.
 *
 * @param {Object}     acl
 * @param {Array}      aces               An array of ACE to check against
 * @param {Array}      masks              An array of permission masks
 * @param {Object}     sids               An array of SecurityIdentities
 * @param {Boolean}    adminMode          True turns off audit logging
 *
 * @return {Boolean} true, or false; either granting, or denying access respectively.
 *
 * @throws no-ace-found-exception
 */
SecurityAcl.PermissionGrantingStrategy.prototype._hasPermissions = function (acl, aces,
                                                                             masks, sids,
                                                                             adminMode) {
  var self = this;
  
  var firstRejectedAce = null;
  
  for (var i in masks) {
    if(!masks.hasOwnProperty(i)) {
      continue;
    }
    
    var requiredMask = masks[i];
    
    loopSids: for (var j in sids) {
      if(!sids.hasOwnProperty(j)) {
        continue;
      }
      var sid = sids[j];
      for (var key in aces) {
        if(!aces.hasOwnProperty(key)) {
          continue;
        }
        
        var ace = aces[key];
        
        if (sid.equals(ace.sid()) && self._isAceApplicable(requiredMask, ace)) {
          if (ace.isGranting()) {
            if (! adminMode) {
              adminMode = false;
              // TODO implement auditLogger
            }
            
            return true;
          }
          
          if (null === firstRejectedAce) {
            firstRejectedAce = ace;
          }
          
          break loopSids;
        }
      }
    }
  }
  
  if (null !== firstRejectedAce) {
    // TODO implement auditLogger
    return false;
  }
  
  throw new Meteor.Error('no-ace-found-exception', 'No ACE found.');
  
};

/**
 * Determines whether the ACE is applicable to the given permission/security
 * identity combination.
 *
 * Per default, we support three different comparison strategies.
 *
 * Strategy ALL:
 * The ACE will be considered applicable when all the turned-on bits in the
 * required mask are also turned-on in the ACE mask.
 *
 * Strategy ANY:
 * The ACE will be considered applicable when any of the turned-on bits in
 * the required mask is also turned-on the in the ACE mask.
 *
 * Strategy EQUAL:
 * The ACE will be considered applicable when the bitmasks are equal.
 *
 * @param {Integer}      mask (requiredMask)
 * @param {Object}       ace
 *
 * @return {Boolean}
 *
 * @throws \run-time-exception if the ACE strategy is not supported
 */
SecurityAcl.PermissionGrantingStrategy.prototype._isAceApplicable = function (mask,
                                                                              ace) {
  var self = this;
  
  var strategy = ace.strategy();
  if (self.ALL === strategy) {
    return mask === (ace.mask() & mask);
  } else if (self.ANY === strategy) {
    return 0 !== (ace.mask() & mask);
  } else if (self.EQUAL === strategy) {
    return mask === ace.mask();
  }
  
  throw new Meteor.Error(
    'run-time-exception',
    'The strategy '+strategy+' is not supported.');
  
};

