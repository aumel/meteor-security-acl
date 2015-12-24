
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}

/**
 * ACE implementation
 *
 * @param {String}    id
 * @param {Object}    acl
 * @param {Object}    sid
 * @param {String}    strategy
 * @param {Integer}   mask
 * @param {Boolean}   granting
 * @param {Boolean}   auditFailure
 * @param {Boolean}   auditSuccess
 */

SecurityAcl.Entry = function (id, acl, sid, strategy, mask, granting,
                              auditFailure, auditSuccess) {
  var self = this;
  
  if (! (self instanceof SecurityAcl.Entry)) {
    throw new Error('Use "new" to construct a SecurityAcl.Entry');
  }
  
  if (! (acl instanceof SecurityAcl.Acl)) {
    throw new Meteor.Error(
      'invalid-argument', 
      'The acl must be an instance of SecurityAcl.Acl.');
  }
    
  if (! (sid instanceof SecurityAcl.SecurityIdentity)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The sid must be an instance of SecurityAcl.SecurityIdentity.');
  }
    
  if (typeof strategy !== 'string') {
    throw new Meteor.Error('invalid-argument', 'The strategy must be a string.');
  }
    
  
  if (! Number.isInteger(mask)) {
    throw new Meteor.Error('invalid-argument', 'The mask must be an integer.');
  }
  
  if (typeof granting !== 'boolean') {
    throw new Meteor.Error('invalid-argument', 'The granting must be a boolean.');
  }
    
  
  if (typeof auditFailure !== 'boolean') {
    throw new Meteor.Error(
      'invalid-argument',
      'The auditFailure must be a boolean.');
  }
  
  if (typeof auditSuccess !== 'boolean') {
    throw new Meteor.Error(
      'invalid-argument', 
      'The auditSuccess must be a boolean.');
  }
  
  self._id = id;
  self._acl = acl;
  self._sid = sid;
  self._strategy = strategy;
  self._mask = mask;
  self._granting = granting;
  self._auditFailure = auditFailure;
  self._auditSuccess = auditSuccess;
  
  
};

// Main API for Entry

// Returns the id of the ACE.
SecurityAcl.Entry.prototype.id = function () {
  var self = this;
  return self._id;
};

// Returns the acl associated with this ACE.
SecurityAcl.Entry.prototype.acl = function () {
  var self = this;
  return self._acl;
};

// Returns the mask associated with this ACE.
SecurityAcl.Entry.prototype.mask = function () {
  var self = this;
  return self._mask;
};

// Returns the sid associated with this ACE.
SecurityAcl.Entry.prototype.sid = function () {
  var self = this;
  return self._sid;
};

// Returns the strategy of the ACE.
SecurityAcl.Entry.prototype.strategy = function () {
var self = this;
return self._strategy;
};

// Returns whether this ACE is granting, or denying.
SecurityAcl.Entry.prototype.isGranting = function () {
var self = this;
return self._granting;
};

// Returns the auditSuccess of the ACE.
SecurityAcl.Entry.prototype.isAuditSuccess = function () {
  var self = this;
  return self._auditSuccess;
};

// Returns the auditFailure of the ACE.
SecurityAcl.Entry.prototype.isAuditFailure = function () {
  var self = this;
  return self._auditFailure;
};

/**
 * Sets the permission mask.
 *
 * Do never call this method directly. Use the respective methods on the
 * Acl instead.
 *
 * @param {Integer}    mask
 */
SecurityAcl.Entry.prototype.setMask = function (mask) {
  var self = this;
  self._mask = mask;
};


/**
 * Sets the mask comparison strategy.
 *
 * Do never call this method directly. Use the respective methods on the
 * Acl instead.
 *
 * @param {String}    strategy
 */
SecurityAcl.Entry.prototype.setStrategy = function (strategy) {
  var self = this;
  self._strategy = strategy;
};
