
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}


/**
 * Field-aware ACE implementation
 *
 * @param {String}    id
 * @param {Object}    acl
 * @param {String}    field
 * @param {Object}    sid
 * @param {String}    strategy
 * @param {Number}    mask
 * @param {Boolean}   granting
 * @param {Boolean}   auditFailure
 * @param {Boolean}   auditSuccess
 */
SecurityAcl.FieldEntry = function (id, acl, field, sid, strategy, mask,
                                   granting, auditFailure, auditSuccess) {
  var self = this;
  
  if (! (self instanceof SecurityAcl.Entry)) {
    throw new Error('Use "new" to construct a SecurityAcl.FieldEntry');
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
    throw new Meteor.Error(
      'invalid-argument',
      'The strategy must be a string.');
  }
    
  
  if (! (mask % 1 === 0 && typeof mask === 'number')) {
    throw new Meteor.Error('invalid-argument', 'The mask must be an integer.');
  }
    
  
  if (typeof granting !== 'boolean') {
    throw new Meteor.Error(
      'invalid-argument',
      'The granting must be a boolean.');
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
  self._field = field;
  self._sid = sid;
  self._strategy = strategy;
  self._mask = mask;
  self._granting = granting;
  self._auditFailure = auditFailure;
  self._auditSuccess = auditSuccess;
  
  
};

// FieldEntry inherits from Entry
SecurityAcl.FieldEntry.prototype = Object.create(SecurityAcl.Entry.prototype);


// Main API for FieldEntry

// Returns the field of the FieldEntry.
SecurityAcl.Entry.prototype.field = function () {
var self = this;
return self._field;
};