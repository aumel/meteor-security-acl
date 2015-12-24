
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}


/**
 * This is a lightweight wrapper around field vote requests.
 *
 */
SecurityAcl.FieldVote = function (domainObject, field) {
  var self = this;
  
  self._domainObject = domainObject;
  self._field = field;
};

// Main API for fieldVote

SecurityAcl.FieldVote.prototype.domainObject = function () {
  var self = this;
  
  return self._domainObject;
};

SecurityAcl.FieldVote.prototype.field = function () {
  var self = this;
  
  return self._field;
};