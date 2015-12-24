
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}

/**
 * Strategy to be used for retrieving object identities from domain objects.
 *
 */
SecurityAcl.OidRetrievalStrategy = function () {
  var self = this;
  
  if (! (self instanceof SecurityAcl.OidRetrievalStrategy)) {
    throw new Error('Use "new" to construct a ' +
    'SecurityAcl.OidRetrievalStrategy');
  }
};

// Main API

SecurityAcl.OidRetrievalStrategy.prototype.getObjectIdentity = function (domainObject) {
  try {
    return SecurityAcl.objectIdentityFromDomainObject(domainObject);
  } catch (e) {
    return;
  }
};