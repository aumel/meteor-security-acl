
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}

/**
 * Describes a logger instance.
 *
 * The logger must have a debug function
 * to detail debug information.
 */
SecurityAcl.logger = null;

SecurityAcl.setLogger = function (logger) {
  
  if (typeof logger.debug !== 'function') {
    throw new Meteor.Error(
        'invalid-argument',
        'The logger must have a debug function.');
  }
  
  SecurityAcl.logger = logger;
};