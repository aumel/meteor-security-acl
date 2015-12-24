
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}

/**
 * This class allows you to build cumulative permissions easily, or convert
 * masks to a human-readable format.
 *
 * <code>
 *       builder = new SecurityAcl.MaskBuilder();
 *       builder.add('view');
 *       builder.add('create');
 *       builder.add('edit');
 *       
 *       console.log(builder.getMask());
 *       // int(7)
 *       console.log(builder.getPattern());
 *       // string(32) ".............................ECV"
 * </code>
 *
 * We have defined some commonly used base permissions which you can use:
 * - VIEW: the SID is allowed to view the domain object / field
 * - CREATE: the SID is allowed to create new instances of the domain object / fields
 * - EDIT: the SID is allowed to edit existing instances of the domain object / field
 * - DELETE: the SID is allowed to delete domain objects
 * - UNDELETE: the SID is allowed to recover domain objects from trash
 * - OPERATOR: the SID is allowed to perform any action on the domain object
 *             except for granting others permissions
 * - MASTER: the SID is allowed to perform any action on the domain object,
 *           and is allowed to grant other SIDs any permission except for
 *           MASTER and OWNER permissions
 * - OWNER: the SID is owning the domain object in question and can perform any
 *          action on the domain object as well as grant any permission
 *
 */
SecurityAcl.MaskBuilder = function () {
  var self = this;
  
  if (! (self instanceof SecurityAcl.MaskBuilder)) {
    throw new Error('Use "new" to construct a SecurityAcl.MaskBuilder');
  }
    
  
  self.MASK_VIEW = 1;           // 1 << 0
  self.MASK_CREATE = 2;         // 1 << 1
  self.MASK_EDIT = 4;           // 1 << 2
  self.MASK_DELETE = 8;         // 1 << 3
  self.MASK_UNDELETE = 16;      // 1 << 4
  self.MASK_OPERATOR = 32;      // 1 << 5
  self.MASK_MASTER = 64;        // 1 << 6
  self.MASK_OWNER = 128;        // 1 << 7
  self.MASK_IDDQD = 1073741823; // 1 << 0 | 1 << 1 | ... | 1 << 30
  
  self.CODE_VIEW = 'V';
  self.CODE_CREATE = 'C';
  self.CODE_EDIT = 'E';
  self.CODE_DELETE = 'D';
  self.CODE_UNDELETE = 'U';
  self.CODE_OPERATOR = 'O';
  self.CODE_MASTER = 'M';
  self.CODE_OWNER = 'N';
  
  self.ALL_OFF = '................................';
  self.OFF = '.';
  self.ON = '*';
  
  self._mask = 0;
};


// Main API for MaskBuilder


/**
 * Set the mask of this permission.
 *
 * @param {Integer}  mask
 *
 * @return {Object}   MaskBuilder
 *
 * @throws \invalid-argument if mask is not an integer
 */
SecurityAcl.MaskBuilder.prototype.setMask = function (mask) {
  var self = this;
  
  if (!Number.isInteger(mask)) {
    throw new Meteor.Error('invalid-argument', 'The mask must be an integer.');
  }
  
  self._mask = mask;
  
  return self;
};

/**
 * Returns the mask of this permission.
 *
 * @return {Integer}
 */
SecurityAcl.MaskBuilder.prototype.getMask = function () {
  var self = this;
  
  return self._mask;
};

/**
 * Adds a mask to the permission.
 *
 * @param {mixed}  mask
 *
 * @return {Object} MaskBuilder
 *
 * @throws \invalid-argument
 */
SecurityAcl.MaskBuilder.prototype.add = function (mask) {
  var self = this;
  
  self._mask |= self.resolveMask(mask);
  
  return self;
};

/**
 * Removes a mask from the permission.
 *
 * @param {mixed} mask
 *
 * @return {Object} MaskBuilder
 *
 * @throws \invalid-argument
 */
SecurityAcl.MaskBuilder.prototype.remove = function (mask) {
  var self = this;
  
  self._mask &= ~self.resolveMask(mask);
  
  return self;
};

/**
 * Resets the PermissionBuilder.
 *
 * @return {Object} MaskBuilder
 */
SecurityAcl.MaskBuilder.prototype.reset = function () {
  var self = this;
  
  self._mask = 0;
  
  return self;
};

/**
 * Returns the mask for the passed code.
 *
 * @param {mixed}    code
 *
 * @return {Integer}
 *
 * @throws \invalid-argument
 */
SecurityAcl.MaskBuilder.prototype.resolveMask = function (code) {
  var self = this;
  
  if (typeof code === 'string') {
    if (typeof self['MASK_'+code.toUpperCase()] === 'undefined') {
      throw new Meteor.Error('invalid-argument', 'The code '+code+' is not supported.');
    }
    
    return self['MASK_'+code.toUpperCase()];
  }
  
  if (!Number.isInteger(code)) {
    throw new Meteor.Error('invalid-argument', code+' must be an integer.');
  }
  
  return code;
};


/**
 * Returns the code for the passed mask.
 *
 * @param {Integer}  mask
 *
 * @throws \invalid-argument
 * @throws \runtime-exception
 *
 * @return {String}
 */
SecurityAcl.MaskBuilder.prototype.getCode = function (mask) {
  var self = this;
  
  if (!Number.isInteger(mask)) {
    throw new Meteor.Error('invalid-argument','The mask must be an integer.');
  }
  
  var properties = Object.getOwnPropertyNames(self);
  for (var key in properties) {
    if(!properties.hasOwnProperty(key)) {
      continue;
    }
    
    var name = properties[key];
    var cMask = self[name];
    
    if (0 !== name.indexOf('MASK_') || mask !== cMask) {
      continue;
    }
    
    if (typeof self['CODE_'+name.substr(5)] === 'undefined') {
      throw new Meteor.Error(
        'runtime-exception',
        'There was no code defined for this mask.');
    }
    
    return self['CODE_'+name.substr(5)];
  }
  
  throw new Meteor.Error('invalid-argument','The mask '+mask+' is not supported.');
  
};


/**
 * Returns a human-readable representation of the permission.
 *
 * @return {String}
 */
SecurityAcl.MaskBuilder.prototype.getPattern = function () {
  var self = this;
  
  var pattern = self.ALL_OFF;
  var length = pattern.length;
  var bitmask = SecurityAcl.utils.strPad(SecurityAcl.utils.decbin(self._mask),
                                          length, '0', 'STR_PAD_LEFT');
  
  for (var i = length - 1; i >= 0; --i) {
    if ('1' === bitmask[i]) {
      try {
        // strings are immutable
        var code = self.getCode(1 << (length - i - 1));
        pattern = pattern.substring(0, i) + code + pattern.substring(i+1);
      } catch (e) {
        // strings are immutable
        pattern = pattern.substring(0, i) + self.ON + pattern.substring(i+1);
      }
    }
  }
  
  return pattern;
  
};
