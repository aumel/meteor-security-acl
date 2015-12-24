
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}

/**
 * This is permission map complements the masks which have been defined
 * on the standard implementation of the SecurityAcl.MaskBuilder.
 *
 */
SecurityAcl.PermissionMap = function () {
  var self = this;
  
  if (! (self instanceof SecurityAcl.PermissionMap)) {
    throw new Error('Use "new" to construct a SecurityAcl.PermissionMap');
  }
    
  
  self.PERMISSION_VIEW = 'VIEW';
  self.PERMISSION_EDIT = 'EDIT';
  self.PERMISSION_CREATE = 'CREATE';
  self.PERMISSION_DELETE = 'DELETE';
  self.PERMISSION_UNDELETE = 'UNDELETE';
  self.PERMISSION_OPERATOR = 'OPERATOR';
  self.PERMISSION_MASTER = 'MASTER';
  self.PERMISSION_OWNER = 'OWNER';
  
  self._map = {};
  
  var maskBuilder = new SecurityAcl.MaskBuilder();
  
  self._map[self.PERMISSION_VIEW] = [
    maskBuilder.MASK_VIEW,
    maskBuilder.MASK_EDIT,
    maskBuilder.MASK_OPERATOR,
    maskBuilder.MASK_MASTER,
    maskBuilder.MASK_OWNER,
  ];
  
  self._map[self.PERMISSION_EDIT] = [
    maskBuilder.MASK_EDIT,
    maskBuilder.MASK_OPERATOR,
    maskBuilder.MASK_MASTER,
    maskBuilder.MASK_OWNER,
  ];
  
  self._map[self.PERMISSION_CREATE] = [
    maskBuilder.MASK_CREATE,
    maskBuilder.MASK_OPERATOR,
    maskBuilder.MASK_MASTER,
    maskBuilder.MASK_OWNER,
  ];
  
  self._map[self.PERMISSION_DELETE] = [
    maskBuilder.MASK_DELETE,
    maskBuilder.MASK_OPERATOR,
    maskBuilder.MASK_MASTER,
    maskBuilder.MASK_OWNER,
  ];
  
  self._map[self.PERMISSION_UNDELETE] = [
    maskBuilder.MASK_UNDELETE,
    maskBuilder.MASK_OPERATOR,
    maskBuilder.MASK_MASTER,
    maskBuilder.MASK_OWNER,
  ];
  
  self._map[self.PERMISSION_OPERATOR] = [
    maskBuilder.MASK_OPERATOR,
    maskBuilder.MASK_MASTER,
    maskBuilder.MASK_OWNER,
  ];
  
  self._map[self.PERMISSION_MASTER] = [
    maskBuilder.MASK_MASTER,
    maskBuilder.MASK_OWNER,
  ];
  
  self._map[self.PERMISSION_OWNER] = [
    maskBuilder.MASK_OWNER,
  ];
  
  
};


// Main API for permissionMap

/**
 * Returns an array of bitmasks.
 *
 * The security identity must have been granted access to at least one of
 * these bitmasks.
 *
 * @param {String}  permission
 *
 * @return array may return null if permission/object combination is not supported
 */
SecurityAcl.PermissionMap.prototype.getMasks = function (permission) {
  var self = this;
  
  if (typeof self._map[permission] === 'undefined') {
    return;
  }
  
  return self._map[permission];
};

/**
 * Whether this map contains the given permission.
 *
 * @param {String}  permission
 *
 * @return {Boolean}
 */
SecurityAcl.PermissionMap.prototype.contains = function (permission) {
  var self = this;
  
  return (typeof self._map[permission] !== 'undefined');
};