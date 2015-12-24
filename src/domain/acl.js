
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}

/**
 * An ACL implementation.
 *
 * Each object identity has exactly one associated ACL. Each ACL can have four
 * different types of ACEs (class ACEs, object ACEs, class field ACEs, object field
 * ACEs).
 *
 * You should not iterate over the ACEs yourself, but instead use isGranted(),
 * or isFieldGranted(). 
 * 
 */
SecurityAcl.Acl = function (id, oid, permissionGrantingStrategy, loadedSids, 
                            entriesInheriting) {
  var self = this;
  
  if (! (self instanceof SecurityAcl.Acl)) {
    throw new Error('Use "new" to construct a SecurityAcl.Acl');
  }
  
  
  if (id === null || typeof id === 'undefined') {
    throw new Meteor.Error(
      'invalid-argument',
      'The id cannot be null or undefined.');
  }
  
  if (! (oid instanceof SecurityAcl.ObjectIdentity)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The oid must be an instance of SecurityAcl.ObjectIdentity.');
  }
    
  if (! (permissionGrantingStrategy instanceof SecurityAcl.PermissionGrantingStrategy)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The permissionGrantingStrategy must be an instance of ' +
      'SecurityAcl.PermissionGrantingStrategy.');
  }
    
  if (! (loadedSids instanceof Array)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The loadedSids must be an array.');
  }
  
  
  if (typeof entriesInheriting !== 'boolean') {
    throw new Meteor.Error(
      'invalid-argument',
      'The entriesInheriting must be a boolean.');
  }

  self._id = id;
  self._oid = oid;
  self._permissionGrantingStrategy = permissionGrantingStrategy;
  self._loadedSids = loadedSids;
  self._entriesInheriting = entriesInheriting;
  
  self._classAces = {};
  self._classFieldAces = {};
  self._objectAces = {};
  self._objectFieldAces = {};
  
  self._parentAcl = null;
  
  self._listeners = [];
};


// Main API for ACL

/**
 * Adds a property changed listener.
 *
 * @param {Object} SecurityAcl.Service     listener
 */
SecurityAcl.Acl.prototype.addPropertyChangedListener = function (listener) {
  var self = this;
  
  if (! (listener instanceof SecurityAcl.Service)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The argument must be an instance of SecurityAcl.Service.');
  }
    
  self._listeners.push(listener);
  
};

// Returns the id of the ACL.
SecurityAcl.Acl.prototype.id = function () {
  var self = this;

  return self._id;
};

// Returns the object identity associated with this ACL.
SecurityAcl.Acl.prototype.objectIdentity = function () {
  var self = this;

  return self._oid;
};


/**
 * Whether this ACL is inheriting ACEs from a parent ACL.
 *
 * @return {Boolean}
 */
SecurityAcl.Acl.prototype.isEntriesInheriting = function () {
  var self = this;

  return self._entriesInheriting;
};

// Set the entriesInheriting
SecurityAcl.Acl.prototype.setEntriesInheriting = function (entriesInheriting) {
  var self = this;
  
  self._onPropertyChanged('entriesInheriting', 
                          self.isEntriesInheriting(),
                          entriesInheriting);

  self._entriesInheriting = entriesInheriting;
};

// Set the classAces
SecurityAcl.Acl.prototype.setClassAces = function (classAces) {
  var self = this;

  self._classAces = classAces;
};

// Returns the classAces associated with this ACL.
SecurityAcl.Acl.prototype.classAces = function () {
  var self = this;

  return self._classAces;
};

// Set the classFieldAces
SecurityAcl.Acl.prototype.setClassFieldAces = function (classFieldAces) {
  var self = this;

  self._classFieldAces = classFieldAces;
};

//get the classFieldAces
SecurityAcl.Acl.prototype.classFieldAces = function (field) {
  var self = this;
  if (typeof self._classFieldAces[field] !== 'undefined') {
    return self._classFieldAces[field];
  } else {
    return [];
  }
};

// Set the objectAces
SecurityAcl.Acl.prototype.setObjectAces = function (objectAces) {
  var self = this;

  self._objectAces = objectAces;
};

// get the objectAces
SecurityAcl.Acl.prototype.objectAces = function () {
  var self = this;
  
  return self._objectAces;
};

// Set the objectFieldAces
SecurityAcl.Acl.prototype.setObjectFieldAces = function (objectFieldAces) {
  var self = this;

  self._objectFieldAces = objectFieldAces;
};

// get the objectFieldAces
SecurityAcl.Acl.prototype.objectFieldAces = function (field) {
  var self = this;
  if (typeof self._objectFieldAces[field] !== 'undefined') {
    return self._objectFieldAces[field];
  } else {
    return [];
  }
};

// Set the parentAcl
SecurityAcl.Acl.prototype.setParentAcl = function (acl) {
  var self = this;
  
  if (! (acl instanceof SecurityAcl.Acl)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The acl must be an instance of SecurityAcl.Acl.');
  }
    
  if (null !== acl && null === acl.id()) {
    throw new Meteor.Error(
      'invalid-argument',
      'The acl cannot be null and the id must be defined.');
  }
    
  self._onPropertyChanged('parentAcl', self.parentAcl(), acl);
  self._parentAcl = acl;
};



// Returns the parent ACL.
SecurityAcl.Acl.prototype.parentAcl = function () {
  var self = this;

  return self._parentAcl;
};

/**
 * Determines whether field access is granted.
 *
 * @param {String}   field
 * @param {Array}    masks
 * @param {Array}    securityIdentities
 * @param {Boolean}  administrativeMode
 *
 * @return {Boolean}
 */
SecurityAcl.Acl.prototype.isFieldGranted = function (field, masks, 
                                                     securityIdentities,
                                                     administrativeMode) {
  var self = this;
  
  if (typeof administrativeMode === 'undefined') {
    administrativeMode = false;
  }
  
  return self._permissionGrantingStrategy.isFieldGranted(self, field, masks,
                                                         securityIdentities,
                                                         administrativeMode);
};

/**
 * Determines whether access is granted.
 *
 * @param {Array}    masks
 * @param {Array}    securityIdentities
 * @param {Boolean}  administrativeMode
 *
 * @throws no-ace-found-exception when no ACE was applicable for this request
 *
 * @return {Boolean}
 */
SecurityAcl.Acl.prototype.isGranted = function (masks, securityIdentities, 
                                                administrativeMode) {
  var self = this;
  
  if (typeof administrativeMode === 'undefined') {
    administrativeMode = false;
  }
  
  return self._permissionGrantingStrategy.isGranted(self, masks, 
                                                    securityIdentities,
                                                    administrativeMode);
};

/**
 * Whether the ACL has loaded ACEs for all of the passed security identities.
 *
 * @param {Object} SecurityIdentities sids
 *
 * @return {Boolean}
 */

SecurityAcl.Acl.prototype.isSidLoaded = function (sids) {
  var self = this;
  
  if (!self._loadedSids) {
    return true;
  }
  
  if (! (sids instanceof Array)) {
    sids = [sids];
  }
  
  loopSids: for (var i in sids) {
    if(!sids.hasOwnProperty(i)) {
      continue;
    }
    
    var sid = sids[i];
    if (! (sid instanceof SecurityAcl.SecurityIdentity)) {
      throw new Meteor.Error(
        'invalid-argument',
        'Sid must be an instance of SecurityAcl.SecurityIdentity.');
    }
    
    for (var j in self._loadedSids) {
      if(!self._loadedSids.hasOwnProperty(j)) {
        continue;
      }
      
      var loadedSid = self._loadedSids[j];
      if (loadedSid.equals(sid)) {
        continue loopSids;
      }
    }
    
    return false;
  }

  return true;
};

SecurityAcl.Acl.prototype.insertClassAce = function (sid, mask, index, 
                                                     granting, strategy) {
  var self = this;
  
  if (! (sid instanceof SecurityAcl.SecurityIdentity)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The sid must be an instance of SecurityAcl.SecurityIdentity.');
  }
    
  if (typeof index === 'undefined') {
    index = 0;
  }
  
  if (typeof granting === 'undefined') {
    granting = true;
  }
  
  if (typeof strategy === 'undefined') {
   strategy = null;
  }
  
  self._insertAce('classAces', index, mask, sid, granting, strategy);
};

SecurityAcl.Acl.prototype.insertClassFieldAce = function (field, sid, mask,
                                                          index, granting,
                                                          strategy) {
  var self = this;
  
  if (! (sid instanceof SecurityAcl.SecurityIdentity)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The sid must be an instance of SecurityAcl.SecurityIdentity.');
  }
    
  if (typeof index === 'undefined') {
    index = 0;
  }
  
  if (typeof granting === 'undefined') {
    granting = true;
  }
  
  if (typeof strategy === 'undefined') {
   strategy = null;
  }
  
  self._insertFieldAce('classFieldAces', index, field, mask, sid, granting, strategy);
};

SecurityAcl.Acl.prototype.insertObjectAce = function (sid, mask, index,
                                                      granting, strategy) {
  var self = this;
  
  if (typeof index === 'undefined') {
    index = 0;
  }
  
  if (typeof granting === 'undefined') {
    granting = true;
  }
  
  if (typeof strategy === 'undefined') {
   strategy = null;
  }
  
  self._insertAce('objectAces', index, mask, sid, granting, strategy);
};

SecurityAcl.Acl.prototype.insertObjectFieldAce = function (field, sid, mask,
                                                           index, granting, strategy) {
  var self = this;
  
  if (! (sid instanceof SecurityAcl.SecurityIdentity)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The sid must be an instance of SecurityAcl.SecurityIdentity.');
  }
    
  if (typeof index === 'undefined') {
    index = 0;
  }
  
  if (typeof granting === 'undefined') {
    granting = true;
  }
  
  if (typeof strategy === 'undefined') {
   strategy = null;
  }
  
  self._insertFieldAce('objectFieldAces', index, field, mask, sid, granting, strategy);
};

SecurityAcl.Acl.prototype.updateClassAce = function (index, mask, strategy) {
  var self = this;
  
  if (typeof strategy === 'undefined') {
    strategy = null;
  }
  
  self._updateAce('classAces', index, mask, strategy);
};

SecurityAcl.Acl.prototype.updateClassFieldAce = function (index, field, mask, strategy) {
  var self = this;
  
  if (typeof strategy === 'undefined') {
    strategy = null;
  }
  
  self._updateFieldAce('classFieldAces', index, field, mask, strategy);
};

SecurityAcl.Acl.prototype.updateObjectAce = function (index, mask, strategy) {
  var self = this;
  
  if (typeof strategy === 'undefined') {
    strategy = null;
  }
  
  self._updateAce('objectAces', index, mask, strategy);
};

SecurityAcl.Acl.prototype.updateObjectFieldAce = function (index, field, mask, strategy) {
  var self = this;
  
  if (typeof strategy === 'undefined') {
    strategy = null;
  }
  
  self._updateFieldAce('objectFieldAces', index, field, mask, strategy);
};


SecurityAcl.Acl.prototype.deleteClassAce = function (index) {
  var self = this;
  
  self._deleteAce('classAces', index);
};

SecurityAcl.Acl.prototype.deleteClassFieldAce = function (index, field) {
  var self = this;
  
  self._deleteFieldAce('classFieldAces', index, field);
};

SecurityAcl.Acl.prototype.deleteObjectAce = function (index) {
  var self = this;
  
  self._deleteAce('objectAces', index);
};

SecurityAcl.Acl.prototype.deleteObjectFieldAce = function (index, field) {
  var self = this;
  
  self._deleteFieldAce('objectFieldAces', index, field);
};


/**
 * Inserts an ACE.
 *
 * @param {String}                    property
 * @param {Integer}                   index
 * @param {Integer}                   mask
 * @param {Object}  SecurityIdentity  sid
 * @param {Boolean}                   granting
 * @param {String}                    strategy
 *
 * @throws \out-of-bounds-exception
 * @throws \invalid-argument
 */
SecurityAcl.Acl.prototype._insertAce = function (property, index, mask, sid,
                                                 granting, strategy) {
  var self = this;
  
  if (! (sid instanceof SecurityAcl.SecurityIdentity)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The sid must be an instance of SecurityAcl.SecurityIdentity.');
  }
    
  if (typeof strategy === 'undefined') {
    strategy = null;
  }
  
  if (! Number.isInteger(index)) {
    throw new Meteor.Error('invalid-argument', 'The index must be an integer.');
  }
  
  if (index < 0 || index > Object.keys(self['_'+property]).length) {
    throw new Meteor.Error(
      'out-of-bounds-exception',
      'The index must be in the interval ' +
      '[0-'+Object.keys(self['_'+property]).length+']');
  }
  
  if (! Number.isInteger(mask)) {
    throw new Meteor.Error('invalid-argument', 'The mask must be an integer.');
  }
  
  if (null === strategy) {
    if (true === granting) {
      strategy = 'ALL';
    } else {
      strategy = 'ANY';
    }
  }
  
  var aces = self['_'+property];
  var oldValue = JSON.parse(JSON.stringify(JSON.decycle(self['_'+property])));
  
  if (typeof aces[index] !== 'undefined') {
    
    for (var i = Object.keys(self['_'+property]).length - 1;  i >= index ; i--) {
      aces[i+1] = aces[i];
    }
    
    var c = null;
    for (i = index, c = Object.keys(self['_'+property]).length - 1; i < c; i++) {
      self._onEntryPropertyChanged(aces[i + 1], 'aceOrder', i, i + 1);
    }
  }
  
  aces[index] = new SecurityAcl.Entry(null, self, sid, strategy, mask,
                                      granting, false, false);
  self._onPropertyChanged(property, oldValue, self['_'+property]);
  
};

/**
 * Inserts a field-based ACE.
 *
 * @param {String}               property
 * @param {Integer}              index
 * @param {String}               field
 * @param {Integer}              mask
 * @param {Object}               sid
 * @param {Boolean}              granting
 * @param {String}               strategy
 *
 * @throws \invalid-argument
 * @throws \out-of-bounds-exception
 */
SecurityAcl.Acl.prototype._insertFieldAce = function (property, index, field,
                                                      mask, sid, granting,
                                                      strategy) {
  var self = this;
  
  if (0 === field.length) {
    throw new Meteor.Error('invalid-argument', 'Field cannot be empty.');
  }
  
  if (! (sid instanceof SecurityAcl.SecurityIdentity)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The sid must be an instance of SecurityAcl.SecurityIdentity.');
  }
    
  
  if (! Number.isInteger(mask)) {
    throw new Meteor.Error('invalid-argument', 'The mask must be an integer.');
  }
  
  if (null === strategy) {
    if (true === granting) {
      strategy = 'ALL';
    } else {
      strategy = 'ANY';
    }
  }
  
  var aces = self['_'+property];
  
  if (typeof aces[field] === 'undefined') {
    aces[field] = {};
  }
  
  if (! Number.isInteger(index)) {
    throw new Meteor.Error('invalid-argument', 'The index must be an integer.');
  }
  
  if (index < 0 || index > Object.keys(aces[field]).length) {
    throw new Meteor.Error(
      'out-of-bounds-exception',
      'The index must be in the interval [0-'+Object.keys(aces[field]).length+']');
  }
  
  var oldValue = JSON.parse(JSON.stringify(JSON.decycle(aces)));
  
  if (typeof aces[field][index] !== 'undefined') {
    for (var i = Object.keys(aces[field]).length - 1;  i >= index ; i--) {
      aces[field][i+1] = aces[field][i];
    }
    var c = null;
    for (i = index, c = Object.keys(aces[field]).length - 1; i < c; i++) {
      self._onEntryPropertyChanged(aces[field][i + 1], 'aceOrder', i, i + 1);
    }
  }
  
  aces[field][index] = new SecurityAcl.FieldEntry(null, self, field, sid,
                                                  strategy, mask, granting,
                                                  false, false);
  self._onPropertyChanged(property, oldValue, self['_'+property]);
  
};

/**
 * Updates an ACE.
 *
 * @param {String}   property
 * @param {Integer}  index
 * @param {Integer}  mask
 * @param {String}   strategy
 *
 * @throws \out-of-bounds-exception
 */
SecurityAcl.Acl.prototype._updateAce = function (property, index, mask, strategy) {
var self = this;
  
  if (typeof strategy === 'undefined') {
    strategy = null;
  }
  
  if (! Number.isInteger(index)) {
    throw new Meteor.Error('invalid-argument', 'The index must be an integer.');
  }
  
  if (! Number.isInteger(mask)) {
    throw new Meteor.Error('invalid-argument', 'The mask must be an integer.');
  }
  
  var aces = self['_'+property];
  
  if (typeof aces[index] === 'undefined') {
    throw new Meteor.Error(
      'out-of-bounds-exception',
      'The index '+index+' does not exist.');
  }
  
  var ace = aces[index];
  var oldMask = ace.mask();
  if (mask !== oldMask) {
    self._onEntryPropertyChanged(ace, 'mask', oldMask, mask);
    ace.setMask(mask);
  }
  
  var oldStrategy = ace.strategy();
  if (null !== strategy && strategy !== oldStrategy) {
    self._onEntryPropertyChanged(ace, 'strategy', oldStrategy, strategy);
    ace.setStrategy(strategy);
  }
  
};

/**
 * Updates a field-based ACE.
 *
 * @param {String}     property
 * @param {Integer}    index
 * @param {String}     field
 * @param {Integer}    mask
 * @param {String}     strategy
 *
 * @throws \invalid-argument
 * @throws \out-of-bounds-exception
 */
SecurityAcl.Acl.prototype._updateFieldAce = function (property, index, field,
                                                      mask, strategy) {
  var self = this;
  
  if (0 === field.length) {
    throw new Meteor.Error('invalid-argument', 'Field cannot be empty.');
  }
  
  if (typeof strategy === 'undefined') {
    strategy = null;
  }
  
  if (! Number.isInteger(index)) {
    throw new Meteor.Error('invalid-argument', 'The index must be an integer.');
  }
  
  if (! Number.isInteger(mask)) {
    throw new Meteor.Error('invalid-argument', 'The mask must be an integer.');
  }
  
  var aces = self['_'+property];
  
  if (typeof aces[field] === 'undefined' ||
      typeof aces[field][index] === 'undefined') {
    throw new Meteor.Error(
      'out-of-bounds-exception',
      'The index '+index+' does not exist.');
  }
  
  var ace = aces[field][index];
  var oldMask = ace.mask();
  if (mask !== oldMask) {
    self._onEntryPropertyChanged(ace, 'mask', oldMask, mask);
    ace.setMask(mask);
  }
  
  var oldStrategy = ace.strategy();
  if (null !== strategy && strategy !== oldStrategy) {
    self._onEntryPropertyChanged(ace, 'strategy', oldStrategy, strategy);
    ace.setStrategy(strategy);
  }
  
};

/**
 * Deletes an ACE.
 *
 * @param {String}     property
 * @param {Integer}    index
 *
 * @throws \out-of-bounds-exception
 */
SecurityAcl.Acl.prototype._deleteAce = function (property, index) {
  var self = this;
  
  if (! Number.isInteger(index)) {
    throw new Meteor.Error('invalid-argument', 'The index must be an integer.');
  }
  
  var aces = self['_'+property];
  
  if (typeof aces[index] === 'undefined') {
    throw new Meteor.Error(
      'out-of-bounds-exception',
      'The index '+index+' does not exist.');
  }
  
  var oldValue = JSON.parse(JSON.stringify(JSON.decycle(self['_'+property])));
  
  delete aces[index];
  
  for (var i = index, c = Object.keys(self['_'+property]).length;  i < c; i++) {
    aces[i] = aces[i+1];
  }
  delete aces[i];
  
  self._onPropertyChanged(property, oldValue, self['_'+property]);
  
  for (i = index, c = Object.keys(self['_'+property]).length; i < c; i++) {
    self._onEntryPropertyChanged(aces[i], 'aceOrder', i+1, i);
  }
};

/**
 * Deletes a field-based ACE.
 *
 * @param {String}   property
 * @param {Integer}  index
 * @param {String}   field
 *
 * @throws \out-of-bounds-exception
 */
SecurityAcl.Acl.prototype._deleteFieldAce = function (property, index, field) {
  var self = this;
  
  if (0 === field.length) {
    throw new Meteor.Error('invalid-argument', 'Field cannot be empty.');
  }
  
  if (! Number.isInteger(index)) {
    throw new Meteor.Error('invalid-argument', 'The index must be an integer.');
  }
  
  var aces = self['_'+property];
  
  if (typeof aces[field] === 'undefined' ||
      typeof aces[field][index] === 'undefined') {
    throw new Meteor.Error(
      'out-of-bounds-exception',
      'The index '+index+' does not exist.');
  }
  
  var oldValue = JSON.parse(JSON.stringify(JSON.decycle(self['_'+property])));
  delete aces[field][index];
  
  for (var i = index, c = Object.keys(aces[field]).length;  i < c; i++) {
    aces[field][i] = aces[field][i+1];
  }
  delete aces[field][i];
  
  self._onPropertyChanged(property, oldValue, self['_'+property]);
  
  for (i = index, c = Object.keys(aces[field]).length; i < c; i++) {
    self._onEntryPropertyChanged(aces[field][i], 'aceOrder', i+1, i);
  }
};


/**
 * Called when a property of the ACL changes.
 *
 * @param {String} name
 * @param {mixed}  oldValue
 * @param {mixed}  newValue
 */
SecurityAcl.Acl.prototype._onPropertyChanged = function (name, oldValue, newValue) {
  var self = this;
  
  for (var i in self._listeners) {
    if(!self._listeners.hasOwnProperty(i)) {
      continue;
    }
    
    var listener = self._listeners[i];
    listener.propertyChanged(self, name, oldValue, newValue);
  }
};


/**
 * Called when a property of an ACE associated with this ACL changes.
 *
 * @param {Object} Entry    entry
 * @param {String}          name
 * @param {mixed}           oldValue
 * @param {mixed}           newValue
 * 
 * @throws \invalid-argument
 */
SecurityAcl.Acl.prototype._onEntryPropertyChanged = function (entry, name,
                                                              oldValue,
                                                              newValue) {
  var self = this;
  
  if (! (entry instanceof SecurityAcl.Entry)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The entry must be an instance of SecurityAcl.Entry.');
  }
    
  for (var i in self._listeners) {
    if(!self._listeners.hasOwnProperty(i)) {
      continue;
    }
    
    var listener = self._listeners[i];
    listener.propertyChanged(entry, name, oldValue, newValue);
  }
};

