
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}

/**
 * Provides support for creating and storing ACL instances.
 * 
 */
SecurityAcl.Service = function () {
  
  var self = this;
  
  if (! (self instanceof SecurityAcl.Service)) {
    throw new Error('Use "new" to construct a SecurityAcl.Service');
  }
  
  self._loadedAces = [];
  self._loadedAcls = {};
  self._permissionGrantingStrategy = new SecurityAcl.PermissionGrantingStrategy();
  
  self.MAX_BATCH_SIZE = 30;
  
  // track changes of an ACL or an ACE.
  self._propertyChanges = {};
};

// Main API for ServiceAcl

/**
 * Creates a new ACL for the given object identity.
 * 
 */
SecurityAcl.Service.prototype.createAcl = function (oid) {
  var self = this;
  
  if (! (oid instanceof SecurityAcl.ObjectIdentity)) {
    throw new Meteor.Error(
      'invalid-argument', 
      'The argument must be an instance of SecurityAcl.ObjectIdentity.');
  }
    
  if (null !== self.retrieveObjectIdentityPrimaryKey(oid)) {
    throw new Meteor.Error(
     'ACL-already-exists',
     'The oid "+oid.identifier()+" is already associated with an ACL.');
  }
  
  try {
    self._createObjectIdentity(oid);
    
    var pk = self.retrieveObjectIdentityPrimaryKey(oid);
    
    if (pk === null) {
      throw new Meteor.Error(
        'object-identity-primary-key-not-found',
        'The primary key of the oid '+oid.identifier()+' not found.');
    }
    
    SecurityAcl.ObjectIdentitiesAncestors.insert({ 
      'objectIdentityId': pk,
      'ancestorId': pk});

  } catch (e) {
    throw e;
  }
  
  // re-read the ACL from the database
  return self.findAcl(oid);
};

/**
 * Returns the ACL that belongs to the given object identity.
 *
 * @param {Object}  ObjectIdentity    oid
 * @param {Array}   SecurityIdentity  sids
 *
 * @return {Object}  Acl
 *
 * @throws acl-not-found-exception when there is no ACL
 */
SecurityAcl.Service.prototype.findAcl = function (oid, sids) {
  var self = this;
  
  if (typeof sids === 'undefined') { 
    sids = []; 
  }
  
  return self.findAcls([oid], sids)[0][1];
};

/**
 * Returns the ACLs that belong to the given object identities.
 *
 * @param {Array}  ObjectIdentity    oids
 * @param {Array}  SecurityIdentity  sids
 *
 * @return {Array} mapping the passed object identities to ACLs
 *
 * @throws acl-not-found-exception when we cannot find an ACL for all identities
 */
SecurityAcl.Service.prototype.findAcls = function (oids, sids) {
  var self = this;
  
  if (typeof sids === 'undefined') { 
    sids = []; 
  }
  
  var result = [];
  var oidLookup = [];
  var currentBatch = [];
  
  for (var i = 0; i < oids.length; i++) {
    var oid = oids[i];
    var oidLookupKey = oid.identifier()+oid.type();
    oidLookup[oidLookupKey] = oid;
    var aclFound = false;
    
    // check if result already contains an ACL
    for (var j = 0; j < result.length; j++) {
      if (result[j][0] === oid ) {
        aclFound = true;
        break;
      }
    }
    
    // check if this ACL has already been hydrated
    if (!aclFound &&
        typeof self._loadedAcls[oid.type()] !== 'undefined' &&
        typeof self._loadedAcls[oid.type()][oid.identifier()] !== 'undefined') {
      
      var acl = self._loadedAcls[oid.type()][oid.identifier()];

      // TODO check isSidLoaded
      
      result.push([oid, acl]);
      aclFound = true;
      
    }
    
    
    // looks like we have to load the ACL from the database
    if (!aclFound) {
        currentBatch.push(oid);
    }
    
    // Is it time to load the current batch?
    var currentBatchesCount = currentBatch.length;
    
    if (currentBatchesCount > 0 &&
        (self.MAX_BATCH_SIZE === currentBatchesCount || (i+1) === oids.length)) {
      try {
        var loadedBatch = self._lookupObjectIdentities(currentBatch, sids, oidLookup);
      } catch (e) {
        if (result.length) {
          throw new Meteor.Error(
            'not-all-acls-found',
            'The service could not find ACLs for all object identities.');
        } else {
          throw e;
        }
      }
      
      for (i in loadedBatch) {
        if(! loadedBatch.hasOwnProperty(i)) {
          continue;
        }
        
        var loadedOid = loadedBatch[i][0];
        var loadedAcl = loadedBatch[i][1];
        
        if (loadedOid.identifier() === oid.identifier() ||
          loadedOid.type() === oid.type) {
          result.push([loadedOid, loadedAcl]);
        }
      }
      
      currentBatch = [];
    }
  }
  
  // TODO check all ACLs
  //check that we got ACLs for all the identities
  
  
  // Add listener to track the changes
  for (i = 0; i < result.length; i++ ) {
    acl = result[i][1];
    
    if (typeof self._propertyChanges[acl.id()] === 'undefined' &&
        acl instanceof SecurityAcl.Acl) {
      acl.addPropertyChangedListener(self);
      self._propertyChanges[acl.id()] = {};
      
      // If we use ObjectID as object key, we encounter a problem because
      // the ObjectID is converted to a string e.g. 'ObjectID("3a4b...")'.
      // This string is not a valid id to retrieve a document in MongoDB.
      // To fix this problem we add an ACL property to retrieve the valid id.
      self._propertyChanges[acl.id()]['acl'] = acl;
    }
  }
  
  return result;
};

/**
 * Deletes the ACL for a given object identity.
 * 
 * @param {Object}  ObjectIdentity  oid
 *
 * NOTE: deleteAcl() doesn't delete classAces or 
 * classFieldAces.
 * 
 */
SecurityAcl.Service.prototype.deleteAcl = function (oid) {
  var self = this;
  
  if (! (oid instanceof SecurityAcl.ObjectIdentity)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The oid must be an instance of SecurityAcl.ObjectIdentity.');
  }
  
  try {
    var childOids = self.findChildren(oid, true);
    for (var i in childOids) {
      if(!childOids.hasOwnProperty(i)) {
        continue;
      }
      var childOid =  childOids[i];
      self.deleteAcl(childOid);
    }
    
    var oidPK = self.retrieveObjectIdentityPrimaryKey(oid);
    
    self._deleteAccessControlEntries(oidPK);
    self._deleteObjectIdentityRelations(oidPK);
    self._deleteObjectIdentity(oidPK);
    
  } catch (e) {
    throw e;
  }
  
  // evict the ACL from the in-memory identity map
  if (typeof self._loadedAcls[oid.type()] !== 'undefined' &&
      typeof self._loadedAcls[oid.type()][oid.identifier()] !== 'undefined') {
    var acl = self._loadedAcls[oid.type()][oid.identifier()];
    delete self._propertyChanges[acl.id()];
  }
};

/**
 * Deletes the security identity from the database.
 * ACL entries for the security identity will also get deleted.
 *
 * @param {Object}  SecurityIdentity  sid
 *
 * @throws \invalid-argument
 */
SecurityAcl.Service.prototype.deleteSecurityIdentity = function (sid) {
  var self = this;
  
  var securityIdentityId = self._getSecurityIdentityId(sid);
  
  // remove all the aces of sid
  SecurityAcl.Entries.remove({ 'securityIdentityId': securityIdentityId });
  
  // remove sid
  SecurityAcl.SecurityIdentities.remove({ '_id': securityIdentityId });

};

/**
 * Updates the ACL for the given ACL.
 *
 */
SecurityAcl.Service.prototype.updateAcl = function (acl) {
  var self = this;
  
  // check if the ACL is tracked by the service
  if (typeof self._propertyChanges[acl.id()] === 'undefined') {
    throw new Meteor.Error(
      'invalid-argument',
      'The ACL is not tracked by this service.');
  }
  
  var propertyChanges = self._propertyChanges[acl.id()];
  
  // check if any changes were made to this ACL
  if (Object.keys(propertyChanges).length === 0) {
    return;
  }
  
  var sets = {};
  var sharedPropertyChanges = {};
  
  if (typeof propertyChanges['entriesInheriting'] !== 'undefined') {
    sets.entriesInheriting = acl.isEntriesInheriting();
  }
  
  if (typeof propertyChanges['parentAcl'] !== 'undefined') {
    var parentObjectIdentityId = null;
    
    if (acl.parentAcl() !== null) {
      parentObjectIdentityId = acl.parentAcl()._id;
    }
    
    sets.parentObjectIdentityId = parentObjectIdentityId;
    
    // if parentAcl updated, we must update ancestorIds.
    var ancestor = SecurityAcl.ObjectIdentitiesAncestors.findOne({
      'objectIdentityId': acl._id,
      'ancestorId': parentObjectIdentityId });
    
    // an ancestor exists in database. It must be updated or deleted.
    if (typeof ancestor !== 'undefined') {
      // we must update ancestor if the parentAcl is different.
      if (ancestor.ancestorId !== parentObjectIdentityId) {
        // we must regenerate all ancestor relations
        self._regenerateAncestorRelations(acl);
        // we must regenerate ancestor relations for child ACLs.
        var childAcls = self.findAcls(self.findChildren(acl.objectIdentity(), false));
        
        for (var i = 0; i < childAcls.length; i++) {
          self._regenerateAncestorRelations(childAcls[i][1]);
        }
      }
      // we must delete ancestor if there is no parentAcl.
      if (parentObjectIdentityId === null) {
        SecurityAcl.ObjectIdentitiesAncestors.remove({
          'objectIdentityId': acl._id,
          'ancestorId': { $ne: acl._id }});
      }
    } else {
      // ancestor doesn't exist and a new parentAcl exists.
      if (parentObjectIdentityId !== null) {
        // we must regenerate ancestors
        self._regenerateAncestorRelations(acl);
        // we must regenerate ancestor relations for child ACLs.
        childAcls = self.findAcls(self.findChildren(acl.objectIdentity(), false));
        
        for (i = 0; i < childAcls.length; i++) {
          self._regenerateAncestorRelations(childAcls[i][1]);
        }
      }
    }
  }

  // check properties for deleted, and created ACEs, and perform deletions
  // we need to perform deletions before updating existing ACEs, in order to
  // preserve uniqueness of the order field
  if (typeof propertyChanges['classAces'] !== 'undefined') {
    self._updateOldAceProperty('classAces', propertyChanges['classAces']);
  }
  
  if (typeof propertyChanges['classFieldAces'] !== 'undefined') {
    self._updateOldFieldAceProperty(
      'classFieldAces',
      propertyChanges['classFieldAces']);
  }
  
  if (typeof propertyChanges['objectAces'] !== 'undefined') {
    self._updateOldAceProperty('objectAces', propertyChanges['objectAces']);
  }
  
  if (typeof propertyChanges['objectFieldAces'] !== 'undefined') {
    self._updateOldFieldAceProperty(
      'objectFieldAces',
      propertyChanges['objectFieldAces']);
  }
  
  // this includes only updates of existing ACEs, but neither the creation, nor
  // the deletion of ACEs; these are tracked by changes to the ACL's respective
  // properties (classAces, classFieldAces, objectAces, objectFieldAces)
  if (typeof propertyChanges['aces'] !== 'undefined') {
    self._updateAces(propertyChanges['aces']);
  }
  
  // check properties for deleted, and created ACEs, and perform creations
  if (typeof propertyChanges['classAces'] !== 'undefined') {
    self._updateNewAceProperty('classAces', propertyChanges['classAces']);
    sharedPropertyChanges['classAces'] = propertyChanges['classAces'];
  }
  
  if (typeof propertyChanges['classFieldAces'] !== 'undefined') {
    self._updateNewFieldAceProperty('classFieldAces', propertyChanges['classFieldAces']);
    sharedPropertyChanges['classFieldAces'] = propertyChanges['classFieldAces'];
  }
  
  if (typeof propertyChanges['objectAces'] !== 'undefined') {
    self._updateNewAceProperty('objectAces', propertyChanges['objectAces']);
  }
  
  if (typeof propertyChanges['objectFieldAces'] !== 'undefined') {
    self._updateNewFieldAceProperty(
      'objectFieldAces',
      propertyChanges['objectFieldAces']);
  }
  
  // if there have been changes to shared properties, we need to synchronize other
  // ACL instances for object identities of the same type that are already in-memory
  if (Object.keys(sharedPropertyChanges).length > 0) {
    
    for (var key in self._loadedAcls[acl.objectIdentity().type()] ){
      if(!self._loadedAcls[acl.objectIdentity().type()].hasOwnProperty(key)) {
        continue;
      }
      
      var sameTypeAcl = self._loadedAcls[acl.objectIdentity().type()][key];
      
      if (typeof sharedPropertyChanges['classAces'] !== 'undefined') {
        // TODO Concurrent modification exception
        
        sameTypeAcl.setClassAces(sharedPropertyChanges['classAces'][1]);
      }
      
      if (typeof sharedPropertyChanges['classFieldAces'] !== 'undefined') {
        // TODO Concurrent modification exception
        
        sameTypeAcl.setClassFieldAces(sharedPropertyChanges['classFieldAces'][1]);
      }
    }
  }

  // persist any changes to the acl_object_identities collection
  if (Object.keys(sets).length > 0) {
    SecurityAcl.ObjectIdentities.update(acl.id(), {
      $set: sets
    });
  }
  
  self._propertyChanges[acl.id()] = {};
  // we must keep acl as a property
  self._propertyChanges[acl.id()]['acl'] = acl;
};

/**
 * Updates all the ACLs with property changes.
 */
SecurityAcl.Service.prototype.updateAcls = function () {
  var self = this;
  
  for(var key in self._propertyChanges) {
    if(!self._propertyChanges.hasOwnProperty(key)) {
      continue;
    }
    var acl = self._propertyChanges[key]['acl'];
    
    if (typeof acl !== 'undefined') {
      self.updateAcl(acl);
    }
  }
};


/**
 * Implementation of propertyChanged.
 *
 * This allows us to keep track of which values have been changed, so we don't
 * have to do a full introspection when updateAcl() is called.
 *
 * @param {mixed}     sender
 * @param {String}    propertyName
 * @param {mixed}     oldValue
 * @param {mixed}     newValue
 *
 * @throws \invalid-argument
 */
SecurityAcl.Service.prototype.propertyChanged = function (sender, propertyName,
                                                          oldValue, newValue) {
  var self = this;
  
  if (! (sender instanceof SecurityAcl.Acl) &&
      ! (sender instanceof SecurityAcl.Entry)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The sender must be an instance of SecurityAcl.Acl or SecurityAcl.Entry.');
  }
    
  var ace = null;
  if (sender instanceof SecurityAcl.Entry) {
    if (null === sender.id()) {
      return;
    }
    
    ace = sender;
    sender = ace.acl();
  }
  
  if (typeof self._propertyChanges[sender.id()] === 'undefined') {
    throw new Meteor.Error(
      'invalid-argument',
      'The sender is not tracked by this service.');
  }
    
  var propertyChanges = self._propertyChanges[sender.id()];
  
  if (null === ace) {
    if (typeof propertyChanges[propertyName] !== 'undefined') {
      oldValue = propertyChanges[propertyName][0];
      if (oldValue === newValue) {
        delete propertyChanges[propertyName];
      } else {
        propertyChanges[propertyName] = [oldValue, newValue];
      }
    } else {
      if (oldValue !== newValue) {
        propertyChanges[propertyName] = [oldValue, newValue];
      }
      
    }
  } else {
    if (typeof propertyChanges['aces'] === 'undefined') {
      propertyChanges['aces'] = {};
    }
    
    var acePropertyChanges = {};
    if (typeof propertyChanges['aces'][ace.id()] !== 'undefined') {
      acePropertyChanges = propertyChanges['aces'][ace.id()]['acePropertyChanges'];
    }
    
    if (typeof acePropertyChanges[propertyName] !== 'undefined') {
      oldValue = acePropertyChanges[propertyName][0];
      if (oldValue === newValue) {
        delete acePropertyChanges[propertyName];
      } else {
        acePropertyChanges[propertyName] = [oldValue, newValue];
      }
    } else {
      if (oldValue !== newValue) {
        acePropertyChanges[propertyName] = [oldValue, newValue];
      }
    }
    
    if (Object.keys(acePropertyChanges).length > 0) {
      // If we use ObjectID as object key, we encounter a problem because
      // the ObjectID is converted to a string e.g. 'ObjectID("3a4b...")'.
      // This string is not a valid id to retrieve a document in MongoDB.
      // To fix this problem we add an ACE property (used by _updateAces).
      propertyChanges['aces'][ace.id()] = {};
      propertyChanges['aces'][ace.id()]['ace'] = ace;
      propertyChanges['aces'][ace.id()]['acePropertyChanges'] = acePropertyChanges;
    } else {
      delete propertyChanges['aces'];
    }
    
  }
  
};

/**
 * Creates the ACL for the passed object identity.
 *
 */
SecurityAcl.Service.prototype._createObjectIdentity = function (oid) {
  var self = this;
  
  if (! (oid instanceof SecurityAcl.ObjectIdentity)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The argument must be an instance of SecurityAcl.ObjectIdentity.');
  }
    
  var classId = self._createOrRetrieveClassId(oid.type());
  
  // FIXME add constraint classId+objectIdentifier must be unique
  SecurityAcl.ObjectIdentities.insert({
    'parentObjectIdentityId': null,
    'classId': classId,
    'objectIdentifier': oid.identifier(),
    'entriesInheriting': true
  });
};

/**
 * Returns the primary key for the passed collection type.
 *
 * If the type does not yet exist in the database, it will be created.
 *
 * @param {String}    classType
 * 
 * @returns {Object}
 */
SecurityAcl.Service.prototype._createOrRetrieveClassId = function (classType) {
  
  if (classType === null || typeof classType === 'undefined') {
    throw new Meteor.Error(
      'invalid-argument',
      'The classType cannot be null or undefined.');
  }
  
  var document = SecurityAcl.Classes.findOne({ 'classType': classType });
  if (document) {
    return document._id;
  }
  
  return SecurityAcl.Classes.insert({ 'classType': classType });
  
};

/**
 * Returns the primary key of the given SecurityIdentity.
 * 
 * @param {Object}  SecurityIdentity  sid
 * 
 * @returns {Object|null}
 */
SecurityAcl.Service.prototype._getSecurityIdentityId = function (sid) {
  
  if (! (sid instanceof SecurityAcl.SecurityIdentity)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The sid must be an instance of SecurityAcl.SecurityIdentity.');
  }
    
  var identifier = null;
  var username = null;
  if (sid instanceof SecurityAcl.UserSecurityIdentity) {
    identifier = sid.className()+'-'+sid.username();
    username = true;
  } else if (sid instanceof SecurityAcl.RoleSecurityIdentity) {
    identifier = sid.role();
    username = false;
  } else {
    throw new Meteor.Error(
      'invalid-argument',
      'The sid must be an instance of UserSecurityIdentity or RoleSecurityIdentity.');
  }
  
  var document = SecurityAcl.SecurityIdentities.findOne({
    'identifier': identifier,
    'username': username
  });
  
  if (document) {
    return document._id;
  }
  
  return null;
};

/**
 * Returns the primary key for the passed security identity.
 *
 * If the security identity does not yet exist in the database, it will be
 * created.
 *
 * @param {Object}  SecurityIdentity    sid
 *
 * @return {Object}
 */
SecurityAcl.Service.prototype._createOrRetrieveSecurityIdentityId = function (sid) {
  
  if (! (sid instanceof SecurityAcl.SecurityIdentity)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The sid must be an instance of SecurityAcl.SecurityIdentity.');
  }
  
  var identifier = null;
  var username = null;
  if (sid instanceof SecurityAcl.UserSecurityIdentity) {
    identifier = sid.className()+'-'+sid.username();
    username = true;
  } else if (sid instanceof SecurityAcl.RoleSecurityIdentity) {
    identifier = sid.role();
    username = false;
  } else {
    throw new Meteor.Error(
      'invalid-argument',
      'The sid  must be an instance of UserSecurityIdentity or RoleSecurityIdentity.');
  }
  
  var document = SecurityAcl.SecurityIdentities.findOne({
    'identifier': identifier,
    'username': username
  });
  
  if (document) {
    return document._id;
  }
  
  return SecurityAcl.SecurityIdentities.insert({
    'identifier': identifier,
    'username': username
  });
};

/**
 * Returns the primary key of the passed object identity.
 *
 * @param {Object} ObjectIdentity oid
 * @return {Object|null}
 */
SecurityAcl.Service.prototype.retrieveObjectIdentityPrimaryKey = function (oid) {
  
  if (! (oid instanceof SecurityAcl.ObjectIdentity)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The argument must be an instance of SecurityAcl.ObjectIdentity.');
  }
  
  var aclOids = SecurityAcl.ObjectIdentities.find({
    'objectIdentifier': oid.identifier()
  }).fetch();
  
  for (var i in aclOids) {
    if(!aclOids.hasOwnProperty(i)) {
      continue;
    }
    
    var aclOid = aclOids[i];
    if (aclOid !== null && typeof aclOid !== 'undefined') {
      var aclClasses = SecurityAcl.Classes.findOne({ '_id': aclOid.classId });
      if (aclClasses.classType === oid.type()) {
        return aclOid._id;
      }
    }
  }

  return null;
};

/**
 * Deletes all ACEs for the given object identity primary key.
 *
 * @param {String}  oidPK
 */
SecurityAcl.Service.prototype._deleteAccessControlEntries = function (oidPK) {
  SecurityAcl.Entries.remove({ 'objectIdentityId': oidPK});
};

/**
 * Deletes all entries from the relations table from the database.
 *
 * @param {String}  pk
 */
SecurityAcl.Service.prototype._deleteObjectIdentityRelations = function (pk) {
  SecurityAcl.ObjectIdentitiesAncestors.remove({ 'objectIdentityId': pk });
};

/**
 * Deletes the object identity from the database.
 *
 * @param {String}  pk
 */
SecurityAcl.Service.prototype._deleteObjectIdentity = function (pk) {
  SecurityAcl.ObjectIdentities.remove({ '_id': pk });
};

/**
 * This function is called to retrieve the object identities associated with
 *  ACL from database.
 *
 * @param {Array} batch
 * @param {Array} sids
 * @param {Array} oidLookup
 *
 * @return {Array} mapping object identities to ACL instances
 *
 * @throws acl-not-found-exception
 */
SecurityAcl.Service.prototype._lookupObjectIdentities = function (batch, sids,
                                                                  oidLookup) {
  var self = this;
  // we need ancestorIds to retrieve data.
  var ancestorIds = self._getAncestorIds(batch);
  
  // exception if ancestorIds is an empty array
  if (ancestorIds.length === 0) {
    throw new Meteor.Error(
      'acl-not-found-exception',
      'There is no ACL for the given object identity.');
  }
  
  var data = self._lookupData(ancestorIds);
  
  return self._hydrateObjectIdentities(data, oidLookup);
  
};

/**
 * Looks up object identities, associated
 * ACEs, and security identities.
 * 
 * @param {Array} ancestorIds
 * 
 * @return {Array} data
 */
SecurityAcl.Service.prototype._lookupData = function (ancestorIds) {
  
  // we must build an array with required data to hydrate ACls and ACEs.
  var data = [];
  
  // lookup in objectIdentities collection
  var dbOids = SecurityAcl.ObjectIdentities.find({ _id: { $in: ancestorIds } }).fetch();
  
  for (var i = 0; i < dbOids.length; i++) {
    // an ACL can have multiple ACEs.
    // we must retrieve all entries.
    var dbEntries = SecurityAcl.Entries.find({ 
      $or : [
              { classId: dbOids[i].classId, objectIdentityId: dbOids[i]._id },
              { classId: dbOids[i].classId, objectIdentityId: null }
      ]
    }).fetch();
    
    
    var row = null;
    // if no dbEntries
    if (dbEntries.length === 0) {
      row = {};
      row.aclId = dbOids[i]._id;
      row.objectIdentifier = dbOids[i].objectIdentifier;
      row.parentObjectIdentityId = dbOids[i].parentObjectIdentityId;
      row.entriesInheriting = dbOids[i].entriesInheriting;
      row.classType = SecurityAcl.Classes.findOne({ _id: dbOids[i].classId }).classType;
      row.aceId = null;
      row.objectIdentityId = null;
      row.fieldName = null;
      row.aceOrder = null;
      row.mask = null;
      row.granting = null;
      row.grantingStrategy = null;
      row.auditSuccess = null;
      row.auditFailure = null;
      row.username = null;
      row.securityIdentifier = null;
      
      data.push(row);
    }
    
    for (var j = 0; j < dbEntries.length; j++) {
      row = {};
      row.aclId = dbOids[i]._id;
      row.objectIdentifier = dbOids[i].objectIdentifier;
      row.parentObjectIdentityId = dbOids[i].parentObjectIdentityId;
      row.entriesInheriting = dbOids[i].entriesInheriting;
      row.classType = SecurityAcl.Classes.findOne({ _id: dbOids[i].classId }).classType;
      row.aceId = dbEntries[j]._id;
      row.objectIdentityId = dbEntries[j].objectIdentityId;
      row.fieldName = dbEntries[j].fieldName;
      row.aceOrder = dbEntries[j].aceOrder;
      row.mask = dbEntries[j].mask;
      row.granting = dbEntries[j].granting;
      row.grantingStrategy = dbEntries[j].grantingStrategy;
      row.auditSuccess = dbEntries[j].auditSuccess;
      row.auditFailure = dbEntries[j].auditFailure;
      
      var sid = SecurityAcl.SecurityIdentities.findOne({
        _id: dbEntries[j].securityIdentityId
      });
      
      row.username = sid.username;
      row.securityIdentifier = sid.identifier;
      
      data.push(row);
    }
    
  }
  
  return data;
};

/**
 * This method is called to hydrate ACLs and ACEs.
 * 
 * @param {Array} data
 * @param {Array} oidLookup
 * @param {Array} sids
 */
SecurityAcl.Service.prototype._hydrateObjectIdentities = function (data,
                                                                   oidLookup) {
  var self = this;
  
  var acls = [],
    aces = [],
    emptyArray = [],
    parentIdToFill = [],
    result = [];
  
  var permissionGrantingStrategy = self._permissionGrantingStrategy;
  var oidCache = oidLookup;
  
  // loop on data
  for (var i = 0; i < data.length; i++ ) {
    var acl = null;
    var classType = data[i].classType;
    var objectIdentifier = data[i].objectIdentifier;
    
    // has the ACL been hydrated during this hydration cycle?
    if (typeof acls[data[i].aclId] !== 'undefined') {
      acl = acls[data[i].aclId];
      
    // has the ACL been hydrated during any previous cycle, or was possibly loaded
    // from cache?
    } else if (typeof self._loadedAcls[classType] !== 'undefined' &&
               typeof self._loadedAcls[classType][objectIdentifier] !== 'undefined') {
      
      acl = self._loadedAcls[data[i].classType][data[i].objectIdentifier];
      
      // keep reference in local array
      acls[data[i].aclId] = acl;
      
      // attach ACL to the result set; even though we do not enforce that every
      // object identity has only one instance, we must make sure to maintain
      // referential equality with the oids passed to findAcls()
      var oidCacheKey = data[i].objectIdentifier+data[i].classType;
      if (typeof oidCache[oidCacheKey] === 'undefined') {
        oidCache[oidCacheKey] = acl.objectIdentity();
      }
      
      result.push([oidCache[oidCacheKey], acl]);
      
    // so, this hasn't been hydrated yet
    } else {
      // create object identity if we haven't done so yet
      var oidLookupKey = data[i].objectIdentifier+data[i].classType;
      if (typeof oidCache[oidLookupKey] === 'undefined') {
        oidCache[oidLookupKey] = new SecurityAcl.ObjectIdentity(data[i].objectIdentifier,
                                                                data[i].classType);
      }
      
      acl = new SecurityAcl.Acl(data[i].aclId, oidCache[oidLookupKey], 
                                permissionGrantingStrategy, emptyArray,
                                !!data[i].entriesInheriting);
      
      // keep a local, and global reference to this ACL
      if (typeof self._loadedAcls[data[i].classType] === 'undefined') {
        self._loadedAcls[data[i].classType] = {};
      }
      self._loadedAcls[data[i].classType][data[i].objectIdentifier] = acl;
      acls[data[i].aclId] = acl;
      
      // try to fill in parent ACL, or defer until all ACLs have been hydrated
      if (null !== data[i].parentObjectIdentityId) {
        if (typeof acls[data[i].parentObjectIdentityId] !== 'undefined') {
          acl.setParentAcl(acls[data[i].parentObjectIdentityId]);
        } else {
          parentIdToFill.push([acl, data[i].parentObjectIdentityId]);
        }
      }
      
      result.push([oidCache[oidLookupKey], acl]);
    }
    
    // ACES
    // check if this row contains an ACE record
    if (null !== data[i].aceId) {
      // have we already hydrated ACEs for this ACL?
      if (typeof aces[data[i].aclId] === 'undefined') {
        aces[data[i].aclId] = [];
      }
      
      // has this ACE already been hydrated during a previous cycle, or
      // possible been loaded from cache?
      // It is important to only ever have one ACE instance per actual row since
      // some ACEs are shared between ACL instances
      if (typeof self._loadedAces[data[i].aceId] === 'undefined') {
        var key = (data[i].username ? '1' : '0')+data[i].securityIdentifier;
        var tmpSids = [];
        if (typeof tmpSids[key] === 'undefined') {
          if (data[i].username) {
            var pos = data[i].securityIdentifier.indexOf('-');
            tmpSids[key] = new SecurityAcl.UserSecurityIdentity(
              data[i].securityIdentifier.substring(1+pos),
              data[i].securityIdentifier.substring(0,pos));
          } else {
            tmpSids[key] = new SecurityAcl.RoleSecurityIdentity(
              data[i].securityIdentifier);
          }
        }
        
        if (null === data[i].fieldName) {
          self._loadedAces[data[i].aceId] = new SecurityAcl.Entry(
            data[i].aceId,
            acl,
            tmpSids[key],
            data[i].grantingStrategy,
            data[i].mask, 
            !!data[i].granting,
            !!data[i].auditFailure,
            !!data[i].auditSuccess);
        } else {
          self._loadedAces[data[i].aceId] = new SecurityAcl.FieldEntry(
            data[i].aceId,
            acl,
            data[i].fieldName,
            tmpSids[key],
            data[i].grantingStrategy,
            data[i].mask, 
            !!data[i].granting,
            !!data[i].auditFailure,
            !!data[i].auditSuccess);
        }
      }
      
      var ace = self._loadedAces[data[i].aceId];
      
      // assign ACE to the correct property
      if (null === data[i].objectIdentityId) {
        if (null === data[i].fieldName) {
          if (typeof aces[data[i].aclId][0] === 'undefined') {
            aces[data[i].aclId][0] = {};
          }
          aces[data[i].aclId][0][data[i].aceOrder] = ace;
        } else {
          if (typeof aces[data[i].aclId][1] === 'undefined') {
            aces[data[i].aclId][1] = {};
          }
          if (typeof aces[data[i].aclId][1][data[i].fieldName] === 'undefined') {
            aces[data[i].aclId][1][data[i].fieldName] = {};
          }
          aces[data[i].aclId][1][data[i].fieldName][data[i].aceOrder] = ace;
        }
      } else {
        if (null === data[i].fieldName) {
          if (typeof aces[data[i].aclId][2] === 'undefined') {
            aces[data[i].aclId][2] = {};
          }
          aces[data[i].aclId][2][data[i].aceOrder] = ace;
        } else {
          if (typeof aces[data[i].aclId][3] === 'undefined') {
            aces[data[i].aclId][3] = {};
          }
          if (typeof aces[data[i].aclId][3][data[i].fieldName] === 'undefined') {
            aces[data[i].aclId][3][data[i].fieldName] = {};
          }
          aces[data[i].aclId][3][data[i].fieldName][data[i].aceOrder] = ace;
        }
      }
      
      for (var aclId in aces) {
        if(!aces.hasOwnProperty(aclId)) {
          continue;
        }
        
        var aceData = aces[aclId];
        
        acl = acls[aclId];
        if (typeof aceData[0] !== 'undefined') {
          acl.setClassAces(aceData[0]);
        }
        if (typeof aceData[1] !== 'undefined') {
          acl.setClassFieldAces(aceData[1]);
        }
        if (typeof aceData[2] !== 'undefined') {
          acl.setObjectAces(aceData[2]);
        }
        if (typeof aceData[3] !== 'undefined') {
          acl.setObjectFieldAces(aceData[3]);
        }
      }
      
    } // data[i].aceId not null
    
  } // loop data
  
  // fill-in parent ACLs where this hasn't been done yet cause the parent ACL was not
  // yet available
  var processed = 0;
  for (i = 0; i < parentIdToFill.length ; i++) {
    acl = parentIdToFill[i][0];
    var parentId = parentIdToFill[i][1];
    
    // let's see if we have already hydrated this
    if (typeof acls[parentId] !== 'undefined') {
      acl.setParentAcl(acls[parentId]);
      processed++;
    }
  }
  
  // this should never be true if the database integrity hasn't been compromised
  if (processed < parentIdToFill.length) {
    throw new Meteor.Error(
      'runtime-exception',
      'Not all parent ids were populated. This implies an integrity problem.');
  }
  
  return result;
};

/**
 * Retrieves all child object identities from the database.
 *
 * @param {Object} ObjectIdentity    parentOid
 * @param {Boolean}                  directChildrenOnly
 *
 * @return array returns an array of child 'ObjectIdentity's
 */
SecurityAcl.Service.prototype.findChildren = function (parentOid, directChildrenOnly) {
  var self = this;
  
  directChildrenOnly = typeof directChildrenOnly !== 'undefined' ?
                       directChildrenOnly : false;
  
  if (! (parentOid instanceof SecurityAcl.ObjectIdentity)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The parentOid must be an instance of SecurityAcl.ObjectIdentity.');
  }
  
  if (typeof directChildrenOnly !== 'boolean') {
    throw new Meteor.Error(
      'invalid-argument',
      'The directChildrenOnly must be a boolean.');
  }
    
  var children = [];
  var oidPk = self.retrieveObjectIdentityPrimaryKey(parentOid); 
  var objectIdentityIds = null;
  
  if (false === directChildrenOnly) {
    objectIdentityIds = SecurityAcl.ObjectIdentitiesAncestors.find({
      'ancestorId': oidPk,
      'objectIdentityId': { $ne: oidPk } 
    }).map(function(doc){ return doc.objectIdentityId; });
    
    children = self.findOids(objectIdentityIds);
  } else {
    objectIdentityIds = SecurityAcl.ObjectIdentities.find({
      'parentObjectIdentityId': oidPk
    }).map(function(doc){ return doc._id; });
    
    children = self.findOids(objectIdentityIds);
  }
  
  return children;
};

/**
 * Returns oids for the given ids array
 * 
 * @param {Array}   ids
 * 
 * @return {Array}  oids
 */
SecurityAcl.Service.prototype.findOids = function (ids) {
  
  if (! (ids instanceof Array)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The argument must be an instance of Array.');
  }
    
  var dbOids = SecurityAcl.ObjectIdentities.find({ _id: { $in: ids } }).fetch();
  var oids = [];
  
  for (var i = 0; i < dbOids.length; i++) {
    var dbClass = SecurityAcl.Classes.findOne({ _id: dbOids[i].classId });
    var oid = new SecurityAcl.ObjectIdentity(dbOids[i].objectIdentifier,
                                             dbClass.classType);
    oids.push(oid);
  }
  
  return oids;
};


/**
 * Retrieves all the ids which need to be queried from the database
 * including the ids of parent ACLs.
 *
 * @param {Array} batch
 *
 * @return {Array} ObjectID
 */
SecurityAcl.Service.prototype._getAncestorIds = function (batch) {
  if (! (batch instanceof Array)) {
    throw new Meteor.Error(
      'invalid-argument',
      'The argument must be an instance of Array.');
  }
    
  var ancestorIds = [];
  
  for (var i = 0; i < batch.length; i++) {
    if (! (batch[i] instanceof SecurityAcl.ObjectIdentity)) {
      throw new Meteor.Error(
        'invalid-argument',
        'The batch element must be an instance of SecurityAcl.ObjectIdentity.');
    }
      
    // get class id
    var aclClass = SecurityAcl.Classes.findOne({ 'classType': batch[i].type() });
    
    if (typeof aclClass !== 'undefined') {
      var oid = SecurityAcl.ObjectIdentities.findOne({
        'classId': aclClass._id,
        'objectIdentifier': batch[i].identifier()
      });
      
      var oidAncestors =  [];
      if (typeof oid !== 'undefined') {
        oidAncestors = SecurityAcl.ObjectIdentitiesAncestors.find({
          'objectIdentityId': oid._id
        }).fetch();
      }
      
      // we add id
      for (var j = 0; j < oidAncestors.length; j++) {
        ancestorIds.push(oidAncestors[j].ancestorId);
      }
    }
  }
  
  return ancestorIds;
};

/**
 * This regenerates the ancestor collection which is used for fast read access.
 *
 * @param {Object} Acl acl
 */
SecurityAcl.Service.prototype._regenerateAncestorRelations = function (acl) {
  var pk = acl._id;
  // first, we must delete all ancestors from previous parentAcl
  SecurityAcl.ObjectIdentitiesAncestors.remove({
    'objectIdentityId': pk,
    'ancestorId': { $ne: acl._id }
  });
  
  var parentAcl = acl.parentAcl();
  while (parentAcl !== null) {
    SecurityAcl.ObjectIdentitiesAncestors.insert({
      'objectIdentityId': pk,
      'ancestorId': parentAcl._id
    });
    
    parentAcl = parentAcl.parentAcl();
  }
};

/**
 * This processes new entries changes on an ACE related property
 * (classAces, or objectAces).
 *
 * @param {String}  name
 * @param {Array}   changes
 */
SecurityAcl.Service.prototype._updateNewAceProperty = function (name, changes) {
  var self = this;
  
  var newValue = changes[1];
  var sids = [];
  var classIds =  [];
  
  for (var i = 0, c = Object.keys(newValue).length; i < c; i++) {
    var ace = newValue[i];
    
    if (null === ace.id()) {
      if (typeof sids[ace.sid()] !== 'undefined') {
        // we use identifier of sid as a key object
        var identifier = null;
        if (sid instanceof SecurityAcl.UserSecurityIdentity) {
          identifier = sid.className()+'-'+sid.username();
        } else if (sid instanceof SecurityAcl.RoleSecurityIdentity) {
          identifier = sid.role();
        } else {
          throw new Meteor.Error(
            'invalid-argument',
            'The sid  must be an instance of UserSecurityIdentity, ' +
            'or RoleSecurityIdentity.');
        }
        
        var sid = sids[identifier]; 
        
      } else {
        sid = self._createOrRetrieveSecurityIdentityId(ace.sid());
      }
      
      var oid = ace.acl().objectIdentity();
      
      if (classIds[oid.identifier()+oid.type()]) {
        var classId = classIds[oid.identifier()+oid.type()];
      } else {
        classId = self._createOrRetrieveClassId(oid.type());
      }
      
      var objectIdentityId = null;
      if (name !== 'classAces') {
        objectIdentityId = ace.acl().id();
      }
      
      var aceId = SecurityAcl.Entries.insert({
        classId: classId,
        objectIdentityId: objectIdentityId,
        securityIdentityId: sid,
        fieldName: null,
        aceOrder: i,
        mask: ace.mask(),
        granting: ace.isGranting(),
        grantingStrategy: ace.strategy(),
        auditSuccess: ace.isAuditSuccess(),
        auditFailure: ace.isAuditFailure(),
      });
      
      ace._id = aceId;
      self._loadedAces[aceId] = ace;
    }
  }
};

/**
 * This processes new entries changes on an ACE related property
 * (classFieldAces, or objectFieldAces).
 *
 * @param {String}  name
 * @param {Array}   changes
 */
SecurityAcl.Service.prototype._updateNewFieldAceProperty = function (name, changes) {
  var self = this;
  
  var sids = [];
  var classIds =  [];
  
  for (var field in changes[1]){
    if(!changes[1].hasOwnProperty(field)) {
      continue;
    }
    
    var newValue = changes[1][field];
  
    for (var i = 0, c = Object.keys(newValue).length; i < c; i++) {
      var ace = newValue[i];
      
      var sid = null;
      if (null === ace.id()) {
        if (typeof sids[ace.sid()] !== 'undefined') {
          sid = sids[ace.sid()]; 
        } else {
          sid = self._createOrRetrieveSecurityIdentityId(ace.sid());
        }
        
        var oid = ace.acl().objectIdentity();
        
        if (classIds[oid.identifier()+oid.type()]) {
          var classId = classIds[oid.identifier()+oid.type()];
        } else {
          classId = self._createOrRetrieveClassId(oid.type());
        }
        
        var objectIdentityId = null;
        if (name !== 'classFieldAces') {
          objectIdentityId = ace.acl().id();
        }
        
        var aceId = SecurityAcl.Entries.insert({
          classId: classId,
          objectIdentityId: objectIdentityId,
          securityIdentityId: sid,
          fieldName: field,
          aceOrder: i,
          mask: ace.mask(),
          granting: ace.isGranting(),
          grantingStrategy: ace.strategy(),
          auditSuccess: ace.isAuditSuccess(),
          auditFailure: ace.isAuditFailure(),
        });
        
        ace._id = aceId;
        self._loadedAces[aceId] = ace;
      }
    }
  }
};


/**
 * This processes old entries changes on an ACE related property
 * (classAces, or objectAces).
 *
 * @param {String}  name
 * @param {Array}   changes
 */
SecurityAcl.Service.prototype._updateOldAceProperty = function (name, changes) {
  var self = this;
  
  var oldValue = changes[0];
  var newValue = changes[1];
  var currentIds = [];
  
  for (var i = 0, c = Object.keys(newValue).length; i < c; i++) {
    var ace = newValue[i];
    
    if (null !== ace.id()) {
      currentIds[ace.id()] = true;
    }
  }
  
  for (i = 0, c = Object.keys(oldValue).length; i < c; i++) {
    ace = oldValue[i];
    // typeof of ace is not SecurityAcl.Entry in OldValue.
    // if Mongo.ObjectId is used for ID, we must create it.
    var aceId = null;
    if (typeof ace._id !== 'undefined' && typeof ace._id._str !== 'undefined' ) {
      aceId = new Mongo.ObjectID(ace._id._str);
    } else {
      aceId = ace._id;
    }
    
    if (typeof currentIds[aceId] === 'undefined') {
      SecurityAcl.Entries.remove(aceId);
      delete self._loadedAces[aceId];
    }
  }
};

/**
 * This processes old entries changes on an ACE related property
 * (classFieldAces, or objectFieldAces).
 *
 * @param {String}    name
 * @param {Array}     changes
 */
SecurityAcl.Service.prototype._updateOldFieldAceProperty = function (name, changes) {
  var self = this;
  
  var currentIds = [];
  
  for (var field in changes[1]){
    if(!changes[1].hasOwnProperty(field)) {
      continue;
    }
    
    var newValue = changes[1][field];
    
    for (var i = 0, c = Object.keys(newValue).length; i < c; i++) {
      var ace = newValue[i];
      
      if (null !== ace.id()) {
        currentIds[ace.id()] = true;
      }
    }
  }
  
  for (field in changes[0]) {
    if(!changes[0].hasOwnProperty(field)) {
      continue;
    }
    var oldValue = changes[0][field];
    
    for (i = 0, c = Object.keys(oldValue).length; i < c; i++) {
      ace = oldValue[i];
      // typeof of ace is not SecurityAcl.Entry in OldValue.
      // if Mongo.ObjectId is used for ID, we must create it.
      var aceId = null;
      if (typeof ace._id !== 'undefined' && typeof ace._id._str !== 'undefined' ) {
        aceId = new Mongo.ObjectID(ace._id._str);
      } else {
        aceId = ace._id;
      }
      
      if (typeof currentIds[aceId] === 'undefined') {
        SecurityAcl.Entries.remove({ _id: aceId });
        delete self._loadedAces[aceId];
      }
    }
  }
  
  
};

/**
 * Persists the changes which were made to ACEs to the database.
 *
 * @param {Object} aces
 */
SecurityAcl.Service.prototype._updateAces = function (aces) {
  var self = this;
  
  for (var key in aces) {
    if (aces.hasOwnProperty(key)) {
      self._updateAce(aces, aces[key]['ace']);
    }
  }
};

SecurityAcl.Service.prototype._updateAce = function (aces, ace) {
  var propertyChanges = aces[ace.id()]['acePropertyChanges'];
  var sets = {};
  
  if (typeof propertyChanges['mask'] !== 'undefined') {
    sets.mask = propertyChanges['mask'][1];
  }
  
  if (typeof propertyChanges['strategy'] !== 'undefined') {
    sets.strategy = propertyChanges['strategy'][1];
  }
  
  if (typeof propertyChanges['aceOrder'] !== 'undefined') {
    sets.aceOrder = propertyChanges['aceOrder'][1];
  }
  
  if (typeof propertyChanges['auditSuccess'] !== 'undefined') {
    sets.auditSuccess = propertyChanges['auditSuccess'][1];
  }
  
  if (typeof propertyChanges['auditFailure'] !== 'undefined') {
    sets.auditFailure = propertyChanges['auditFailure'][1];
  }
  
  if (Object.keys(sets).length > 0) {
    SecurityAcl.Entries.update( ace.id(), {
      $set: sets
    });
  }
};

