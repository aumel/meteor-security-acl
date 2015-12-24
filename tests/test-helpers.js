
if (typeof SecurityAclTestHelpers === 'undefined') {
  SecurityAclTestHelpers = {};
}

// remove all data in database before testing.
SecurityAclTestHelpers.cleanUpDatabase = function () {
  SecurityAcl.ObjectIdentities.remove({});
  SecurityAcl.ObjectIdentitiesAncestors.remove({});
  SecurityAcl.Classes.remove({});
  SecurityAcl.Entries.remove({});
  SecurityAcl.SecurityIdentities.remove({});
  
  if (typeof Posts !== 'undefined') {
    Posts.remove({});
  }
  
  if (typeof Comments !== 'undefined') {
    Comments.remove({});
  }
  
};