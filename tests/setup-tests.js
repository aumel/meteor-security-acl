
Tinytest.add('Setup - Clean up database', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();
  Meteor.users.remove({});
  
  test.equal(SecurityAcl.Classes.findOne(), undefined, 'SecurityAcl.Collections is empty.');
  test.equal(SecurityAcl.ObjectIdentities.findOne(), undefined, 'SecurityAcl.ObjectIdentities is empty.');
  test.equal(SecurityAcl.ObjectIdentitiesAncestors.findOne(), undefined, 'SecurityAcl.ObjectIdentitiesAncestors is empty.');
  test.equal(SecurityAcl.Entries.findOne(), undefined, 'SecurityAcl.Entries is empty.');
  test.equal(SecurityAcl.SecurityIdentities.findOne(), undefined, 'SecurityAcl.SecurityIdentities is empty.');
  
});

Tinytest.add('Setup - Define getDomainObjectName() for Posts and Comments', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  // data fixtures
  if (typeof Posts === 'undefined') {
    Posts = new Mongo.Collection("posts", {
      idGeneration: 'MONGO',
      transform: function (doc) {
        doc.getDomainObjectName = function () {
          return Posts._name;
        };
        return doc;
      }
    });
    
  }
  
  if (typeof Comments === 'undefined') {
    Comments = new Mongo.Collection("comments", {
      idGeneration: 'MONGO',
      transform: function (doc) {
        doc.getDomainObjectName = function () {
          return Comments._name;
        };
        return doc;
      }
    });
  }
  
  //create user
  var userId = Accounts.createUser({
    username: 'username1',
    email: 'email1@test.com',
    password: 'test1'
  });
  
  var user = Meteor.users.findOne({ _id: userId });
  
  test.equal(user.getDomainObjectName(), 'users', 'getDomainObjectName function defined for user.');
  
  Posts.insert({
    text: 'test'
  });
  
  var post = Posts.findOne({ text: 'test'});
  test.equal(post.text, 'test', 'One post defined.');
  test.equal(post.getDomainObjectName(), 'posts', 'getDomainObjectName function defined.');
  Comments.insert({
    text: 'test'
  });
  
  var comment = Comments.findOne({ text: 'test'});
  
  test.equal(comment.text, 'test', 'One comment defined.');
  test.equal(comment.getDomainObjectName(), 'comments', 'getDomainObjectName function defined.');
});

