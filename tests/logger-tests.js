
Tinytest.add('AuthorizationChecker - Logger', function (test) {
  
  SecurityAclTestHelpers.cleanUpDatabase();
  
  var logger = 'invalid-logger';
  
  test.throws(function () {
    SecurityAcl.setLogger(logger);
  }, 'The logger must have a debug function.');

  var logger = {
    debug: function (text) {
      test.equal(
        text,
        'No ACL found for the object identity. Voting to deny access.',
        'The logger returns debug informations');
    }
  };
  
  SecurityAcl.setLogger(logger);

  var user = {};
  user.username = 'username';
  user.getClassName = function () {
    return 'users';
  };

  // VIEW permission

  var authorizationChecker = new SecurityAcl.AuthorizationChecker();
  authorizationChecker.setAuthenticatedUser(user);

  // data-fixture
  Posts.insert({
    text: 'test'
  });
  var post = Posts.findOne({});

  authorizationChecker.isGranted('VIEW', post);
  
  // reset Logger to null
  SecurityAcl.logger = null;
});