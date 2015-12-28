
Tinytest.add('SecurityAcl - SidRetrievalStrategy (roles)', function (test) {
  
  var user = {};
  user.username = 'username';
  user.roles = ['moderator', 'reviewer'];
  user.getClassName = function () {
    return 'users';
  };
  
  var sidRetrievalStrategy = new SecurityAcl.SidRetrievalStrategy();
  
  var sids = sidRetrievalStrategy.getSecurityIdentities(user);
  
  test.equal(sids[1]._role, 'moderator', 'SidRetrievalStrategy manages correctly multiple roles.');
  test.equal(sids[2]._role, 'reviewer', 'SidRetrievalStrategy manages correctly multiple roles.');
});

Tinytest.add('SecurityAcl - SidRetrievalStrategy (group of roles)', function (test) {
  
  var user = {};
  user.username = 'username';
  user.roles = { 
    'posts': ['moderator', 'reviewer'],
    'tech-blog': ['moderator'] 
  };
  user.getClassName = function () {
    return 'users';
  };
  
  var sidRetrievalStrategy = new SecurityAcl.SidRetrievalStrategy();
  
  var sids = sidRetrievalStrategy.getSecurityIdentities(user);
  
  test.equal(sids[1]._role, 'posts-moderator', 'SidRetrievalStrategy manages correctly the group.');
  test.equal(sids[2]._role, 'posts-reviewer', 'SidRetrievalStrategy manages correctly the group.');
  test.equal(sids[3]._role, 'tech-blog-moderator', 'SidRetrievalStrategy manages correctly the group.');
  
});