
Tinytest.add('SecurityAcl - SidRetrievalStrategy (roles)', function (test) {
  
  var user = {};
  user.username = 'username';
  user.roles = ['moderator', 'reviewer'];
  user.getClassName = function () {
    return 'users';
  };
  
  var sidRetrievalStrategy = new SecurityAcl.SidRetrievalStrategy();
  
  var sids = sidRetrievalStrategy.getSecurityIdentities(user);
  
  var check = _.some(sids, function(c) {
    return c._role == 'moderator'; 
  });
  
  test.isTrue(check, 'moderator role exists.');

  var check = _.some(sids, function(c) {
    return c._role == 'reviewer'; 
  });
  
  test.isTrue(check, 'reviwer role exists.');
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
  
  var check = _.some(sids, function(c) {
    return c._role == 'posts-moderator'; 
  });
  
  test.isTrue(check, 'posts-moderator role exists.');

  var check = _.some(sids, function(c) {
    return c._role == 'posts-reviewer'; 
  });
  
  test.isTrue(check, 'posts-reviewer role exists.');

  var check = _.some(sids, function(c) {
    return c._role == 'tech-blog-moderator'; 
  });
  
  test.isTrue(check, 'tech-blog-moderator exists.');

});