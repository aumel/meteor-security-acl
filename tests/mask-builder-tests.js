
Tinytest.add('SecurityAcl - MaskBuilder', function (test) {
  var builder = new SecurityAcl.MaskBuilder();
  
  // Test: getCode
  
  test.equal(builder.getCode(1), 'V', 'The code for the mask 1 is V');
  test.equal(builder.getCode(2), 'C', 'The code for the mask 2 is C');
  test.equal(builder.getCode(4), 'E', 'The code for the mask 4 is E');
  test.equal(builder.getCode(8), 'D', 'The code for the mask 8 is D');
  test.equal(builder.getCode(16), 'U', 'The code for the mask 16 is D');
  test.equal(builder.getCode(32), 'O', 'The code for the mask 32 is O');
  test.equal(builder.getCode(64), 'M', 'The code for the mask 64 is M');
  test.equal(builder.getCode(128), 'N', 'The code for the mask 128 is N');
  
  // Test: add
  
  test.throws(function () {
    builder.add('invalid-mask');
  }, 'The code invalid-mask is not supported. ');
  
  builder.add(1);
  
  test.equal(builder.getMask(), 1, 'MaskBuilder returns 1 for the mask.');
  
  builder.add('create');
  
  test.equal(builder.getMask(), 3, 'MaskBuilder returns 3 for the mask.');
  
  builder.add('edit');
  
  test.equal(builder.getMask(), 7, 'MaskBuilder returns 7 for the mask.');
  
  // Test: getPattern
  
  test.equal(builder.getPattern(), '.............................ECV', 'getPattern returns a readable representation of the permission.');
  
});