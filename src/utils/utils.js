
"use strict";

if (typeof SecurityAcl === 'undefined') {
  SecurityAcl = {};
}

if (typeof SecurityAcl.utils === 'undefined') {
  SecurityAcl.utils = {};
}

// Polyfill for isInteger
Number.isInteger = Number.isInteger || function(value) {
  return typeof value === "number" && 
         isFinite(value) && 
         Math.floor(value) === value;
};

SecurityAcl.utils.strPad = function (input, padLength, padString, padType) {
  var half = '',
    padToGo;

  var strPadRepeater = function(s, len) {
    var collect = '';

    while (collect.length < len) {
      collect += s;
    }
    collect = collect.substr(0, len);

    return collect;
  };

  input += '';
  padString = padString !== undefined ? padString : ' ';

  if (padType !== 'STR_PAD_LEFT' &&
      padType !== 'STR_PAD_RIGHT' &&
      padType !== 'STR_PAD_BOTH') {
    padType = 'STR_PAD_RIGHT';
  }
  if ((padToGo = padLength - input.length) > 0) {
    if (padType === 'STR_PAD_LEFT') {
      input = strPadRepeater(padString, padToGo) + input;
    } else if (padType === 'STR_PAD_RIGHT') {
      input = input + strPadRepeater(padString, padToGo);
    } else if (padType === 'STR_PAD_BOTH') {
      half = strPadRepeater(padString, Math.ceil(padToGo / 2));
      input = half + input + half;
      input = input.substr(0, padLength);
    }
  }

  return input;
};

SecurityAcl.utils.decbin = function (number) {
  if (number < 0) {
    number = 0xFFFFFFFF + number + 1;
  }
  return parseInt(number, 10)
    .toString(2);
};

