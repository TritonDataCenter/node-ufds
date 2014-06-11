// Copyright 2014 Joyent.  All rights reserved.

var util = require('util');

// --- Globals

var sprintf = util.format;

// --- API

function assertArgument(name, type, arg) {
    if (typeof (arg) !== type) {
        throw new TypeError(sprintf('%s (%s) is required', name, type));
    }
}

module.exports = {
    assertFunction: function assertFunction(name, arg) {
        assertArgument(name, 'function', arg);
    },
    assertNumber: function assertNumber(name, arg) {
        assertArgument(name, 'number', arg);
    },
    assertObject: function assertObject(name, arg) {
        assertArgument(name, 'object', arg);
    },
    assertString: function assertString(name, arg) {
        assertArgument(name, 'string', arg);
    }
};
