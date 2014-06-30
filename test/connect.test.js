// Copyright 2014 Joyent, Inc.  All rights reserved.


var Logger = require('bunyan');
var clone = require('clone');

var UFDS = require('../lib/index');


// --- Globals

var UFDS_URL = 'ldaps://' + (process.env.UFDS_IP || '10.99.99.18');

var LOG = new Logger({
    name: 'ufds_unit_test',
    stream: process.stdout,
    level: (process.env.LOG_LEVEL || 'info'),
    serializers: Logger.stdSerializers
});

var DEFAULT_PARAMS = {
    url: UFDS_URL,
    bindDN: 'cn=root',
    bindPassword: 'secret',
    clientTimeout: 2000,
    log: null,
    tlsOptions: {
        rejectUnauthorized: false
    },
    retry: {
        retries: 5,
        maxTimeout: 10000,
        minTimeout: 100
    }
};
var ufds;


// --- Helper functions

function ufdsParams(obj) {
    var params = clone(DEFAULT_PARAMS);
    if (obj) {
        Object.keys(obj).forEach(function (k) {
            params[k] = clone(obj[k]);
        });
    }
    params.log = LOG;
    return params;
}


// --- Tests


exports.testBasicConnect = function (test) {
    ufds = new UFDS(ufdsParams());
    ufds.once('connect', function () {
        test.ok(true);
        test.done();
        console.log('connect');
        ufds.close(function () {});
    });
};

exports.testBadCreds = function (t) {
    ufds = new UFDS(ufdsParams({
        bindPassword: 'bogus'
    }));
    ufds.once('connect', function () {
        t.ok(false);
    });
    ufds.on('destroy', function (err) {
        t.ok(err);
        t.equal(err.name, 'InvalidCredentialsError');
        t.done();
    });
};
