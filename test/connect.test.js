/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

var assert = require('assert-plus');
var bunyan = require('bunyan');
var clone = require('clone');

var UFDS = require('../lib/index');


// --- Globals

assert.string(process.env.UFDS_IP, 'UFDS_IP envvar');
assert.string(process.env.UFDS_LDAP_ROOT_PASSWORD,
    'UFDS_LDAP_ROOT_PASSWORD envvar');

var UFDS_URL = 'ldaps://' + process.env.UFDS_IP;
var UFDS_PASSWORD = process.env.UFDS_LDAP_ROOT_PASSWORD;

var LOG = bunyan.createLogger({
    name: 'ufds_unit_test',
    stream: process.stdout,
    level: (process.env.LOG_LEVEL || 'info'),
    serializers: bunyan.stdSerializers
});

var DEFAULT_PARAMS = {
    url: UFDS_URL,
    bindDN: 'cn=root',
    bindPassword: UFDS_PASSWORD,
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
