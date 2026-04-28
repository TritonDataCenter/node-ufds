/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Tests for idleTimeout option handling in the UFDS
 * constructor.  Verifies that idleTimeout:0 is preserved
 * (not treated as falsy) and that absent/null/undefined
 * values fall back to the 90000ms default.
 *
 * These tests only check ldapOpts assignment -- they do
 * not require a live UFDS connection.
 */

var assert = require('assert');
var Logger = require('bunyan');
var UFDS = require('../lib/index');

var LOG = Logger.createLogger({
    name: 'idle-timeout-test',
    level: 'fatal',
    stream: process.stdout
});

var passed = 0;
var failed = 0;

function check(name, opts, expected) {
    var params = {
        url: 'ldaps://localhost:1',
        bindDN: 'cn=root',
        bindPassword: 'test',
        log: LOG
    };
    if (opts !== undefined) {
        params.idleTimeout = opts;
    }
    var client = new UFDS(params);
    client.on('error', function () {});

    var actual = client.ldapOpts.idleTimeout;
    if (actual === expected) {
        console.log('PASS: %s (got %d)', name, actual);
        passed++;
    } else {
        console.log('FAIL: %s (expected %d, got %d)',
            name, expected, actual);
        failed++;
    }
    client.close(function () {});
}

check('idleTimeout: 0 preserved', 0, 0);
check('idleTimeout: undefined defaults to 90000',
    undefined, 90000);
check('idleTimeout: null defaults to 90000',
    null, 90000);
check('idleTimeout: 60000 preserved', 60000, 60000);
check('idleTimeout: 1 preserved', 1, 1);

/*
 * Test with idleTimeout absent from opts entirely.
 * We pass a sentinel to skip the assignment.
 */
(function () {
    var params = {
        url: 'ldaps://localhost:1',
        bindDN: 'cn=root',
        bindPassword: 'test',
        log: LOG
    };
    var client = new UFDS(params);
    client.on('error', function () {});

    var actual = client.ldapOpts.idleTimeout;
    if (actual === 90000) {
        console.log('PASS: idleTimeout absent defaults' +
            ' to 90000 (got %d)', actual);
        passed++;
    } else {
        console.log('FAIL: idleTimeout absent defaults' +
            ' to 90000 (expected 90000, got %d)', actual);
        failed++;
    }
    client.close(function () {});
})();

console.log('\n%d passed, %d failed', passed, failed);
if (failed > 0) {
    process.exit(1);
}
/* Allow event loop to drain (close callbacks) */
setTimeout(function () { process.exit(0); }, 500);
