/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

var crypto = require('crypto');
var util = require('util');
var assert = require('assert-plus');
var vasync = require('vasync');
var Logger = require('bunyan');
var uuidv4 = require('uuid/v4');
var restify_errors = require('restify-errors');

var UFDS = require('../lib/index');
var accesskey = require('../lib/accesskey');

assert.string(process.env.UFDS_IP, 'UFDS_IP envvar');
assert.string(process.env.UFDS_LDAP_ROOT_PASSWORD,
    'UFDS_LDAP_ROOT_PASSWORD envvar');

var UFDS_URL = 'ldaps://' + process.env.UFDS_IP;
var UFDS_PASSWORD = process.env.UFDS_LDAP_ROOT_PASSWORD;
var ufds;

var ID = uuidv4();
var LOGIN = 'a' + ID.substr(0, 7);
var EMAIL = LOGIN + '_test@tritondatacenter.com';
var USER_FMT = 'uuid=%s, ou=users, o=smartdc';
var DN = util.format(USER_FMT, ID);

var SUB_ID = uuidv4();
var SUB_LOGIN = 'a' + SUB_ID.substr(0, 7);
var SUB_EMAIL = SUB_LOGIN + '_test@tritondatacenter.com';
var SUB_UUID;

var SUB_ID2 = uuidv4();
var SUB_LOGIN2 = 'b' + SUB_ID2.substr(0, 7);
var SUB_EMAIL2 = SUB_LOGIN2 + '_test@tritondatacenter.com';
var SUB_UUID2;

var PWD = process.env.ADMIN_PWD || 'joypass123';

exports.setUp = function (callback) {
    ufds = new UFDS({
        url: UFDS_URL,
        bindDN: 'cn=root',
        bindPassword: UFDS_PASSWORD,
        clientTimeout: 2000,
        log: new Logger({
            name: 'ufds_unit_test',
            stream: process.stdout,
            level: (process.env.LOG_LEVEL || 'info'),
            serializers: Logger.stdSerializers
        }),
        tlsOptions: {
            rejectUnauthorized: false
        },
        retry: {
            retries: 5,
            maxTimeout: 10000,
            minTimeout: 100
        }
    });
    ufds.once('ready', function () {
        ufds.removeAllListeners('error');
        callback();
    });
    ufds.once('error', function (err) {
        ufds.removeAllListeners('ready');
        callback(err);
    });
};

exports.testAccessKeyGenerator = function (t) {
    var prefix = accesskey.DEFAULT_PREFIX;
    var bytes = accesskey.DEFAULT_BYTE_LENGTH;

    accesskey.generate(prefix, bytes, function (err, key) {
        assert.ifError(err, 'failed to generate key');
        t.ok(key, 'access key was generated');
        t.ok(accesskey.validate(prefix, bytes, key), 'access key is valid');

        // replace a char within the random byte area
        var change = String.fromCharCode(key[8].charCodeAt(0) + 1);
        var modifiedKey = key.substring(0, 8) + change + key.substring(8 + 1);
        t.ok(!accesskey.validate(prefix, bytes, modifiedKey), 'invalid key');

        // replace a char in the prefix area
        change = String.fromCharCode(key[2].charCodeAt(0) + 1);
        modifiedKey = key.substring(0, 2) + change + key.substring(2 + 1);
        t.ok(!accesskey.validate(prefix, bytes, modifiedKey), 'invalid key');

        // replace a char in the checksum area
        change = String.fromCharCode(key[key.length - 2].charCodeAt(0) + 1);
        modifiedKey = key.substring(0, key.length - 2) + change +
            key.substring(key.length - 1);
        t.ok(!accesskey.validate(prefix, bytes, modifiedKey), 'invalid key');

        // replace a char within the random byte areawith an non-base64 char
        modifiedKey = key.substring(0, 9) + '!' + key.substring(9 + 1);
        t.ok(!accesskey.validate(prefix, bytes, modifiedKey), 'invalid key');

        // toss random bytes at validate()
        var randPrefix = crypto.randomBytes(4).toString('base64');
        var randBytes = crypto.randomBytes(bytes + 4).toString('base64');
        t.ok(!accesskey.validate(randPrefix, bytes, randBytes), 'invalid key');

        t.done();
    });
};

exports.setupTestUsers = function (test) {
    var entry = {
        login: LOGIN,
        email: EMAIL,
        uuid: ID,
        userpassword: PWD,
        objectclass: 'sdcperson'
    };
    ufds.add(DN, entry, function (err) {
        assert.ifError(err, 'err adding user');
        var entry = {
            login: SUB_LOGIN,
            email: SUB_EMAIL,
            userpassword: PWD,
            objectclass: 'sdcperson',
            account: ID
        };
        ufds.addUser(entry, function (err, user) {
            assert.ifError(err, 'err adding subuser');
            SUB_UUID = user.uuid;
            var entry2 = {
                login: SUB_LOGIN2,
                email: SUB_EMAIL2,
                userpassword: PWD,
                objectclass: 'sdcperson',
                account: ID
            };
            ufds.addUser(entry2, function (err, user2) {
                assert.ifError(err, 'err adding subuser2');
                SUB_UUID2 = user2.uuid;
                test.done();
            });
        });
    });
};

exports.testAccountAccessKeysBasic = function (t) {
    vasync.waterfall([
        function addAccessKey(next) {
            ufds.addAccessKey(ID, next);
        },
        function checkResponse(accKey, next) {
            t.ok(accKey, 'added AccessKey');
            t.ok(accKey.accesskeyid, 'AccessKeyId');
            t.ok(accKey.accesskeysecret, 'AccessKeySecret');
            t.ok(accKey.created, 'AccessKey Created');
            t.ok(accKey.updated, 'AccessKey Updated');
            t.equal(accKey.status, 'Active', 'AccessKey Status');
            next(null, accKey);
        },
        function getAccessKey(accKey, next) {
            var accessKeyId = accKey.accesskeyid;
            ufds.getAccessKey(ID, accessKeyId, next);
        },
        function listAccessKeys(accKey, next) {
            t.ok(accKey, 'getAccessKey key');
            ufds.listAccessKeys(ID, function (listErr, listOfKeys) {
                assert.ifError(listErr, 'listAccessKeys error');
                t.ok(listOfKeys, 'List of access keys');
                t.ok(Array.isArray(listOfKeys, 'list of keys is an array'));
                t.ok(listOfKeys[0], 'list of keys contains a key');
                var foundKey = listOfKeys.some(function (key) {
                    return (key.accesskeyid === accKey.accesskeyid);
                });
                t.ok(foundKey, 'list of keys contains created key');
                next(null, accKey);
            });
        },
        function listActiveAccessKeys(accKey, next) {
            t.ok(accKey, 'listActiveAccessKeys key');
            ufds.listActiveAccessKeys(ID, function (listErr, listOfKeys) {
                assert.ifError(listErr, 'listAccessKeys error');
                assert.deepEqual([accKey], listOfKeys);
                next(null, accKey);
            });
        },
        function deleteAccessKey(accKey, next) {
            t.ok(accKey, 'getAccessKey key');
            ufds.deleteAccessKey(ID, accKey, function (delErr) {
                assert.ifError(delErr, 'deleteAccessKey error');
                next(null, accKey);
            });
        },
        function getDeletedAccessKey(accKey, next) {
            var accessKeyId = accKey.accesskeyid;
            ufds.getAccessKey(ID, accessKeyId, function (error, key) {
                t.ok(error instanceof restify_errors.ResourceNotFoundError,
                    'getAccessKey deleted key is absent');
                t.equal(key, undefined, 'deleted key not returned');
                next(null, accKey);
            });
        },
        function listDeletedAccessKey(accKey, next) {
            ufds.listAccessKeys(ID, function (listErr, listOfKeys) {
                assert.ifError(listErr, 'listAccessKeys error');
                t.ok(listOfKeys, 'List of access keys');
                t.ok(Array.isArray(listOfKeys, 'list of keys is an array'));
                var foundKey = listOfKeys.some(function (key) {
                    return (key.accesskeyid === accKey.accesskeyid);
                });
                t.ok(!foundKey, 'deleted key abesent from list of keys');
                next();
            });
        }
    ], function (err, res) {
        assert.ifError(err);
        t.done();
    });
};

exports.testAccountAccessKeysFalsyAccount = function (t) {
    vasync.waterfall([
        function addAccessKey(next) {
            ufds.addAccessKey(ID, null, next);
        },
        function checkResponse(accKey, next) {
            t.ok(accKey, 'added AccessKey');
            t.ok(accKey.accesskeyid, 'AccessKeyId');
            t.ok(accKey.accesskeysecret, 'AccessKeySecret');
            t.ok(accKey.created, 'AccessKey Created');
            t.ok(accKey.updated, 'AccessKey Updated');
            t.equal(accKey.status, 'Active', 'AccessKey Status');
            next(null, accKey);
        },
        function getAccessKey(accKey, next) {
            var accessKeyId = accKey.accesskeyid;
            ufds.getAccessKey(ID, accessKeyId, next);
        },
        function listActiveAccessKeys(accKey, next) {
            t.ok(accKey, 'listActiveAccessKeys key');
            ufds.listActiveAccessKeys(ID, function (listErr, listOfKeys) {
                assert.ifError(listErr, 'listAccessKeys error');
                assert.deepEqual([accKey], listOfKeys);
                next(null, accKey);
            });
        },
        function deleteAccessKey(accKey, next) {
            t.ok(accKey, 'getAccessKey key');
            ufds.deleteAccessKey(ID, accKey, function (delErr) {
                assert.ifError(delErr, 'deleteAccessKey error');
                next(null, accKey);
            });
        }
    ], function (err, res) {
        assert.ifError(err);
        t.done();
    });
};

exports.testAccountAccessKeysOptions = function (t) {
    const options = {
        status: 'Inactive',
        description: 'My hovercraft is full of eels.'
    };
    vasync.waterfall([
         function addAccessKeyWithOptions(next) {
            ufds.addAccessKey(ID, options, next);
        },
        function checkResponse(accKey, next) {
            t.ok(accKey, 'added AccessKey');
            t.ok(accKey.accesskeyid, 'AccessKeyId');
            t.ok(accKey.accesskeysecret, 'AccessKeySecret');
            t.ok(accKey.created, 'AccessKey Created');
            t.ok(accKey.updated, 'AccessKey Updated');
            t.equal(accKey.status, options.status, 'AccessKey Status');
            t.equal(accKey.description, options.description,
                'AccessKey description');
            next(null, accKey);
        },
        function listActiveAccessKeys(accKey, next) {
            t.ok(accKey, 'listActiveAccessKeys key');
            ufds.listActiveAccessKeys(SUB_UUID, ID,
                function (listErr, listOfKeys) {
                assert.deepEqual([], listOfKeys, 'no active keys');
                next(null, accKey);
            });
        },
        function deleteAccessKey(accKey, next) {
            t.ok(accKey, 'getAccessKey key');
            ufds.deleteAccessKey(ID, accKey, function (delErr) {
                assert.ifError(delErr, 'deleteAccessKey error');
                next(null, accKey);
            });
        }
    ], function (err, res) {
        assert.ifError(err);
        t.done();
    });
};

exports.testAccountAccessKeysStatusValidation = function (t) {
    const options = {
        status: 'NotYetCreated'
    };
    ufds.addAccessKey(ID, options, function (error, key) {
        t.ok(error instanceof restify_errors.InvalidArgumentError,
            'addAccessKey rejects invalid status');
        t.equal(key, undefined, 'key not returned for invalid status');
        t.done();
    });
};

exports.testAccountAccessKeysDescValidation = function (t) {
    const options = {
        description: 'Strange women lying in ponds distributing swords is ' +
        'no basis for a system of government. Supreme executive power ' +
        'derives from a mandate from the masses, not from some farcical ' +
        'aquatic ceremony.'
    };
    ufds.addAccessKey(ID, options, function (error, key) {
        t.ok(error instanceof restify_errors.InvalidArgumentError,
            'addAccessKey rejects invalid description');
        t.equal(key, undefined, 'key not returned for invalid description');
        t.done();
    });
};

exports.testSubAccountAccessKeysBasic = function (t) {
    vasync.waterfall([
        function addAccessKey(next) {
            ufds.addAccessKey(SUB_UUID, ID, next);
        },
        function checkResponse(accKey, next) {
            t.ok(accKey, 'added AccessKey');
            t.ok(accKey.accesskeyid, 'AccessKeyId');
            t.ok(accKey.accesskeysecret, 'AccessKeySecret');
            t.ok(accKey.created, 'AccessKey Created');
            t.ok(accKey.updated, 'AccessKey Updated');
            t.equal(accKey.status, 'Active', 'AccessKey Status');
            next(null, accKey);
        },
        function getAccessKey(accKey, next) {
            var accessKeyId = accKey.accesskeyid;
            ufds.getAccessKey(SUB_UUID, accessKeyId, ID, next);
        },
        function listAccessKeys(accKey, next) {
            t.ok(accKey, 'getAccessKey key');
            ufds.listAccessKeys(SUB_UUID, ID, function (listErr, listOfKeys) {
                assert.ifError(listErr, 'listAccessKeys error');
                t.ok(listOfKeys, 'List of access keys');
                t.ok(Array.isArray(listOfKeys, 'list of keys is an array'));
                t.ok(listOfKeys[0], 'list of keys contains a key');
                var foundKey = listOfKeys.some(function (key) {
                    return (key.accesskeyid === accKey.accesskeyid);
                });
                t.ok(foundKey, 'list of keys contains created key');
                next(null, accKey);
            });
        },
        function listActiveAccessKeys(accKey, next) {
            t.ok(accKey, 'listActiveAccessKeys key');
            ufds.listActiveAccessKeys(SUB_UUID, ID,
                function (listErr, listOfKeys) {
                assert.ifError(listErr, 'listAccessKeys error');
                assert.deepEqual([accKey], listOfKeys);
                next(null, accKey);
            });
        },
        function deleteAccessKey(accKey, next) {
            t.ok(accKey, 'getAccessKey key');
            ufds.deleteAccessKey(SUB_UUID, accKey, ID, function (delErr) {
                assert.ifError(delErr, 'deleteAccessKey error');
                next(null, accKey);
            });
        },
        function getDeletedAccessKey(accKey, next) {
            var accessKeyId = accKey.accesskeyid;
            ufds.getAccessKey(SUB_UUID, accessKeyId, ID, function (error, key) {
                t.ok(error instanceof restify_errors.ResourceNotFoundError,
                    'getAccessKey deleted key is absent');
                t.equal(key, undefined, 'deleted key not returned');
                next(null, accKey);
            });
        },
        function listDeletedAccessKey(accKey, next) {
            ufds.listAccessKeys(SUB_UUID, ID, function (listErr, listOfKeys) {
                assert.ifError(listErr, 'listAccessKeys error');
                t.ok(listOfKeys, 'List of access keys');
                t.ok(Array.isArray(listOfKeys, 'list of keys is an array'));
                var foundKey = listOfKeys.some(function (key) {
                    return (key.accesskeyid === accKey.accesskeyid);
                });
                t.ok(!foundKey, 'deleted key abesent from list of keys');
                next();
            });
        }
    ], function (err, res) {
        assert.ifError(err);
        t.done();
    });
};

exports.testSubAccountAccessKeysOptions = function (t) {
    const options = {
        status: 'Expired',
        description: 'What is the air-speed velocity of an unladen swallow?'
    };
    vasync.waterfall([
         function addAccessKeyWithOptions(next) {
            ufds.addAccessKey(SUB_UUID, ID, options, next);
        },
        function checkResponse(accKey, next) {
            t.ok(accKey, 'added AccessKey');
            t.ok(accKey.accesskeyid, 'AccessKeyId');
            t.ok(accKey.accesskeysecret, 'AccessKeySecret');
            t.ok(accKey.created, 'AccessKey Created');
            t.ok(accKey.updated, 'AccessKey Updated');
            t.equal(accKey.status, options.status, 'AccessKey Status');
            t.equal(accKey.description, options.description,
                'AccessKey description');
            next(null, accKey);
        },
        function listActiveAccessKeys(accKey, next) {
            t.ok(accKey, 'listActiveAccessKeys key');
            ufds.listActiveAccessKeys(SUB_UUID, ID,
                function (listErr, listOfKeys) {
                assert.ifError(listErr, 'listAccessKeys error');
                assert.deepEqual([], listOfKeys, 'no active keys');
                next(null, accKey);
            });
        },
        function deleteAccessKey(accKey, next) {
            t.ok(accKey, 'getAccessKey key');
            ufds.deleteAccessKey(ID, accKey, function (delErr) {
                assert.ifError(delErr, 'deleteAccessKey error');
                next(null, accKey);
            });
        }
    ], function (err, res) {
        assert.ifError(err);
        t.done();
    });
};

exports.testAccountAccessKeysUpdate = function (t) {
    var description = 'Are you suggesting coconuts migrate?';
    vasync.waterfall([
        function addAccessKey(next) {
            ufds.addAccessKey(ID, next);
        },
        function checkResponse(accKey, next) {
            t.ok(accKey, 'added AccessKey');
            t.ok(accKey.accesskeyid, 'AccessKeyId');
            t.ok(accKey.accesskeysecret, 'AccessKeySecret');
            t.ok(accKey.created, 'AccessKey Created');
            t.ok(accKey.updated, 'AccessKey Updated');
            t.equal(accKey.status, 'Active', 'AccessKey Status');
            next(null, accKey);
        },
        function updateStatus(accKey, next) {
            var accesskey = {
                accesskeyid: accKey.accesskeyid,
                status: 'Inactive'
            };
            ufds.updateAccessKey(ID, accesskey, function (err, result) {
                assert.ifError(err, 'updateStatus');
                next(null, accKey);
            });
        },
        function getAccessKey(accKey, next) {
            var accessKeyId = accKey.accesskeyid;
            ufds.getAccessKey(ID, accessKeyId, function (err, updatedAccKey) {
                assert.ifError(err, 'getAccessKey');
                // Should not have changed
                t.ok(updatedAccKey, 'updatedAccKey');
                t.equal(accKey.accesskeyid,
                    updatedAccKey.accesskeyid, 'AccessKeyId');
                t.equal(accKey.accesskeysecret,
                    updatedAccKey.accesskeysecret, 'AccessKeySecret');
                t.equal(accKey.created, updatedAccKey.created,
                    'AccessKey Created');
                t.equal(accKey.description, updatedAccKey.description,
                    'AccessKey description');

                // Should have changed
                t.equal(updatedAccKey.status, 'Inactive',
                    'AccessKey Status');
                t.notEqual(accKey.updated, updatedAccKey.updated,
                    'AccessKey Updated');

                next(null, updatedAccKey);
            });
        },
        function addDescription(accKey, next) {
            var accesskey = {
                accesskeyid: accKey.accesskeyid,
                description: description
            };
            ufds.updateAccessKey(ID, accesskey, function (err, result) {
                assert.ifError(err, 'addDescription');
                next(null, accKey);
            });
        },
        function getUpdatedAccessKey(accKey, next) {
            var accessKeyId = accKey.accesskeyid;
            ufds.getAccessKey(ID, accessKeyId, function (err, updatedAccKey) {
                assert.ifError(err, 'getUpdatedAccessKey');
                // Should not have changed
                t.ok(updatedAccKey, 'updatedAccKey');
                t.equal(accKey.accesskeyid,
                    updatedAccKey.accesskeyid, 'AccessKeyId');
                t.equal(accKey.accesskeysecret,
                    updatedAccKey.accesskeysecret, 'AccessKeySecret');
                t.equal(accKey.created, updatedAccKey.created,
                    'AccessKey Created');
                t.equal(updatedAccKey.status, accKey.status,
                    'AccessKey Status');

                // Should have changed
                t.notEqual(accKey.updated, updatedAccKey.updated,
                    'AccessKey Updated');

                t.equal(updatedAccKey.description,
                    description,
                    'AccessKey description');

                next(null, updatedAccKey);
            });
        },
        function removeDescription(accKey, next) {
            var accesskey = {
                accesskeyid: accKey.accesskeyid,
                description: null
            };
            ufds.updateAccessKey(ID, accesskey, function (err, result) {
                assert.ifError(err, 'removeDescription');
                next(null, accKey);
            });
        },
        function getUpdatedAccessKeyNoDesc(accKey, next) {
            var accessKeyId = accKey.accesskeyid;
            ufds.getAccessKey(ID, accessKeyId, function (err, updatedAccKey) {
                assert.ifError(err, 'getUpdatedAccessKeyNoDesc');

                // Should not have changed
                t.ok(updatedAccKey, 'updatedAccKey');
                t.equal(accKey.accesskeyid,
                    updatedAccKey.accesskeyid, 'AccessKeyId');
                t.equal(accKey.accesskeysecret,
                    updatedAccKey.accesskeysecret, 'AccessKeySecret');
                t.equal(accKey.created, updatedAccKey.created,
                    'AccessKey Created');
                t.equal(updatedAccKey.status, accKey.status,
                    'AccessKey Status');

                // Should have changed
                t.notEqual(accKey.updated, updatedAccKey.updated,
                    'AccessKey Updated');

                t.equal(updatedAccKey.description, undefined,
                    'AccessKey description');

                next(null, updatedAccKey);
            });
        }
    ], function (err, res) {
        assert.ifError(err);
        t.done();
    });
};

exports.testSubAccountAccessKeysUpdate = function (t) {
    var description = 'You can’t expect to wield supreme executive power ' +
        'just because some watery tart threw a sword at you!';

    vasync.waterfall([
        function addAccessKey(next) {
            ufds.addAccessKey(SUB_UUID, ID, next);
        },
        function checkResponse(accKey, next) {
            t.ok(accKey, 'added AccessKey');
            t.ok(accKey.accesskeyid, 'AccessKeyId');
            t.ok(accKey.accesskeysecret, 'AccessKeySecret');
            t.ok(accKey.created, 'AccessKey Created');
            t.ok(accKey.updated, 'AccessKey Updated');
            t.equal(accKey.status, 'Active', 'AccessKey Status');
            next(null, accKey);
        },
        function updateStatus(accKey, next) {
            var accesskey = {
                accesskeyid: accKey.accesskeyid,
                status: 'Expired'
            };
            ufds.updateAccessKey(SUB_UUID, ID, accesskey,
                function (err, result) {
                assert.ifError(err, 'updateStatus');
                next(null, accKey);
            });
        },
        function getAccessKey(accKey, next) {
            var accessKeyId = accKey.accesskeyid;
            ufds.getAccessKey(SUB_UUID, accessKeyId, ID,
                function (err, updatedAccKey) {
                assert.ifError(err, 'getAccessKey');

                // Should not have changed
                t.ok(updatedAccKey, 'updatedAccKey');
                t.equal(accKey.accesskeyid,
                    updatedAccKey.accesskeyid, 'AccessKeyId');
                t.equal(accKey.accesskeysecret,
                    updatedAccKey.accesskeysecret, 'AccessKeySecret');
                t.equal(accKey.created, updatedAccKey.created,
                    'AccessKey Created');
                t.equal(accKey.description, updatedAccKey.description,
                    'AccessKey description');

                // Should have changed
                t.equal(updatedAccKey.status, 'Expired', 'AccessKey Status');
                t.notEqual(accKey.updated, updatedAccKey.updated,
                    'AccessKey Updated');

                next(null, updatedAccKey);
            });
        },
        function addDescription(accKey, next) {
            var accesskey = {
                accesskeyid: accKey.accesskeyid,
                description: description
            };
            ufds.updateAccessKey(SUB_UUID, ID, accesskey,
                function (err, result) {
                assert.ifError(err, 'addDescription');
                next(null, accKey);
            });
        },
        function getAccessKeyDesc(accKey, next) {
            var accessKeyId = accKey.accesskeyid;
            ufds.getAccessKey(SUB_UUID, accessKeyId, ID,
                function (err, updatedAccKey) {
                assert.ifError(err, 'getAccessKey');
                // Should not have changed
                t.ok(updatedAccKey, 'updatedAccKey');
                t.equal(accKey.accesskeyid,
                    updatedAccKey.accesskeyid, 'AccessKeyId');
                t.equal(accKey.accesskeysecret,
                    updatedAccKey.accesskeysecret, 'AccessKeySecret');
                t.equal(accKey.created, updatedAccKey.created,
                    'AccessKey Created');
                t.equal(updatedAccKey.status, accKey.status,
                    'AccessKey Status');

                // Should have changed
                t.notEqual(accKey.updated, updatedAccKey.updated,
                    'AccessKey Updated');

                t.equal(updatedAccKey.description,
                    description,
                    'AccessKey description');

                next(null, updatedAccKey);
            });
        },
        function listActiveAccessKeys(accKey, next) {
            t.ok(accKey, 'listActiveAccessKeys key');
            ufds.listActiveAccessKeys(SUB_UUID, ID,
                function (listErr, listOfKeys) {
                assert.ifError(listErr, 'listAccessKeys error');
                assert.deepEqual([], listOfKeys, 'no active keys');
                next(null, accKey);
            });
        },
        function removeDescription(accKey, next) {
            var accesskey = {
                accesskeyid: accKey.accesskeyid,
                description: null
            };
            ufds.updateAccessKey(SUB_UUID, ID, accesskey,
                function (err, result) {
                assert.ifError(err, 'removeDescription');
                next(null, accKey);
            });
        },
        function getAccessKeyUpdated(accKey, next) {
            var accessKeyId = accKey.accesskeyid;
            ufds.getAccessKey(SUB_UUID, accessKeyId, ID,
                function (err, updatedAccKey) {
                assert.ifError(err, 'getAccessKey');

                // Should not have changed
                t.ok(updatedAccKey, 'updatedAccKey');
                t.equal(accKey.accesskeyid,
                    updatedAccKey.accesskeyid, 'AccessKeyId');
                t.equal(accKey.accesskeysecret,
                    updatedAccKey.accesskeysecret, 'AccessKeySecret');
                t.equal(accKey.created, updatedAccKey.created,
                    'AccessKey Created');
                t.equal(updatedAccKey.status, accKey.status,
                    'AccessKey Status');

                // Should have changed
                t.notEqual(accKey.updated, updatedAccKey.updated,
                    'AccessKey Updated');

                t.equal(updatedAccKey.description, undefined,
                    'AccessKey description');

                next(null, updatedAccKey);
            });
        }
    ], function (err, res) {
        assert.ifError(err);
        t.done();
    });
};


// Sanity check that sub account keys and parent keys are separate
exports.testSubAccountAccessKeysChecks = function (t) {

    vasync.waterfall([

        // wipe out any existing keys for test users and children

        function purgeParentKeys(next) {
            ufds.listAccessKeys(ID, function (listErr, listOfKeys) {
                vasync.forEachParallel({
                    inputs: listOfKeys,
                    func: function deleteKeys(key, cb) {
                        ufds.deleteAccessKey(ID, key, cb);
                    }
                }, next);
            });
        },
        function purgeChild1Keys(_, next) {
            ufds.listAccessKeys(SUB_UUID, ID, function (listErr, listOfKeys) {
                vasync.forEachParallel({
                    inputs: listOfKeys,
                    func: function deleteKeys(key, cb) {
                        ufds.deleteAccessKey(SUB_UUID, key, ID, cb);
                    }
                }, next);
            });
        },
        function purgeChild2Keys(_, next) {
            ufds.listAccessKeys(SUB_UUID2, ID, function (listErr, listOfKeys) {
                vasync.forEachParallel({
                    inputs: listOfKeys,
                    func: function deleteKeys(key, cb) {
                        ufds.deleteAccessKey(SUB_UUID2, key, ID, cb);
                    }
                }, next);
            });
        },

        // confirm all keys have been purged

        function parentKeysEmpty(_, next) {
            ufds.listAccessKeys(ID, function (listErr, listOfKeys) {
                assert.ifError(listErr, 'parentKeysEmpty error');
                t.ok(Array.isArray(listOfKeys, 'list of keys is an array'));
                t.equal(listOfKeys.length, 0);
                next(null, {});
            });
        },
        function child1KeysEmpty(_, next) {
            ufds.listAccessKeys(SUB_UUID, ID, function (listErr, listOfKeys) {
                assert.ifError(listErr, 'child1KeysEmpty error');
                t.ok(Array.isArray(listOfKeys, 'list of keys is an array'));
                t.equal(listOfKeys.length, 0);
                next(null, {});
            });
        },
        function child2KeysEmpty(_, next) {
            ufds.listAccessKeys(SUB_UUID2, ID, function (listErr, listOfKeys) {
                assert.ifError(listErr, 'child2KeysEmpty error');
                t.ok(Array.isArray(listOfKeys, 'list of keys is an array'));
                t.equal(listOfKeys.length, 0);
                next(null, {});
            });
        },

        // Create a key in the parent and one in each child account

        function addParentAccessKey(_, next) {
            ufds.addAccessKey(ID, function (err, key) {
                assert.ifError(err, 'addParentAccessKey');
                next(null, {parent: [key]});
            });
        },

        function addChild1AccessKey(context, next) {
            ufds.addAccessKey(SUB_UUID, ID, function (err, key) {
                assert.ifError(err, 'addChild1AccessKey');
                context.child1 = [key];
                next(null, context);
            });
        },

        function addChild2AccessKey(context, next) {
            ufds.addAccessKey(SUB_UUID2, ID, function (err, key) {
                assert.ifError(err, 'addChild2AccessKey');
                context.child2 = [key];
                next(null, context);
            });
        },

        // Ensure keys aren't intermingled

        function listParentAccessKeys(context, next) {
            ufds.listAccessKeys(ID, function (err, keys) {
                assert.ifError(err, 'listParentAccessKeys');
                assert.deepEqual(context.parent, keys);
                assert.notDeepEqual(context.child1, keys);
                assert.notDeepEqual(context.child2, keys);
                next(null, context);
            });
        },

        function listChild1AccessKeys(context, next) {
            ufds.listAccessKeys(SUB_UUID, ID, function (err, keys) {
                assert.ifError(err, 'listChild1AccessKeys');
                assert.deepEqual(context.child1, keys);
                assert.notDeepEqual(context.child2, keys);
                assert.notDeepEqual(context.parent, keys);
                next(null, context);
            });
        },

        function listChild2AccessKeys(context, next) {
            ufds.listAccessKeys(SUB_UUID2, ID, function (err, keys) {
                assert.ifError(err, 'listChild2AccessKeys');
                assert.deepEqual(context.child2, keys);
                assert.notDeepEqual(context.child1, keys);
                assert.notDeepEqual(context.parent, keys);
                next(null, context);
            });
        }
    ], function (err, res) {
        assert.ifError(err);
        t.done();
    });
};

exports.tearDown = function (callback) {
    ufds.close(function () {
        callback();
    });
};