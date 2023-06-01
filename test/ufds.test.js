/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2020 Joyent, Inc.
 * Copyright 2023 MNX Cloud, Inc.
 */

var assert = require('assert-plus');
var Logger = require('bunyan');
var uuidv4 = require('uuid/v4');
var util = require('util');
var vasync = require('vasync');

var UFDS = require('../lib/index');


// --- Globals

assert.string(process.env.UFDS_IP, 'UFDS_IP envvar');
assert.string(process.env.UFDS_LDAP_ROOT_PASSWORD,
    'UFDS_LDAP_ROOT_PASSWORD envvar');

var UFDS_URL = 'ldaps://' + process.env.UFDS_IP;
var UFDS_PASSWORD = process.env.UFDS_LDAP_ROOT_PASSWORD;

var ufds;

// Some test depend on a minimum version
var UFDS_VERSION;

var SSH_KEY = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAvad19ePSDckmgmo6Unqmd8' +
    'n2G7o1794VN3FazVhV09yooXIuUhA+7OmT7ChiHueayxSubgL2MrO/HvvF/GGVUs/t3e0u4' +
    '5YwRC51EVhyDuqthVJWjKrYxgDMbHru8fc1oV51l0bKdmvmJWbA/VyeJvstoX+eiSGT3Jge' +
    'egSMVtc= mark@foo.local';

var SSH_KEY_TWO = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCymx1xJfEugfRzb3G4H' +
'dB8pzwZWbRo6kCSSgrpElMkOSPiPYCqaRVoD7FaX1yv1wUwQzuS/9rrf9PFvdGk81CNMpy0NG/I' +
'6nlMH/v+mKvJYGvX5hc/fAg8izLwBwqCkJw/nek8Hv3PL4bJUZ18driqn4LUoj+gFlcmYoJy9+p' +
'uvGkgDmXQxx5z0Vf+J6N6DQo8mymgbzvAMQNgf4xfTGCjIbUJFCVOMnH2S7XPypbGzOYS3Z8VYT' +
'bt3AZHhEq9ZK4JfC60P8ddZvx6HFxOpqcoE6lFKj2GGziXusNndxfMKjTcZx2IHHlkR2+umeEnM' +
'QhuWNEaoMFHiEIWU8h8HloD whatever@wherever.local';

var SSH_KEY_THREE = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDY2qV5e2q8qb+kYtn' +
'pvRxC5PM6aqPPgWcaXn2gm4jtefGAPuJX9fIkz/KTRRLxdG27IMt6hBXRXvL0Gzw0H0mSUPHAbq' +
'g4TAyG3/xEHp8iLH/QIf/RwVgjoGB0MLZn7q+L4ThMDo9rIrc5CpfOm/AN9vC4w0Zzu/XpJbzjd' +
'pTXOh+vmOKkiWCzN+BJ9DvX3iei5NFiSL3rpru0j4CUjBKchUg6X7mdv42g/ZdRT9rilmEP154F' +
'X/bVsFHitmyyYgba+X90uIR8KGLFZ4eWJNPprJFnCWXrpY5bSOgcS9aWVgCoH8sqHatNKUiQpZ4' +
'Lsqr+Z4fAf4enldx/KMW91iKn whatever@wherever.local';

var PWD = process.env.ADMIN_PWD || 'joypass123';

var ID = uuidv4();
var LOGIN = 'a' + ID.substr(0, 7);
var EMAIL = LOGIN + '_test@joyent.com';
var USER_FMT = 'uuid=%s, ou=users, o=smartdc';
var DN = util.format(USER_FMT, ID);

var SUB_ID = uuidv4();
var SUB_LOGIN = 'a' + SUB_ID.substr(0, 7);
var SUB_EMAIL = SUB_LOGIN + '_test@joyent.com';
var SUB_UUID;

var DC = process.env.DC || 'coal';
var DCLC_FMT = 'dclocalconfig=%s, ';
var DCLC_USER_DN = util.format(DCLC_FMT + USER_FMT, DC, ID);
var DCLC_SUBUSER_FMT = DCLC_FMT + 'uuid=%s, ' + USER_FMT;

var DCLOCALCONFIG = {
    dclocalconfig: DC,
    defaultfabricsetup: 'false'
};


// --- Tests

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

exports.testQueryVersion = function (test) {
    // Until v18, version was not present in the rootDSE
    // Default to that in case none is found.
    UFDS_VERSION = 17;
    ufds.search('', {scope: 'base'}, function (err, res) {
        if (!err) {
            var version = parseInt(res[0].morayVersion, 10);
            if (version >= 17) {
                UFDS_VERSION = version;
            }
        }
        test.ok(UFDS_VERSION, util.format('ufds version v%d', UFDS_VERSION));
        test.done();
    }, true);
};

exports.testGetUser = function (test) {
    var entry = {
        login: LOGIN,
        email: EMAIL,
        uuid: ID,
        userpassword: PWD,
        objectclass: 'sdcperson'
    };

    ufds.add(DN, entry, function (err) {
        test.ifError(err);
        ufds.getUser(LOGIN, function (err, user) {
            test.ifError(err);
            test.equal(user.login, LOGIN);
            // Testing no hidden attributes are available:
            test.ok(!user._owner);
            test.ok(!user._parent);
            // test no dclocalconfig object (yet);
            test.ok(user.hasOwnProperty('dclocalconfig'),
                'has dclocalconfig property');
            test.equal(user.dclocalconfig, null, 'dclocalconfig is empty');
            test.done();
        });
    });
};


exports.testGetUserByUuid = function (test) {
    ufds.getUser(ID, function (err, user) {
        test.ifError(err);
        test.equal(user.login, LOGIN);
        test.done();
    });
};


exports.testGetUserByEmail = function (test) {
    ufds.getUserByEmail(EMAIL, function (err, user) {
        test.ifError(err);
        test.equal(user.login, LOGIN);
        test.done();
    });
};

exports.testGetUserNotFound = function (test) {
    ufds.getUser(uuidv4(), function (err, user) {
        test.ok(err);
        test.equal(err.statusCode, 404);
        test.equal(err.restCode, 'ResourceNotFound');
        test.ok(err.message);
        test.ok(!user);
        test.done();
    });
};

exports.testGetUserExByUuid = function (test) {
    ufds.getUserEx({
        searchType: 'uuid',
        value: ID
    }, function (err, user) {
        test.ifError(err);
        test.strictEqual(user.login, LOGIN);
        test.done();
    });
};

exports.testGetUserExByLogin = function (test) {
    ufds.getUserEx({
        searchType: 'login',
        value: LOGIN
    }, function (err, user) {
        test.ifError(err);
        test.strictEqual(user.login, LOGIN);
        test.done();
    });
};

exports.testGetUserExByLoginNotFound = function (test) {
    ufds.getUserEx({
        searchType: 'login',
        value: LOGIN + 'whatever'
    }, function (err, user) {
        test.ok(err);
        test.equal(err.statusCode, 404);
        test.equal(err.restCode, 'ResourceNotFound');
        test.ok(err.message);
        test.ok(!user);
        test.done();
    });
};

exports.testGetUserExByUuidNotFound = function (test) {
    ufds.getUserEx({
        searchType: 'uuid',
        value: ID + '00'
    }, function (err, user) {
        test.ok(err);
        test.equal(err.statusCode, 404);
        test.equal(err.restCode, 'ResourceNotFound');
        test.ok(err.message);
        test.ok(!user);
        test.done();
    });
};

/*
 * Ensure that getUserEx() does not search by uuid when we asked for login:
 */
exports.testGetUserExNoCrossOver0 = function (test) {
    ufds.getUserEx({
        searchType: 'login',
        value: ID
    }, function (err, user) {
        test.ok(err);
        test.equal(err.statusCode, 404);
        test.equal(err.restCode, 'ResourceNotFound');
        test.ok(err.message);
        test.ok(!user);
        test.done();
    });
};

/*
 * Ensure that getUserEx() does not search by login when we asked for uuid:
 */
exports.testGetUserExNoCrossOver1 = function (test) {
    ufds.getUserEx({
        searchType: 'uuid',
        value: LOGIN
    }, function (err, user) {
        test.ok(err);
        test.equal(err.statusCode, 404);
        test.equal(err.restCode, 'ResourceNotFound');
        test.ok(err.message);
        test.ok(!user);
        test.done();
    });
};

/*
 * getUserEx() should fail if we pass spurious options.
 */
exports.testGetUserExError0 = function (test) {
    test.throws(function () {
        ufds.getUserEx({
            someInvalidProperty: 'bogus',
            searchType: 'uuid',
            value: ID
        }, function () {});
    });
    test.done();
};

/*
 * getUserEx() should fail if we request an invalid search type.
 */
exports.testGetUserExError1 = function (test) {
    test.throws(function () {
        ufds.getUserEx({
            searchType: 'bogus',
            value: ID
        }, function () {});
    });
    test.done();
};

/*
 * getUserEx() should fail if "value" is provided, but is not a string.
 */
exports.testGetUserExError2 = function (test) {
    test.throws(function () {
        ufds.getUserEx({
            searchType: 'uuid',
            value: 1
        }, function () {});
    });
    test.done();
};

exports.testEmptyListDcLocalConfig = function (test) {
    ufds.listDcLocalConfig(ID, function (err, cfg) {
        test.ifError(err, 'err listing dc config object');
        test.equal(cfg, null, 'null dclocalconfig');
        test.done();
    });
};

exports.testAddDcLocalConfig = function (test) {
    var entry = {
        dclocalconfig: DCLOCALCONFIG.dclocalconfig,
        defaultfabricsetup: DCLOCALCONFIG.defaultfabricsetup
    };
    ufds.addDcLocalConfig(ID, DC, entry, function (err, cfg) {
        test.ifError(err, 'no errors');
        test.ok(cfg, 'added cfg');
        if (cfg) {
            test.equal(cfg.dn, DCLC_USER_DN, 'dn correct');
            test.equal(cfg.dclocalconfig, DCLOCALCONFIG.dclocalconfig,
                'dclocalconfig correct');
            test.equal(cfg.defaultfabricsetup, DCLOCALCONFIG.defaultfabricsetup,
                'defaultfabricsetup correct');
        }
        test.done();
    });
};

exports.testGetUserWithDcConfig = function (test) {
    ufds.getUser(ID, function (err, user) {
        test.ifError(err, 'err getting user');
        test.ok(user, 'user');
        test.ok(user.dclocalconfig, 'has dc config');
        if (user.dclocalconfig) {
            test.equal(DCLC_USER_DN, user.dclocalconfig.dn, 'dn correct');
            test.equal(DCLOCALCONFIG.dclocalconfig,
                user.dclocalconfig.dclocalconfig, 'dclocalconfig correct');
            test.equal(DCLOCALCONFIG.defaultfabricsetup,
                user.dclocalconfig.defaultfabricsetup,
                'defaultfabricsetup correct');
        }
        test.done();
    });
};

exports.testGetDcLocalConfig = function (test) {
    ufds.getDcLocalConfig(ID, DC, function (err, cfg) {
        test.ifError(err, 'getting dc config object');
        test.ok(cfg, 'found config object');
        if (cfg) {
            test.equal(cfg.dn, DCLC_USER_DN, 'dn correct');
            test.equal(cfg.dclocalconfig, DCLOCALCONFIG.dclocalconfig,
                'dclocalconfig correct');
            test.equal(cfg.defaultfabricsetup, DCLOCALCONFIG.defaultfabricsetup,
                'defaultfabricsetup correct');
        }
        test.done();
    });
};

exports.testListDcLocalConfig = function (test) {
    ufds.listDcLocalConfig(ID, function (err, cfg) {
        test.ifError(err, 'listing dc config object');
        test.ok(cfg, 'found config object');
        if (cfg) {
            test.equal(cfg.dn, DCLC_USER_DN, 'dn correct');
            test.equal(cfg.dclocalconfig, DCLOCALCONFIG.dclocalconfig,
                'dclocalconfig correct');
            test.equal(cfg.defaultfabricsetup, DCLOCALCONFIG.defaultfabricsetup,
                'defaultfabricsetup correct');
        }
        test.done();
    });
};

exports.testUpdateDcLocalConfig = function (test) {
    var update = {
        defaultfabricsetup: 'true',
        defaultnetwork: uuidv4()
    };
    ufds.updateDcLocalConfig(ID, DC, update, function (err, cfg) {
        test.ifError(err, 'updated dc config');
        test.ok(cfg, 'updated config object');
        if (cfg) {
            test.equal(cfg.dn, DCLC_USER_DN, 'dn correct');
            test.equal(cfg.dclocalconfig, DCLOCALCONFIG.dclocalconfig,
                'dclocalconfig correct');
            test.equal(cfg.defaultfabricsetup, update.defaultfabricsetup,
                'defaultfabricsetup updated');
            test.equal(cfg.defaultnetwork, update.defaultnetwork,
                'defaultnetwork updated');
        }
        test.done();
    });
};

exports.testDelUpdateDcLocalConfig = function (test) {
    var update = {
        defaultnetwork: null
    };
    ufds.updateDcLocalConfig(ID, DC, update, function (err, cfg) {
        test.ifError(err, 'updated dc config');
        test.ok(cfg, 'config object');
        if (cfg) {
            test.equal(cfg.dclocalconfig, DC,
                'dclocalconfig still present');
            test.ok(!cfg.defaultnetwork, 'correctly deleted');
        }
        test.done();
    });
};

exports.testDeleteDcLocalConfig = function (test) {
    ufds.deleteDcLocalConfig(ID, DC, function (err) {
        test.ifError(err, 'deleted config ogject');
        ufds.getDcLocalConfig(ID, DC, function (err, data) {
            test.ok(err, 'err');
            if (err) {
                test.equal(err.statusCode, 404, 'cfg object not found');
            }
            test.done();
        });
    });
};

exports.testAuthenticate = function (test) {
    ufds.authenticate(LOGIN, PWD, function (err, user) {
        test.ifError(err);
        test.ok(user);
        ufds.getUser(LOGIN, function (err, user2) {
            test.ifError(err);
            test.equal(user.login, user2.login);
            test.done();
        });
    });
};


exports.testAuthenticateByUuid = function (test) {
    ufds.authenticate(ID, PWD, function (err, user) {
        test.ifError(err);
        test.ok(user);
        test.equal(user.login, LOGIN);
        user.authenticate(PWD, function (err) {
            test.ifError(err);
            test.done();
        });
    });
};


exports.testAddKey = function (test) {
    ufds.getUser(LOGIN, function (err, user) {
        test.ifError(err);
        user.addKey(SSH_KEY, function (err, key) {
            test.ifError(err, err);
            test.ok(key, 'have key: ' + key);
            if (key) {
                test.equal(key.openssh, SSH_KEY);
                test.equal(key.name, 'mark@foo.local');
                test.equal(key.fingerprint,
                    '59:a4:61:0e:38:18:9f:0f:28:58:2a:27:f7:65:c5:87');
            }
            test.done();
        });
    });
};


exports.testAddDuplicatedKeyNotAllowed = function (test) {
    ufds.getUser(LOGIN, function (err, user) {
        test.ifError(err, 'getUser error');
        user.addKey(SSH_KEY, function (err, key) {
            test.ok(err, 'add duplicated key error');
            test.done();
        });
    });
};


exports.testListAndGetKeys = function (test) {
    ufds.getUser(LOGIN, function (err, user) {
        test.ifError(err);
        user.listKeys(function (err, keys) {
            test.ifError(err);
            test.ok(keys);
            test.ok(keys.length);
            test.equal(keys[0].openssh, SSH_KEY);
            test.equal(keys[0].name, 'mark@foo.local');
            user.getKey(keys[0].fingerprint, function (err, key) {
                test.ifError(err);
                test.ok(key);
                test.deepEqual(keys[0], key);
                test.done();
            });
        });
    });
};


exports.testAddKeyByName = function (test) {
    ufds.getUser(LOGIN, function (err, user) {
        test.ifError(err);
        user.addKey({
            openssh: SSH_KEY_TWO,
            name: 'id_rsa'
        }, function (err, key) {
            test.ifError(err);
            test.ok(key);
            test.equal(key.openssh, SSH_KEY_TWO);
            test.equal(key.name, 'id_rsa');
            test.done();
        });
    });

};

exports.testAddDuplicatedKeyByName = function (test) {
    ufds.getUser(LOGIN, function (err, user) {
        test.ifError(err, 'getUser error');
        user.addKey({
            openssh: SSH_KEY_THREE,
            name: 'id_rsa'
        }, function (err, key) {
            test.ok(err, 'add duplicated key error');
            test.done();
        });
    });
};


exports.testDelKey = function (test) {
    ufds.getUser(LOGIN, function (err, user) {
        test.ifError(err);
        user.listKeys(function (err, keys) {
            test.ifError(err);
            user.deleteKey(keys[0], function (err) {
                test.ifError(err);
                user.deleteKey(keys[1], function (err) {
                    test.ifError(err);
                    test.done();
                });
            });
        });
    });
};


exports.testUserGroups = function (test) {
    ufds.getUser(LOGIN, function (err, user) {
        test.ifError(err);
        test.ok(!user.isAdmin());
        test.ok(!user.isReader());
        user.addToGroup('readers', function (err2) {
            test.ifError(err2);
            ufds.getUser(LOGIN, function (err3, user2) {
                test.ifError(err3);
                test.ok(user2.isReader());
                test.deepEqual(user2.groups(), ['readers']);
                user2.addToGroup('operators', function (err4) {
                    test.ifError(err4);
                    ufds.getUser(LOGIN, function (err5, user3) {
                        test.ifError(err5);
                        test.ok(user3.isAdmin());
                        test.deepEqual(user3.groups(),
                            ['operators', 'readers']);
                        user3.removeFromGroup('operators', function (err6) {
                            test.ifError(err6);
                            ufds.getUser(LOGIN, function (err7, user4) {
                                test.ifError(err7);
                                test.ok(user4.isReader() && !user4.isAdmin());
                                test.deepEqual(user4.groups(), ['readers']);
                                test.done();
                            });
                        });
                    });
                });
            });
        });
    });
};


exports.testCrudUser = function (test) {
    var entry = {
        login: 'a' + uuidv4().replace('-', '').substr(0, 7),
        email: uuidv4() + '@devnull.com',
        userpassword: 'secret123'
    };
    ufds.addUser(entry, function (err, user) {
        test.ifError(err);
        test.ok(user);
        test.ok(user.uuid);
        ufds.updateUser(user, {
            phone: '+1 (206) 555-1212',
            pwdaccountlockedtime: Date.now() + (3600 * 1000)
        }, function (err) {
            test.ifError(err);
            user.authenticate(entry.userpassword, function (er) {
                test.ok(er);
                test.equal(er.statusCode, 401);
                user.unlock(function (e) {
                    test.ifError(e);
                    user.authenticate(entry.userpassword, function (er2) {
                        test.ifError(er2);
                        user.destroy(function (err) {
                            test.ifError(err);
                            test.done();
                        });
                    });
                });
            });
        });
    });
};


exports.testCrudLimit = function (test) {
    ufds.getUser(LOGIN, function (err, user) {
        test.ifError(err);
        test.ok(user);
        user.addLimit(
          {datacenter: 'coal', smartos: '123'},
          function (err, limit) {
            test.ifError(err);
            test.ok(limit);
            test.ok(limit.smartos);
            user.listLimits(function (err, limits) {
                test.ifError(err);
                test.ok(limits);
                test.ok(limits.length);
                test.ok(limits[0].smartos);
                limits[0].nodejs = 234;
                user.updateLimit(limits[0], function (err) {
                    test.ifError(err);
                    user.getLimit(limits[0].datacenter, function (err, limit) {
                        test.ifError(err);
                        test.ok(limit);
                        test.ok(limit.smartos);
                        test.ok(limit.nodejs);
                        user.deleteLimit(limit, function (err) {
                            test.ifError(err);
                            test.done();
                        });
                    });
                });
            });
        });
    });
};


exports.testMetadata = function (t) {
    var meta = {
        whatever: 'A meaningful value for whatever setting it'
    };
    var key = 'some-app';
    var META_FMT = 'metadata=%s, uuid=%s, ou=users, o=smartdc';

    ufds.getUser(LOGIN, function (err, user) {
        t.ifError(err, 'testMetadata getUser error');
        t.ok(user);
        ufds.addMetadata(user, key, meta, function (err2, metadata) {
            t.ifError(err2, 'testMetadata addMetadata error');
            t.ok(metadata.cn);
            t.equal(key, metadata.cn);
            t.ok(metadata.dn);
            t.equal(metadata.dn, util.format(META_FMT, key, user.uuid));
            t.ok(metadata.objectclass);
            t.equal('capimetadata', metadata.objectclass);
            // CAPI-319: getMetadata w/o object
            ufds.getMetadata(LOGIN, key, function (err3, meta3) {
                t.ifError(err3, 'testMetadata getMetadata error');
                t.ok(meta3);
                // And now with object:
                ufds.getMetadata(user, key, function (err4, meta4) {
                    t.ifError(err4, 'testMetadata getMetadata error');
                    t.ok(meta4);
                    ufds.deleteMetadata(user, key, function (er5, meta5) {
                        t.ifError(er5);
                        t.done();
                    });
                });
            });
        });
    });
};


// Account users and roles:
exports.testAddSubUserToAccount = function (test) {
    var entry = {
        login: SUB_LOGIN,
        email: SUB_EMAIL,
        userpassword: PWD,
        objectclass: 'sdcperson',
        account: ID
    };
    ufds.addUser(entry, function (err, user) {
        test.ifError(err, 'err adding user');
        test.ok(user, 'returned new user');
        test.strictEqual(user.login, SUB_LOGIN, 'login correct');
        test.strictEqual(user.uuid.length, 36, 'uuid set');
        test.ok(!SUB_UUID, 'SUB_UUID was already set');
        SUB_UUID = user.uuid;
        ufds.getUser(SUB_UUID, ID, function (e1, u1) {
            test.ifError(e1, 'getUser for new subuser ' + SUB_UUID + ' failed');
            test.equal(u1.login, SUB_LOGIN, 'sub_login correct');
            test.done();
        });
    });
};

exports.testGetUserExSubUserByUuid = function (test) {
    ufds.getUserEx({
        searchType: 'uuid',
        account: ID,
        value: SUB_UUID
    }, function (err, user) {
        test.ifError(err, 'getUserEx error');
        test.strictEqual(user.login, SUB_LOGIN, 'expected subuser login');
        test.done();
    });
};

exports.testGetUserExSubUserByLogin = function (test) {
    ufds.getUserEx({
        searchType: 'login',
        account: ID,
        value: SUB_LOGIN
    }, function (err, user) {
        test.ifError(err, 'getUserEx error');
        test.strictEqual(user.login, SUB_LOGIN, 'expected subuser login');
        test.done();
    });
};

exports.testGetUserExSubUserWrongLogin = function (test) {
    ufds.getUserEx({
        searchType: 'login',
        account: ID,
        value: SUB_LOGIN + 'whatever'
    }, function (err, user) {
        test.ok(err, 'error expected');
        test.strictEqual(err.statusCode, 404, 'expected statusCode');
        test.strictEqual(err.restCode, 'ResourceNotFound', 'expected restCode');
        test.ok(err.message, 'an error message was set');
        test.ok(!user, 'no user object expected');
        test.done();
    });
};

exports.testGetUserExSubUserWrongAccount = function (test) {
    ufds.getUserEx({
        searchType: 'login',
        account: ID + '1234',
        value: SUB_LOGIN
    }, function (err, user) {
        test.ok(err, 'error expected');
        test.equal(err.statusCode, 404, 'expected statusCode');
        test.equal(err.restCode, 'ResourceNotFound', 'expected restCode');
        test.ok(err.message, 'an error message was set');
        test.ok(!user, 'no user object expected');
        test.done();
    });
};

exports.testAddSubUserDcLocalConfig = function (test) {
    var entry = {
        dclocalconfig: DCLOCALCONFIG.dclocalconfig,
        defaultfabricsetup: DCLOCALCONFIG.defaultfabricsetup
    };

    ufds.addDcLocalConfig(ID, SUB_UUID, DC, entry, function (err, cfg) {
        test.ifError(err, 'no errors');
        test.ok(cfg, 'added cfg');
        if (cfg) {
            test.equal(cfg.dn, util.format(DCLC_SUBUSER_FMT,
                DC, SUB_UUID, ID), 'dn correct');
            test.equal(cfg.defaultfabricsetup, entry.defaultfabricsetup,
                'defaultfabricsetup correct');
        }
        test.done();
    });
};

exports.getSubUserWithDcLocalConfig = function (test) {
    ufds.getUser(SUB_UUID, ID, function (err, user) {
        test.ifError(err, 'err getting user');
        test.ok(user, 'user');
        if (user && user.dclocalconfig) {
            test.ok(user.dclocalconfig, 'has dc config');
            test.equal(util.format(DCLC_SUBUSER_FMT, DC, SUB_UUID, ID),
                user.dclocalconfig.dn, 'dn correct');
            test.equal(DCLOCALCONFIG.dclocalconfig,
                user.dclocalconfig.dclocalconfig, 'dclocalconfig correct');
        }
        test.done();
    });
};

exports.delSubUserDcLocalConfig = function (test) {
    ufds.deleteDcLocalConfig(ID, SUB_UUID, DC, function (err) {
        test.ifError(err, 'deleted config object');
        ufds.getDcLocalConfig(ID, SUB_UUID, DC, function (err, data) {
            test.ok(err, 'expected err');
            if (err) {
                test.equal(err.statusCode, 404, 'cfg object not found');
            }
            test.done();
        });
    });
};

exports.testSubuserKey = function (test) {
    ufds.getUser(SUB_LOGIN, ID, function (err, user) {
        test.ifError(err);
        user.addKey(SSH_KEY, function (err, key) {
            test.ifError(err, err);
            test.ok(key, 'have key: ' + key);
            if (key) {
                test.equal(key.openssh, SSH_KEY);
            }
            user.listKeys(function (er2, keys) {
                test.ifError(er2);
                test.ok(keys);
                test.ok(keys.length);
                test.equal(keys[0].openssh, SSH_KEY);
                user.getKey(keys[0].fingerprint, user.account,
                    function (er3, key2) {
                    test.ifError(er3);
                    test.ok(key2);
                    test.deepEqual(keys[0], key2);
                    user.deleteKey(keys[0], function (err) {
                        test.ifError(err);
                        test.done();
                    });
                });
            });
        });
    });
};


exports.testSubUsersMetadata = function (t) {
    var meta = {
        whatever: 'A meaningful value for whatever setting it'
    };
    var key = 'some-app';
    var SUB_META_FMT = 'metadata=%s, uuid=%s, uuid=%s, ou=users, o=smartdc';

    ufds.getUser(SUB_LOGIN, ID, function (err, user) {
        t.ifError(err, 'testMetadata getUser error');
        t.ok(user, 'metadata user');
        ufds.addMetadata(user, key, meta, function (err2, metadata) {
            t.ifError(err2, 'testMetadata addMetadata error');
            t.ok(metadata.cn, 'metadata cn');
            t.equal(key, metadata.cn, 'metadata cn value');
            t.ok(metadata.dn, 'metadata dn');
            t.equal(metadata.dn,
                util.format(SUB_META_FMT, key, user.uuid, user.account),
                'metadata dn value');
            t.ok(metadata.objectclass, 'meta objectclass');
            t.equal('capimetadata', metadata.objectclass,
                'meta objectclass val');
            // CAPI-319: getMetadata w/o object
            ufds.getMetadata(SUB_LOGIN, key, user.account,
                function (err3, meta3) {
                t.ifError(err3, 'testMetadata getMetadata error');
                t.ok(meta3, 'get meta w/o object');
                // And now with object:
                ufds.getMetadata(user, key, function (err4, meta4) {
                    t.ifError(err4, 'testMetadata getMetadata error');
                    t.ok(meta4, 'get meta with object');
                    ufds.deleteMetadata(user, key, function (er5, meta5) {
                        t.ifError(er5);
                        t.done();
                    });
                });
            });
        });
    });
};


// Sub-users limits are the same than main account user limits:
exports.testSubUsersLimits = function (test) {
    ufds.getUser(LOGIN, function (err, user) {
        test.ifError(err);
        test.ok(user);
        user.addLimit(
          {datacenter: 'coal', smartos: '123'},
          function (err, limit) {
            test.ifError(err);
            test.ok(limit);
            test.ok(limit.smartos);
            ufds.getUser(SUB_LOGIN, ID, function (err, subuser) {
                test.ifError(err, 'sub user limits getUser error');
                test.ok(subuser, 'subuser');
                subuser.listLimits(function (err, limits) {
                    test.ifError(err);
                    test.ok(limits);
                    test.ok(limits.length);
                    test.ok(limits[0].smartos);
                    subuser.getLimit(limits[0].datacenter,
                        function (err, limit) {
                        test.ifError(err);
                        test.ok(limit);
                        test.ok(limit.smartos);
                        user.deleteLimit(limit, function (err) {
                            test.ifError(err);
                            test.done();
                        });
                    });
                });
            });
        });
    });
};


function generateSubUser() {
    var id = uuidv4();
    var login = 'a' + id.substr(0, 7);
    var email = login + '_test@joyent.com';

    return ({
        login: login,
        email: email,
        userpassword: PWD,
        objectclass: 'sdcperson',
        account: ID
    });
}


exports.testSubUsersCrud = function (test) {
    var entry = generateSubUser();

    ufds.addUser(entry, function (err, user) {
        test.ifError(err);
        test.equal(user.login, entry.login);
        ufds.getUserByEmail(entry.email, entry.account,
            function (err2, user2) {
                test.ifError(err2);
                test.equal(user2.login, entry.login);

                ufds.updateUser(user.uuid, {
                    phone: '+1 (206) 555-1212',
                    pwdaccountlockedtime: Date.now() + (3600 * 1000)
                }, user.account, function (err) {
                    test.ifError(err);
                    user.authenticate(entry.userpassword, function (er) {
                        test.ok(er);
                        test.equal(er.statusCode, 401);
                        user.unlock(function (e) {
                            test.ifError(e);
                            user.authenticate(entry.userpassword,
                                function (er2) {
                                test.ifError(er2);
                                user.destroy(function (er3) {
                                    test.ifError(er3);
                                    test.done();
                                });
                            });
                        });
                    });
                });

        });
    });
};


exports.testSubUsersCrudWithObject = function (test) {
    var entry = generateSubUser();
    var update = {
        phone: '+1 (206) 555-1212'
    };

    ufds.addUser(entry, function (err, su) {
        test.ifError(err, 'addUser');
        test.strictEqual(su.login, entry.login, 'correct user returned');

        /*
         * This invocation of "updateUser()" must have both the "account"
         * property set on the user object we pass in, _and_ pass the
         * "account" positional argument to the function.
         */
        test.strictEqual(su.account, entry.account, 'user has "account" set');
        ufds.updateUser(su, update, su.account, function (err) {
            test.ifError(err, 'updateUser');

            ufds.getUserEx({
                searchType: 'uuid',
                value: su.uuid,
                account: su.account
            }, function (err, su2) {
                test.ifError(err, 'getUserEx');
                test.strictEqual(su2.phone, update.phone, 'phone updated');

                su2.destroy(function (err) {
                    test.ifError(err, 'destroy user');
                    test.done();
                });
            });
        });
    });
};


exports.testSubUsersCrudWithObjectMismatchedAccount = function (test) {
    var entry = generateSubUser();
    var update = {
        phone: '+1 (206) 555-1212'
    };

    ufds.addUser(entry, function (err, su) {
        test.ifError(err, 'addUser');
        test.strictEqual(su.login, entry.login, 'correct user returned');

        /*
         * This invocation of "updateUser()" must have both the "account"
         * property set on the user object we pass in, _and_ pass the _wrong_
         * UUID in the "account" positional argument to the function.
         */
        test.strictEqual(su.account, entry.account, 'user has "account" set');
        var wrong_uuid = entry.account.replace(/[1-9]/, '0');

        test.throws(function () {
            ufds.updateUser(su, update, wrong_uuid, function () {});
        }, 'mismatch must trip assertion failure');

        su.destroy(function (err) {
            test.ifError(err, 'destroy user');
            test.done();
        });
    });
};


exports.testAccountPolicies = function (test) {
    var policy_uuid = uuidv4();
    var cn = 'a' + policy_uuid.substr(0, 7);
    var entry = {
        name: cn,
        rule: 'John, Jack and Jane can ops_* *',
        account: ID,
        uuid: policy_uuid,
        description: 'This is completely optional'
    };
    ufds.addPolicy(ID, entry, function (err, policy) {
        test.ifError(err, 'addPolicy error');
        test.equal(policy.dn, util.format(
                'policy-uuid=%s, uuid=%s, ou=users, o=smartdc',
                policy_uuid, ID));
        ufds.listPolicies(ID, function (err, policies) {
            test.ifError(err, 'listPolicies error');
            test.ok(Array.isArray(policies), 'Array of policies');
            test.equal(policies[0].dn, util.format(
                'policy-uuid=%s, uuid=%s, ou=users, o=smartdc',
                policy_uuid, ID));
            entry.rule = [
                'Fred can read *.js when dirname::string = ' +
                'examples and sourceip = 10.0.0.0/8',
                'John, Jack and Jane can ops_* *'
            ];
            ufds.modifyPolicy(ID, entry.uuid, entry,
                function (err, policy) {
                test.ifError(err, 'modify policy error');
                test.equal(policy.rule.length, 2);
                ufds.deletePolicy(ID, entry.uuid,
                    function (err) {
                    test.ifError(err, 'deletePolicy error');
                    test.done();
                });
            });

        });
    });
};


exports.testAccountRoles = function (test) {
    var role_uuid = uuidv4();
    var cn = 'a' + role_uuid.substr(0, 7);
    var entry = {
        name: cn,
        uniquemember: util.format(
                'uuid=%s, uuid=%s, ou=users, o=smartdc', SUB_UUID, ID),
        uniquememberdefault: util.format(
                'uuid=%s, uuid=%s, ou=users, o=smartdc', SUB_UUID, ID),
        account: ID,
        uuid: role_uuid
    };
    ufds.addRole(ID, entry, function (err, role) {
        test.ifError(err, 'addGroup error');
        test.equal(role.dn, util.format(
                'role-uuid=%s, uuid=%s, ou=users, o=smartdc',
                role_uuid, ID));
        ufds.listRoles(ID, function (err, roles) {
            test.ifError(err, 'listRoles error');
            test.ok(Array.isArray(roles), 'Array of roles');
            test.equal(roles[0].dn, util.format(
                'role-uuid=%s, uuid=%s, ou=users, o=smartdc',
                role_uuid, ID));
            ufds.getUser(SUB_LOGIN, ID, function (err, subuser) {
                test.ifError(err, 'sub user limits getUser error');
                test.ok(subuser, 'subuser');
                subuser.roles(function (err, rls) {
                    test.ifError(err, 'sub user roles');
                    test.ok(Array.isArray(rls), 'user roles is an array');
                    subuser.defaultRoles(function (err, drls) {
                        test.ifError(err, 'sub user default roles');
                        test.ok(Array.isArray(drls),
                            'sub user default roles is an array');
                        entry.description = 'This is completely optional';
                        ufds.modifyRole(ID, entry.uuid, entry,
                            function (err, role) {
                            test.ifError(err, 'modify role error');
                            test.ok(role.description);
                            ufds.deleteRole(ID, entry.uuid,
                                function (err) {
                                test.ifError(err, 'deleteRole error');
                                test.done();
                            });
                        });
                    });
                });
            });
        });
    });
};


exports.testAccountDisabled = function (test) {
    if (UFDS_VERSION < 19) {
        test.ok(true, 'skipped for UFDS < v19');
        test.done();
        return;
    }
    // Disable the primary account
    var original;
    vasync.pipeline({
        funcs: [
            function checkParent(_, cb) {
                ufds.getUser(ID, function (err, user) {
                    test.ifError(err);
                    test.ok(!user.disabled, 'account not disabled');
                    original = user;
                    cb(err);
                });
            },
            function checkChild(_, cb) {
                ufds.getUser(SUB_UUID, ID, function (err, user) {
                    test.ifError(err);
                    test.ok(!user.disabled, 'sub-account not disabled');
                    cb(err);
                });
            },
            function setDisabled(_, cb) {
                original.setDisabled(true, cb);
            },
            function afterParent(_, cb) {
                ufds.getUser(ID, function (err, user) {
                    test.ifError(err);
                    test.ok(user.disabled, 'account disabled');
                    cb(err);
                });
            },
            function afterChild(_, cb) {
                ufds.getUser(SUB_UUID, ID, function (err, user) {
                    test.ifError(err);
                    test.ok(user.disabled, 'sub-account disabled');
                    cb(err);
                });
            }
        ]
    }, function (err, res) {
        test.ifError(err);
        test.done();
    });
};


exports.testRemoveUserFromAccount = function (test) {
    ufds.deleteUser(SUB_LOGIN, ID, function (err) {
        test.ifError(err);
        test.done();
    });
};


exports.testHiddenControl = function (test) {
    var ufds2 = new UFDS({
        url: UFDS_URL,
        bindDN: 'cn=root',
        bindPassword: UFDS_PASSWORD,
        clientTimeout: 2000,
        hidden: true,
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

    ufds2.once('ready', function () {
        ufds2.removeAllListeners('error');
        ufds2.getUser(LOGIN, function (err, user) {
            test.ifError(err);
            test.equal(user.login, LOGIN);
            // Testing hidden attributes are available:
            test.ok(user._owner);
            test.ok(user._parent);
            ufds2.close(function () {
                test.done();
            });
        });
    });

    ufds2.once('error', function (err) {
        ufds2.removeAllListeners('ready');
        test.ifError(err);
        test.done();
    });
};


exports.testAccountResources = function (test) {
    var res_uuid = uuidv4();
    var entry = {
        name: util.format('/%s/users', ID),
        memberrole: [ util.format(
                'role-uuid=%s, uuid=%s, ou=users, o=smartdc',
                uuidv4(), ID) ],
        account: ID,
        uuid: res_uuid
    };
    ufds.addResource(ID, entry, function (err, resource) {
        test.ifError(err, 'addResource error');
        test.equal(resource.dn, util.format(
                'resource-uuid=%s, uuid=%s, ou=users, o=smartdc',
                res_uuid, ID));
        ufds.listResources(ID, function (err, resources) {
            test.ifError(err, 'listResources error');
            test.ok(Array.isArray(resources), 'Array of resources');
            test.equal(resources[0].dn, util.format(
                'resource-uuid=%s, uuid=%s, ou=users, o=smartdc',
                res_uuid, ID));
            entry.memberrole.push(util.format(
                'role-uuid=%s, uuid=%s, ou=users, o=smartdc',
                uuidv4(), ID));
            ufds.modifyResource(ID, entry.uuid, entry,
                function (err, resource) {
                test.ifError(err, 'modify resource error');
                test.equal(resource.memberrole.length, 2);
                ufds.deleteResource(ID, entry.uuid,
                    function (err) {
                    test.ifError(err, 'deleteResource error');
                    test.done();
                });
            });
        });
    });
};


exports.testAccountAccessKeys = function (t) {
    ufds.addAccessKey(ID, function addCb(addErr, accKey) {
        t.ifError(addErr, 'addAccessKey Error');
        t.ok(accKey, 'addded AccessKey');
        t.ok(accKey.accesskeyid, 'AccessKeyId');
        t.ok(accKey.accesskeysecret, 'AccessKeySecret');
        t.ok(accKey.created, 'AccessKey Created');
        ufds.getAccessKey(ID, accKey.accesskeyid,
            function getCb(getErr, getKey) {
            t.ifError(getErr, 'getAccessKey error');
            t.ok(getKey, 'getAccessKey key');
            ufds.listAccessKeys(ID, function listCb(listErr, listOfKeys) {
                t.ifError(listErr, 'listAccessKeys error');
                t.ok(listOfKeys, 'List of access keys');
                t.ok(Array.isArray(listOfKeys, 'list of keys is an array'));
                t.ok(listOfKeys[0], 'list of keys contains a key');
                ufds.deleteAccessKey(ID, accKey, function delCb(delErr) {
                    t.ifError(delErr, 'deleteAccessKey error');
                    t.done();
                });
            });
        });
    });
};


exports.tearDown = function (callback) {
    ufds.close(function () {
        callback();
    });
};
