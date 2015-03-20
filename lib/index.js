/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

/*
 * This is the new UFDS client, including support for multiple account users,
 * roles and policies. It requires an ufds server including changes until
 * February 5th, 2014. (version >= c8d683200e)
 */

var crypto = require('crypto');
var EventEmitter = require('events').EventEmitter;
var util = require('util');

var assert = require('assert-plus');
var bunyan = require('bunyan');
var httpSignature = require('http-signature');
var clone = require('clone');
var ldap = require('ldapjs');
var once = require('once');
var restify = require('restify');
var libuuid = require('libuuid');
var vasync = require('vasync');
function uuid() {
    return (libuuid.create());
}

var cache = require('./cache');
var assertions = require('./assertions');



// --- Globals

var sprintf = util.format;

var getFingerprint = httpSignature.sshKeyFingerprint;

var InternalError = restify.InternalError;
var InvalidArgumentError = restify.InvalidArgumentError;
var InvalidCredentialsError = restify.InvalidCredentialsError;
var MissingParameterError = restify.MissingParameterError;
var NotAuthorizedError = restify.NotAuthorizedError;
var ResourceNotFoundError = restify.ResourceNotFoundError;

var DEF_LOG = bunyan.createLogger({
    name: 'sdc-client',
    component: 'ufds',
    stream: process.stderr,
    serializers: bunyan.stdSerializers
});

var HIDDEN = new ldap.Control({
    type: '1.3.6.1.4.1.38678.1',
    criticality: true
});

var LDAP_PROXY_EVENTS = [
    'connectTimeout',
    'end',
    'error',
    'socketTimeout',
    'timeout',
    'destroy'
];

var SUFFIX = 'o=smartdc';

var GROUPS = 'ou=groups, ' + SUFFIX;
var GROUP_FMT = 'cn=%s, ' + GROUPS;
var ADMIN_GROUP = sprintf(GROUP_FMT, 'operators');
var READERS_GROUP = sprintf(GROUP_FMT, 'readers');

var USERS = 'ou=users, ' + SUFFIX;
var USER_FMT = 'uuid=%s, ' + USERS;
var KEY_FMT = 'fingerprint=%s, ' + USER_FMT;

// Account sub users
var SUBUSER_FMT = 'uuid=%s, ' + USER_FMT;
var SUBUSER_KEY_FMT = 'fingerprint=%s, ' + SUBUSER_FMT;
// Account access policies
var POLICY_FMT = 'policy-uuid=%s, ' + USER_FMT;
// Account roles
var ROLE_FMT = 'role-uuid=%s, ' + USER_FMT;
// Account resources:
var RESOURCE_FMT = 'resource-uuid=%s, ' + USER_FMT;

var LIMIT_FMT = 'dclimit=%s, ' + USER_FMT;
var VM_FMT = 'vm=%s, ' + USER_FMT;
var METADATA_FMT = 'metadata=%s, ' + USER_FMT;
var SUBUSER_METADATA_FORMAT = 'metadata=%s, ' + SUBUSER_FMT;

// dclocalconfig; per-dc per-user format
var DCLC_PREFIX = 'dclocalconfig=%s, ';
var DCLC_USER_FMT = DCLC_PREFIX + USER_FMT;
var DCLC_SUBUSER_FMT = DCLC_PREFIX + SUBUSER_FMT;

var AUTHDEV_FMT = 'authdev=%s, ' + USER_FMT;
var FOREIGNDC_FMT = 'foreigndc=%s, ' + AUTHDEV_FMT;

var REGION = 'region=%s, ' + SUFFIX;

var UUID_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

// --- Internal Functions



function extendUser(self, user) {
    assert.object(self, 'self');
    assert.object(user, 'user');

    user.isAdmin = function isAdmin() {
        return (user.memberof.indexOf(ADMIN_GROUP) !== -1);
    };

    user.isReader = function isReader() {
        return (user.memberof.indexOf(READERS_GROUP) !== -1);
    };

    user.addToGroup = function addToGroup(group, cb) {

        var rdn = sprintf(GROUP_FMT, group);

        if (user.memberof.indexOf(rdn) !== -1) {
            cb(null);
            return;
        }

        var change = {
            operation: 'add',
            modification: {
                uniquemember: user.dn.toString()
            }
        };
        self.modify(rdn, [change], cb);
    };

    user.removeFromGroup = function removeFromGroup(group, cb) {

        var rdn = sprintf(GROUP_FMT, group);

        if (user.memberof.indexOf(rdn) === -1) {
            cb(null);
            return;
        }

        var change = {
            operation: 'delete',
            modification: {
                uniquemember: user.dn.toString()
            }
        };
        self.modify(rdn, [change], cb);
    };


    user.groups = function groups() {
        var grps = [];
        user.memberof.forEach(function (g) {
            var rdns = ldap.parseDN(g).rdns;
            if (rdns && rdns.length && rdns[0].cn) {
                grps.push(rdns[0].cn);
            }
        });
        return (grps);
    };

    user.unlock = function unlock(cb) {
        var mod = {
            pwdfailuretime: null,
            pwdaccountlockedtime: null
        };
        self.updateUser(user, mod, cb);
    };

    user.setDisabled = function setDisabled(value, cb) {
        assert.bool(value);
        if (user.account) {
            return cb(new Error('not valid for user-users'));
        }
        var mod = {
            disabled: value
        };
        return self.updateUser(user, mod, cb);
    };

    // Reexport the prototype as bounds so callers can use convenience
    // functions (warning: this is slow)
    // FIXME: Remove addLimit, updateLimit and deleteLimit since those
    // cannot be used with account sub-users (and aren't in use anywhere).
    [
        'authenticate',
        'addKey',
        'getKey',
        'listKeys',
        'deleteKey',
        'addLimit',
        'getLimit',
        'listLimits',
        'updateLimit',
        'deleteLimit'
    ].forEach(function curry(f) {
        user[f] = UFDS.prototype[f].bind(self, user);
    });

    user.destroy = UFDS.prototype.deleteUser.bind(self, user);

    return (user);
}


function translateError(err) {
    assert.object(err, 'error');

    var error;

    if (err instanceof restify.HttpError) {
        error = err;
    } else if (err instanceof ldap.LDAPError) {
        switch (err.name) {

        case 'NoSuchAttributeError':
        case 'NoSuchObjectError':
        case 'UndefinedAttributeTypeError':
            error = new ResourceNotFoundError('The resource you requested ' +
                                              'does not exist');
            break;

        case 'InvalidDnSyntax':
        case 'AttributeOrValueExistsError':
        case 'ConstraintViolationError':
        case 'ObjectclassModsProhibitedError':
            error = new InvalidArgumentError(err.message);
            break;

        case 'EntryAlreadyExistsError':
            error =  new InvalidArgumentError(err.message + ' already exists');
            break;

        case 'ObjectclassViolationError':
            var msg = sprintf('Request is missing a required parameter (%s)',
                              err.message);
            error = new MissingParameterError(msg);
            break;


        case 'NotAllowedOnNonLeafError':
        case 'NotAllowedOnRdnError':
            error = new InvalidArgumentError(
                'The resource in question has "child" elements or is ' +
                    'immutable and cannot be destroyed');
            break;

        default:
            error = new restify.InternalError(err.message);
            break;
        }
    } else {
        error = new restify.InternalError(err.message);
    }

    return (error);
}



// --- Exported API

/**
 * Creates a UFDS client that will stay connected "forever", and automatically
 * binds with credentials you provide.
 *
 * As an example usage around connection management:
 *
 *    var bunyan = require('bunyan');
 *    var sdc = require('sdc-clients');
 *
 *
 *    var log = bunyan.createLogger({
 *        level: 'warn',
 *        name: 'ufds_client',
 *        serializers: bunyan.stdSerializers,
 *        stream: process.stderr
 *    });
 *
 *    var client = new sdc.UFDS({
 *        bindDN: 'cn=root',
 *        bindPassword: 'secret',
 *        clientTimeout: 2000,     // maximum operation time
 *        connectTimeout: 4000,
 *        log: log,
 *        retry: {
 *            maxDelay: 8000
 *        },
 *        url: 'ldaps://' + process.env.UFDS_IP + ':636'
 *    });
 *
 *    client.once('connect', function () {
 *        client.removeAllListeners('error');
 *        client.on('error', function (err) {
 *            log.warn(err, 'UFDS: unexpected error occurred');
 *        });
 *
 *        client.on('close', function () {
 *            log.warn('UFDS: disconnected');
 *        });
 *
 *        client.on('connect', function () {
 *            log.info('UFDS: reconnected');
 *        });
 *
 *        log.info('UFDS: connected');
 *
 *        // Let's get a user and their keys
 *        client.getUser('admin', function (err, user) {
 *            assert.ifError(err);
 *
 *            // Note the user object has its own methods
 *            user.listKeys(function (err2, keys) {
 *                assert.ifError(err2);
 *
 *                keys.forEach(function (k) {
 *                    log.debug({
 *                        user: user.login,
 *                        key: k
 *                    }, 'key found');
 *                });
 *
 *                client.close();
 *            });
 *
 *        });
 *    });
 *
 *    client.once('error', function (err) {
 *        log.fatal(err, 'UFDS: unable to connect and/or bind');
 *        process.exit(1);
 *    });
 *
 *
 * @param {Object} options options object:
 *                  - url {String} UFDS location
 *                  - bindDN {String} admin bind DN
 *                  - bindPassword {String} password to said admin DN
 *                  - cacheOptions {Object} age (def: 60s) and size (def: 1k).
 *                                 Use false to disable altogether.
 *                  - clientTimeout {Number} Optional request timeout (in ms)
 *                    to pass to ldapjs client. Any request that takes longer
 *                    will be terminated with a 'request timeout (client
 *                    interrupt)' error. By default there is no timeout.
 *                  - connectTimeout {Number} TCP connect timeout.
 *                  - log {Bunyan Logger} Optional.
 *                  - retry {Object} Optional:
 *                    - maxDelay {Number} maximum amount of time between retries
 *                    - retries {Number} maximum # of retries
 *                  - failFast {Boolean} Optional: While client is
 *                    disconnected, report errors to requests instead of
 *                    queueing them.
 *                  - tlsOptions {Object} node TLS options
 */
function UFDS(opts) {
    assert.object(opts, 'options');
    assert.string(opts.bindDN, 'options.bindDN');
    assert.string(opts.bindPassword, 'options.bindPassword');
    assert.ok(!opts.bindCredentials, 'options.bindCredentials not supported');
    assert.optionalObject(opts.log, 'options.log');
    assert.string(opts.url, 'options.url');

    var self = this;
    EventEmitter.call(this);

    this.cacheOptions = clone(opts.cache || false);
    this.cache =
        this.cacheOptions ? cache.createCache(this.cacheOptions) : null;
    this.log = (opts.log || DEF_LOG).child({component: 'ufds'}, true);

    this.ldapOpts = {
        connectTimeout: opts.connectTimeout,
        credentials: {
            dn: opts.bindDN,
            passwd: opts.bindPassword
        },
        log: self.log,
        reconnect: {
            maxDelay: 30000,
            failAfter: Infinity
        },
        tlsOptions: {
            rejectUnauthorized: false
        },
        timeout: opts.clientTimeout || opts.timeout,
        url: opts.url,
        idleTimeout: opts.idleTimeout || 90000,
        queueSize: 10,
        queueTimeout: 200
    };
    if (opts.retry) {
        if (opts.retry.maxTimeout) {
            this.ldapOpts.reconnect.maxDelay = opts.retry.maxTimeout;
        }
        if (opts.retry.maxDelay) {
            this.ldapOpts.reconnect.maxDelay = opts.retry.maxDelay;
        }
        if (opts.retry.retries) {
            this.ldapOpts.reconnect.failAfter = opts.retry.retries;
        }
    }

    this.failFast = opts.failFast;
    this.hidden = opts.hidden;

    this.__defineGetter__('connected', function () {
        return self.client.connected;
    });

    this.connect();
}
util.inherits(UFDS, EventEmitter);
module.exports = UFDS;


UFDS.prototype.connect = function connect() {
    if (this.client) {
        return;
    }
    var self = this;
    var log = this.log;

    var dn = this.ldapOpts.credentials.dn;
    var passwd = this.ldapOpts.credentials.passwd;

    var client = ldap.createClient(this.ldapOpts);
    client.on('setup', function (clt, cb) {
        clt.bind(dn, passwd, function (err) {
            if (err) {
                if (err.name === 'InvalidCredentialsError') {
                    log.error({bindDN: dn, err: err},
                        'UFDS: invalid credentials; aborting');
                    client.destroy(err);
                } else {
                    log.error({bindDN: dn, err: err},
                        'UFDS: unexpected bind error');
                }
                return cb(err);
            }
            return cb(null);
        });
    });
    client.on('connect', function () {
        log.trace({
            bindDN: dn
        }, 'UFDS: connected and bound');
        if (self.failFast) {
            // Disable queue to fail fast in the case of error/disconnect
            client.queue.freeze();
        }
        self.emit('connect');
        self.emit('ready'); //backwards compatible
    });
    client.on('close', function (had_err) {
        log.info('LDAP client disconnected');
        self.emit('close', had_err);
    });
    client.on('connectError', function (err) {
        log.debug('Error connecting to UFDS', err);
    });
    client.on('idle', function () {
        if (self.failFast) {
            // The queue must be re-enabled when performing an idle disconnect.
            // This gives the client time to attempt a reconnect instead of
            // immediately failing new incoming requests.
            client.queue.thaw();
        }
        client.unbind();
        log.info('LDAP client gone idle');
    });
    this.client = client;
    LDAP_PROXY_EVENTS.forEach(function reEmit(event) {
        client.on(event, self.emit.bind(self, event));
    });
};


/**
 * Unbinds/destroys the underlying LDAP client.
 *
 * @param {Function} (Optional) callback of the form f(err).
 */
UFDS.prototype.close = function close(cb) {
    assert.optionalFunc(cb, 'callback');
    if (!cb) {
        cb = function () {};
    }

    cb = once(cb);
    var self = this;

    LDAP_PROXY_EVENTS.forEach(function reEmit(event) {
        self.client.removeAllListeners(event);
    });

    this.unbind(function (err) {
        self.client.destroy();
        if (err) {
            cb(translateError(err));
        } else {
            cb(null);
        }
    });
};


/**
 * Checks a user's password in UFDS.
 *
 * Returns a RestError of '401' if password mismatches. Returns the same user
 * object as getUser on success.
 *
 * @param {String} login one of login, uuid or the result of getUser.
 * @param {String} password correct password.
 * @param {String} (Optional) account uuid for a customer sub-user
 * @param {Function} callback of the form fn(err, user).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.authenticate = function authenticate(login, pwd, account, cb) {
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }
    if (typeof (login) !== 'object') {
        assert.string(login, 'login');
    } else {
        if (login.account) {
            account = login.account;
        }
    }
    assert.string(pwd, 'password');
    assert.func(cb, 'callback');
    if (account) {
        assert.string(account, 'account');
    }

    cb = once(cb);

    var entry;
    var cacheKey = (login.login || login) + ':' + pwd;
    var self = this;

    function _compare(user) {
        self.compare(user.dn, 'userpassword', pwd, function (err, ok) {
            if (err) {
                cb(translateError(err));
            } else if (!ok) {
                cb(new InvalidCredentialsError('The credentials ' +
                                               'provided are invalid'));
            } else {
                if (self.cache) {
                    self.cache.put(cacheKey, user);
                }

                cb(null, user);
            }
        });
    }

    if (this.cache && (entry = this.cache.get(cacheKey))) {
        cb(null, entry);
    } else if (typeof (login) === 'object') {
        _compare(login);
    } else {
        this.getUser(login, account, function (err, user) {
            if (err) {
                cb(err);
            } else {
                _compare(user);
            }
        });
    }
};


/**
 * Adds a new user into UFDS.
 *
 * This call expects the user object to look like the `sdcPerson` UFDS
 * schema, minus objectclass/dn/uuid.
 *
 * If the user includes an "account" attribute set to a UUID, the user will
 * be added as sub-user of the given account UUID, and the new user will also
 * have the objectclass `sdcAccountUser`.
 *
 * Of course, this means that if a UUID not existing into the backend is given
 * as the value for "account", `ldap.NoSuchObjectError` will become the return
 * value.
 *
 * @param {Object} user the entry to add.
 * @param {Function} callback of the form fn(err, user).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.addUser = function addUser(user, cb) {
    assert.object(user, 'user');
    assert.func(cb, 'callback');

    cb = once(cb);

    user.uuid = uuid();
    user.objectclass = 'sdcperson';

    var dn = (typeof (user.account) !== 'undefined' &&
                UUID_RE.test(user.account)) ?
                sprintf(SUBUSER_FMT, user.uuid, user.account) :
                sprintf(USER_FMT, user.uuid);

    var self = this;

    this.add(dn, user, function (add_err) {
        if (add_err) {
            cb(add_err);
        } else {
            self.getUser(user.uuid, user.account, function (err, obj) {
                if (err) {
                    cb(err);
                } else {
                    cb(null, obj);
                }
            });
        }
    });
};

/**
 * Looks up a user by the given filter to UFDS.
 *
 * @param {String} filter to use for customer search.
 * @param {String} msg error message for failures.
 * @param {String} (Optional) account uuid for a customer sub-user
 * @param {Function} callback of the form f(err, user).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype._getUser = function _getUser(filter, msg, account, cb, noCache) {
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }
    assert.func(cb, 'callback');
    assert.string(msg, 'msg');
    assert.string(filter, 'filter');
    if (account) {
        assert.string(account, 'account');
    }

    cb = once(cb);

    var opts = {
        scope: 'one',
        filter: filter
    };

    var base = (account) ? sprintf(USER_FMT, account) : USERS;
    var self = this;
    this.search(base, opts, function (err, entries) {
        if (err) {
            cb(err);
            return;
        }

        if (entries.length === 0) {
            cb(new ResourceNotFoundError(msg));
            return;
        }

        var result = entries[0];

        // Do not load them, just make roles available through the user:
        result.roles = function roles(callback) {
            var filter = sprintf(
                '(&(objectclass=sdcaccountrole)(uniquemember=%s))',
                result.dn.toString());
            return self.listRoles(account, filter, callback, noCache);
        };

        // Same for default roles:
        result.defaultRoles = function defaultRoles(callback) {
            var filter = sprintf(
                '(&(objectclass=sdcaccountrole)(uniquememberdefault=%s))',
                result.dn.toString());
            return self.listRoles(account, filter, callback, noCache);
        };


        vasync.parallel({
            funcs: [
                function loadGroups(callback) {
                    // Because of weird indexing in ufds, it's presently faster
                    // to do a pair of base-scoped searches to check group
                    // membership than to search on the objectclass for
                    // matching groups.
                    var lookup = [
                        ADMIN_GROUP,
                        READERS_GROUP
                    ];
                    var compareDN = result.dn.toString();
                    result.memberof = [];
                    vasync.forEachParallel({
                        'func': function (inputDN, subCB) {
                            opts = {
                                scope: 'base'
                            };
                            self.search(inputDN, opts, function (gErr, gRes) {
                                var field = gRes ? gRes[0].uniquemember : null;
                                if ((Array.isArray(field) &&
                                    field.indexOf(compareDN) !== -1) ||
                                    (field === compareDN)) {
                                    result.memberof.push(inputDN);
                                }
                                subCB();
                            }, noCache);
                        },
                        'inputs': lookup
                    }, callback);
                },
                function loadDisabledFlag(callback) {
                    // If this user is child to an account, load the parent to
                    // check for disabled status.
                    if (!account) {
                        // uneeded for top-level users
                        callback();
                        return;
                    }
                    opts = { scope: 'base' };
                    self.search(base, opts, function (disErr, data) {
                        if (disErr) {
                            return callback(disErr);
                        }
                        if (data.length !== 1) {
                            return callback(new Error('bad result count'));
                        }

                        // copy the disabled flag from the parent user
                        result.disabled = data[0].disabled;
                        return callback();
                    });
                },
                function loadDcLocalConfig(callback) {
                    self.listDcLocalConfig(result.uuid, result.account,
                        function (cfgErr, data) {
                        if (cfgErr) {
                            return callback(cfgErr);
                        }
                        result.dclocalconfig = data;
                        return callback();
                    });
                }
            ]
        }, function (postErr, res) {
            if (postErr) {
                return cb(postErr);
            }
            return cb(null, extendUser(self, result));
        });

    }, noCache);
};


/**
 * Looks up a user by login to UFDS.
 *
 * @param {String} login (or uuid) for a customer.
 * @param {String} (Optional) account uuid for a customer sub-user.
 * @param {Function} callback of the form f(err, user).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.getUser = function getUser(login, account, cb, noCache) {
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }
    assert.func(cb, 'callback');
    if (typeof (login) !== 'object') {
        assert.string(login, 'login');
    } else {
        cb(null, login);
        return;
    }
    if (account) {
        assert.string(account, 'account');
    }

    var filter = (account) ? sprintf(
                '(&(objectclass=sdcperson)(|(login=%s/%s)(uuid=%s)))',
                account, login, login) :
            sprintf('(&(objectclass=sdcperson)(|(login=%s)(uuid=%s)))',
                login, login);
    var msg = login + ' does not exist';
    this._getUser(filter, msg, account, cb, noCache);
};

/**
 * Looks up a user by email to UFDS.
 *
 * @param {String} email for a customer.
 * @param {String} (Optional) account uuid for a customer sub-user.
 * @param {Function} callback of the form f(err, user).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.getUserByEmail =
function getUserByEmail(email, account, cb, noCache) {
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }
    assert.func(cb, 'callback');
    if (typeof (email) !== 'object') {
        assert.string(email, 'email');
    } else {
        cb(null, email);
        return;
    }
    if (account) {
        assert.string(account, 'account');
    }

    var filter = sprintf(
            '(&(objectclass=sdcperson)(email=%s))',
            email);
    var msg = 'A user with email ' + email + ' does not exist';

    this._getUser(filter, msg, account, cb, noCache);
};


/**
 * Updates a user record.
 *
 * @param {String|Object} user  UUID or login string or a user object with
 *      a `user.dn`, `user.uuid` or `user.login` (i.e. a user object as from
 *      `getUser`).
 * @param {Object} changes  Changes to the plain object you want merged in. E.g.
 *      `{myfield: "blah"}` will add/replace the existing `myfield`. You can
 *      delete an existing field by passing in a null value, e.g.:
 *      `{addthisfield: "blah", rmthisfield: null}`.
 * @param {String} (Optional) account uuid for a customer sub-user.
 * @param {Function} callback of the form fn(err, user).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.updateUser = function updateUser(user, changes, account, cb) {
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }

    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
        if (user.account) {
            account = user.account;
        }
    }
    assert.object(changes, 'changes');
    assert.func(cb, 'callback');
    if (account) {
        assert.string(account, 'account');
    }

    cb = once(cb);

    var self = this;

    function getDn(u, _cb) {
        if (u.dn) {
            _cb(null, u.dn);
        } else {
            var login = u.uuid || u.login || u;
            self.getUser(login, account, function (err, obj) {
                if (err) {
                    _cb(err);
                } else {
                    _cb(null, obj.dn);
                }
            });
        }
    }

    // Get the user from the backend to get the `dn`, if necessary.
    getDn(user, function (err, dn) {
        if (err) {
            cb(err);
            return;
        }

        var ldapChanges = [];
        Object.keys(changes).forEach(function (k) {
            if (k === 'dn' ||
                k === 'objectclass' ||
                k === 'uuid' ||
                k === '_owner' ||
                k === '_parent' ||
                user[k] === changes[k] ||
                typeof (changes[k]) === 'function') {
                return;
            }

            var change = {modification: {}};
            if (changes[k] === null) {
                change.type = 'delete';
                change.modification[k] = [];
            } else {
                change.type = 'replace';
                change.modification[k] = changes[k];
            }
            ldapChanges.push(change);
        });

        if (!ldapChanges.length) {
            cb(null);
            return;
        }

        self.modify(dn, ldapChanges, cb);
    });
};


/**
 * Deletes a user record.
 *
 * @param {Object} user the user record you got from getUser.
 * @param {String} (Optional) account uuid for a customer sub-user.
 * @param {Function} callback of the form fn(err, user).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.deleteUser = function deleteUser(user, account, cb) {
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }
    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
        if (user.account) {
            account = user.account;
        }
    }
    assert.func(cb, 'callback');
    if (account) {
        assert.string(account, 'account');
    }

    cb = once(cb);

    var self = this;

    function _delete(err, user) {
        if (err) {
            cb(err);
        } else {
            self.del(user.dn, cb);
        }
    }

    if (typeof (user) === 'object') {
        _delete(null, user);
    } else {
        this.getUser(user, account, _delete);
    }
};


/**
 * Adds a new SSH key to a given user record.
 *
 * You can either pass in an SSH public key (string) or an object of the form
 *
 * {
 *   name: foo,
 *   openssh: public key
 * }
 *
 * This method will return you the full key as processed by UFDS. If you don't
 * pass in a name, then the name gets set to the fingerprint of the SSH key.
 *
 * @param {Object} user the user record you got from getUser.
 * @param {String} key the OpenSSH public key.
 * @param {String} (Optional) account uuid for a customer sub-user
 * @param {Function} callback of the form fn(err, key).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.addKey = function addKey(user, key, account, cb) {
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }
    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
        if (user.account) {
            account = user.account;
        }
    }
    if (typeof (key) !== 'object') {
        assert.string(key, 'key');
        key = { openssh: key };
        assert.string(key.openssh, 'key.openssh');
    }
    assert.func(cb, 'callback');
    if (account) {
        assert.string(account, 'account');
    }

    cb = once(cb);


    var self = this;

    function _addKey(init_err, user) {
        if (init_err) {
            cb(init_err);
            return;
        }

        var fingerprint;
        try {
            fingerprint = getFingerprint(key.openssh);
        } catch (e) {
            cb(new InvalidArgumentError(e.message));
            return;
        }
        var dn = (account) ?
            sprintf(SUBUSER_KEY_FMT, fingerprint, user.uuid, account) :
            sprintf(KEY_FMT, fingerprint, user.uuid);

        if (key.name) {
            key.name = key.name.trim();
        }

        key.openssh = key.openssh.trim().replace(/[\n\r]/g, '');

        var entry = {
            openssh: key.openssh,
            fingerprint: fingerprint,
            name: key.name || fingerprint,
            objectclass: 'sdckey'
        };

        // We are searching keys by fingerprint or name before allowing
        // addition of a new one with same fingerprint or name:
        self.getKey(user, entry.fingerprint, account, function (err, k) {
            if (err && err.statusCode === 404) {
                self.getKey(user, entry.name, account, function (err2, k) {
                    if (err2 && err2.statusCode === 404) {
                        self.add(dn, entry, function (err3) {
                            if (err3) {
                                cb(translateError(err3));
                            } else {
                                self.getKey(user, fingerprint, account, cb);
                            }
                        });
                    } else {
                        cb(new InvalidArgumentError(sprintf(
                            'Key with name=%s, fingerprint=%s already exists',
                            entry.name, entry.fingerprint)));
                    }
                }, true);
            } else {
                cb(new InvalidArgumentError(sprintf(
                    'Key with name %s and fingerprint %s already exists',
                    entry.name, entry.fingerprint)));
            }
        }, true);
    }

    if (typeof (user) === 'object') {
        _addKey(null, user);
    } else {
        this.getUser(user, account, _addKey);
    }
};


/**
 * Retrieves an SSH key by fingerprint.
 *
 * @param {Object} user the object you got back from getUser.
 * @param {String} fingerprint the SSH fp (or name) of the SSH key you want.
 * @param {String} (Optional) account uuid for a customer sub-user
 * @param {Function} callback of the form fn(err, key).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.getKey = function getKey(user, fp, account, cb, noCache) {
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }
    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
        if (user.account) {
            account = user.account;
        }
    }
    assert.string(fp, 'fingerprint');
    assert.func(cb, 'callback');
    if (account) {
        assert.string(account, 'account');
    }

    cb = once(cb);


    var self = this;
    function _keys(err, user) {
        if (err) {
            cb(err);
        } else {
            var filter = util.format(
                '(&(objectclass=sdckey)(|(name=%s)(fingerprint=%s)))', fp, fp);
            var opts = {
                scope: 'one',
                filter: filter
            };
            self.search(user.dn, opts, function (err, keys) {
                if (err) {
                    cb(err);
                } else {
                    if (keys.length) {
                        cb(null, keys[0]);
                    } else {
                        cb(new ResourceNotFoundError(fp + ' does not exist'));
                    }
                }
            }, noCache);
        }
    }

    if (typeof (user) === 'object') {
        _keys(null, user);
    } else {
        self.getUser(user, account, _keys);
    }
};


/**
 * Loads all keys for a given user.
 *
 * @param {Object} user the user you got from getUser.
 * @param {String} (Optional) account uuid for a customer sub-user
 * @param {Function} callback of the form fn(err, keys).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.listKeys = function listKeys(user, account, cb, noCache) {
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }
    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
        if (user.account) {
            account = user.account;
        }
    }
    assert.func(cb, 'callback');
    if (account) {
        assert.string(account, 'account');
    }

    cb = once(cb);

    var self = this;
    function _keys(err, user) {
        if (err) {
            cb(err);
        } else {
            var opts = {
                scope: 'one',
                filter: '(objectclass=sdckey)'
            };
            self.search(user.dn, opts, cb, noCache);
        }
    }

    if (typeof (user) === 'object') {
        _keys(null, user);
    } else {
        self.getUser(user, account, _keys);
    }
};


/**
 * Deletes an SSH key under a user.
 *
 * @param {User} the object you got back from getUser.
 * @param {Object} key the object you got from getKey.
 * @param {String} (Optional) account uuid for a customer sub-user
 * @param {Function} callback of the form fn(err, key).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.deleteKey = function deleteKey(user, key, account, cb) {
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }
    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
        if (user.account) {
            account = user.account;
        }
    }
    if (typeof (key) !== 'string') {
        assert.object(key, 'key');
    }
    assert.func(cb, 'callback');
    if (account) {
        assert.string(account, 'account');
    }

    cb = once(cb);

    var self = this;
    function _delKey(user, key) {
        if (!ldap.parseDN(user.dn).parentOf(key.dn)) {
            cb(new NotAuthorizedError(key.dn + ' not a child of ' + user.dn));
        } else {
            self.del(key.dn, cb);
        }
    }

    function _getKey(user) {
        if (typeof (key) === 'object') {
            _delKey(user, key);
        } else {
            self.getKey(user, key, account, function (err, key) {
                if (err) {
                    cb(err);
                } else {
                    _delKey(user, key);
                }

        });
        }

    }

    if (typeof (user) === 'object') {
        _getKey(user);
    } else {
        this.getUser(user, account, function (err, user) {
            if (err) {
                cb(err);
            } else {
                _getKey(user);
            }
        });
    }
};


/**
 * Lists "CAPI" limits for a given user.
 *
 * Note limits are the same for the main account user and all the
 * account sub-users.
 *
 * @param {Object} user the object returned from getUser.
 * @param {String} (Optional) account uuid for a customer sub-user
 * @param {Function} callback of the form fn(err, limits).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.listLimits = function listLimits(user, account, cb, noCache) {
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }
    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
        if (user.account) {
            account = user.account;
        }
    }
    assert.func(cb, 'callback');
    if (account) {
        assert.string(account, 'account');
    }
    cb = once(cb);

    var opts = {
        scope: 'one',
        filter: '(objectclass=capilimit)'
    };
    var self = this;

    function limits(err, user) {
        if (err) {
            cb(err);
        } else {
            var dn = (user.account) ? sprintf(USER_FMT, user.account) : user.dn;
            self.search(dn, opts, cb, noCache);
        }
    }

    if (typeof (user) === 'object') {
        limits(null, user);
    } else {
        self.getUser(user, account, limits);
    }
};


/**
 * Gets a "CAPI" limit for a given user.
 *
 * Note limits are the same for the main account user and all the
 * account sub-users.
 *
 * @param {Object} user the object returned from getUser.
 * @param {String} datacenter the datacenter name.
 * @param {String} (Optional) account uuid for a customer sub-user
 * @param {Function} callback of the form fn(err, limit).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.getLimit = function getLimit(user, dc, account, cb, noCache) {
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }
    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
        if (user.account) {
            account = user.account;
        }
    }
    if (typeof (dc) !== 'string') {
        assert.object(dc, 'datacenter');
        cb(null, dc);
        return;
    }
    assert.func(cb, 'callback');
    if (account) {
        assert.string(account, 'account');
    }
    cb = once(cb);

    var self = this;
    function _limits(init_err, user) {
        if (init_err) {
            cb(init_err);
            return;
        }

        self.listLimits(user, account, function (err, limits) {
            if (err) {
                cb(err);
                return;
            }

            var limit;
            if (!limits.some(function (l) {
                if (l.datacenter === dc) {
                    limit = l;
                }
                return (limit ? true : false);
            })) {
                cb(new ResourceNotFoundError(sprintf('No limit found for %s/%s',
                                                     user.login, dc)));
            } else {
                cb(null, limit);
            }
        }, noCache);
    }

    if (typeof (user) === 'object') {
        _limits(null, user);
    } else {
        this.getUser(user, account, _limits);
    }
};


/**
 * Creates a "CAPI" limit for a given user.
 *
 * @param {Object} user the object returned from getUser.
 * @param {Object} limit the limit to add.
 * @param {Function} callback of the form fn(err, limit).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.addLimit = function addLimit(user, limit, cb) {
    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
    }
    assert.object(limit, 'limit');
    assert.string(limit.datacenter, 'limit.datacenter');
    assert.func(cb, 'callback');

    cb = once(cb);

    var self = this;
    function _add(get_err, user) {
        if (get_err) {
            cb(get_err);
            return;
        }

        var dn = sprintf(LIMIT_FMT, limit.datacenter, user.uuid);
        var entry = clone(limit);
        entry.objectclass = 'capilimit';

        self.add(dn, entry, function (err) {
            if (err) {
                cb(translateError(err));
            } else {
                self.getLimit(user, limit.datacenter, cb);
            }
        });
    }

    if (typeof (user) === 'object') {
        _add(null, user);
    } else {
        this.getUser(user, _add);
    }
};


/**
 * Updates a "CAPI" limit for a given user.
 *
 * @param {Object} user the object returned from getUser.
 * @param {Object} limit the limit to add.
 * @param {Function} callback of the form fn(err, limit).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.updateLimit = function updateLimit(user, limit, cb) {
    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
    }
    assert.object(limit, 'limit');
    assert.string(limit.datacenter, 'limit.datacenter');
    assert.func(cb, 'callback');

    cb = once(cb);

    var self = this;
    function _mod(user, existingLimits) {
        var dn = sprintf(LIMIT_FMT, limit.datacenter, user.uuid);
        var changes = [];
        Object.keys(existingLimits).forEach(function (k) {
            if (k === 'dn' ||
                k === 'objectclass' ||
                k === '_owner' ||
                k === '_parent' ||
                typeof (limit[k]) === 'function' ||
                limit[k] === existingLimits[k]) {
                return;
            }

            if (existingLimits[k] && !limit[k]) {
                var change = {
                    type: 'delete',
                    modification: {}
                };
                change.modification[k] = [];
                changes.push(change);
            }
        });

        Object.keys(limit).forEach(function (k) {
            if (k === 'dn' ||
                k === 'objectclass' ||
                k === '_owner' ||
                k === '_parent' ||
                typeof (limit[k]) === 'function' ||
                limit[k] === existingLimits[k]) {
                return;
            }

            var change = {
                type: 'replace',
                modification: {}
            };
            if (existingLimits[k] && !limit[k]) {
                change.type = 'delete';
                change.modification[k] = [];
            } else {
                change.modification[k] = limit[k];
            }
            changes.push(change);
        });

        if (!changes.length) {
            cb(null);
            return;
        }

        self.modify(dn, changes, cb);
    }

    function _limit(get_err, user) {
        if (get_err) {
            cb(get_err);
        } else {
            self.getLimit(user, limit.datacenter, function (err, l) {
                if (err) {
                    cb(err);
                } else {
                    _mod(user, l);
                }
            });
        }
    }

    if (typeof (user) === 'object') {
        _limit(null, user);
    } else {
        this.getUser(user, _limit);
    }
};


/**
 * Deletes a "CAPI" limit for a given user.
 *
 * Note that this deletes _all_ limits for a datacenter, so if you just want
 * to purge one, you probably want to use updateLimit.
 *
 * @param {Object} user the object returned from getUser.
 * @param {Object} limit the limit to delete.
 * @param {Function} callback of the form fn(err).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.deleteLimit = function deleteLimit(user, limit, cb) {
    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
    }
    assert.object(limit, 'limit');
    assert.string(limit.datacenter, 'limit.datacenter');
    assert.func(cb, 'callback');

    cb = once(cb);

    var self = this;
    function _del(err, user) {
        if (err) {
            cb(err);
        } else {
            self.del(sprintf(LIMIT_FMT, limit.datacenter, user.uuid), cb);
        }
    }

    if (typeof (user) === 'object') {
        _del(null, user);
    } else {
        this.getUser(user, _del);
    }
};


/**
 * Lists foreign dcs by authorized dev.
 *
 * @param {Object} user the object you got back from getUser.
 * @param {String} authdev the authorized developer key
 * @param {Function} callback of the form fn(err, key)
 * @throws {TypeError} on bad input
 */

UFDS.prototype.listForeigndc = function listForeigndc(user, authdev, cb) {
    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
    }
    assert.string(authdev, 'authdev');
    assert.func(cb, 'callback');

    cb = once(cb);

    var self = this;

    function _fdc(err, user) {
        if (err) {
            cb(err);
        } else {
            var dn = sprintf(AUTHDEV_FMT, authdev, user.uuid);
            var opts = {
                scope: 'one',
                filter: '(objectclass=foreigndc)'
            };
            self.search(dn, opts, cb);
        }
    }

    if (typeof (user) === 'object') {
        _fdc(null, user);
    } else {
        this.getUser(user, _fdc);
    }
};

/**
 * Gets the dclocalconfig child object of a given user or subuser; this is a
 * non-replicated object intended to hold dc-specific settings.
 *
 * Compared to getDcLocalConfig, this function requires only the uuids of the
 * user to find the dclocalconfig object.
 *
 * @param {String} user - user uuid.
 * @param {String} account - (Optional) main account uuid for subusers.
 * @param {Function} cb standard callback.
 */
UFDS.prototype.listDcLocalConfig =
function listDcLocalConfig(uuid, account, cb) {
    var base;
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }

    if (!account) {
        base = sprintf(USER_FMT, uuid);
    } else {
        base = sprintf(SUBUSER_FMT, uuid, account);
    }
    cb = once(cb);

    var opts = {
        scope: 'one',
        filter: '(objectclass=dclocalconfig)'
    };
    this.search(base, opts, function (err, data) {
        if (err) {
            return cb(err);
        }

        switch (data.length) {
        case 0:
            return cb(null);
        case 1:
            return cb(null, data[0]);
        default:
            var _err = new Error(util.format('Multiple results for %s ' +
                ' dclocalconfig child objects. UFDS may be misconfigured',
                account));
            this.log.error({ err: _err, results: data },
                'Multiple dclocalconfig results');
            return cb(_err);
        }
    });
};

/**
 * Gets the dclocalconfig child object of a given [sub]user; this is a
 * non-replicated object intended to hold dc-specific settings.
 *
 * Compared to listDcLocalConfig, this function specifies the datacenter,
 * allowing the search call to use the fully specified dn.
 *
 * @param {String} uuid - string uuid of user.
 * @param {String} account - (Optional) main account uuid for subusers.
 * @param {Function} cb standard callback.
 */
UFDS.prototype.getDcLocalConfig =
function getDcLocalConfig(uuid, account, datacenter, cb) {
    var dn;
    if (typeof (datacenter) === 'function') {
        cb = datacenter;
        datacenter = account;
        account = null;
    }

    if (!account) {
        dn = sprintf(DCLC_USER_FMT, datacenter, uuid);
    } else {
        dn = sprintf(DCLC_SUBUSER_FMT, datacenter, account, uuid);
    }
    cb = once(cb);

    var opts = {
        scope: 'base'
    };
    this.search(dn, opts, function (err, data) {
        var cfg = {};
        if (err) {
            return cb(err);
        }
        if (data.length > 0) {
            cfg = data[0];
        }
        return cb(null, cfg);
    });
};

/**
 * adds a dclocalconfig object as a child of a given user; this is a
 * non-replicated object intended to hold dc-specific settings.
 *
 * @param {String} uuid - uuid of user.
 * @param {String} account - (Optional) main account uuid for subusers.
 * @param {String} datacenter - datacenter for dn (must be local dc)
 * @param {Object} config - object to add. 'datacenter' property is required.
 * @param {Function} cb - standard callback.
 */
UFDS.prototype.addDcLocalConfig =
function addDcLocalConfig(uuid, account, datacenter, config, cb) {
    var self = this;
    var dn;

    if (typeof (config) === 'function') {
        cb = config;
        config = datacenter;
        datacenter = account;
        account = null;
    }

    if (!account) {
        dn = sprintf(DCLC_USER_FMT, datacenter, uuid);
    } else {
        dn = sprintf(DCLC_SUBUSER_FMT, datacenter, account, uuid);
    }

    config.objectclass = 'dclocalconfig';

    cb = once(cb);
    self.add(dn, config, function (err) {
        if (err) {
            cb(translateError(err));
        } else {
            self.getDcLocalConfig(uuid, account, datacenter, cb);
        }
    });
};

/**
 * Updates a dclocalconfig object as a child of a given user; this is a
 * non-replicated object intended to hold dc-specific settings.
 *
 * @param {String} uuid - uuid string.
 * @param {String} account - (Optional) main account uuid for subusers.
 * @param {Object} config object to add. 'datacenter' property is required.
 * @param {Function} cb standard callback.
 */
UFDS.prototype.updateDcLocalConfig =
function updateDcLocalConfig(uuid, account, datacenter, update, cb) {
    var self = this;
    var dn;

    if (typeof (update) === 'function') {
        cb = update;
        update = datacenter;
        datacenter = account;
        account = null;
    }

    if (!account) {
        dn = sprintf(DCLC_USER_FMT, datacenter, uuid);
    } else {
        dn = sprintf(DCLC_SUBUSER_FMT, datacenter, account, uuid);
    }
    cb = once(cb);

    self.getDcLocalConfig(uuid, account, datacenter, function (err) {
        if (err && err.statusCode === 404) {
            self.addDcLocalConfig(uuid, account, datacenter, update,
                function (err2, user) {
                if (err2) {
                    return cb(translateError(err2));
                }
                return cb(null, user);
            });
        } else if (err) {
            cb(translateError(err));
        } else {
            var ldapChanges = Object.keys(update).reduce(function (acc, key) {
                if (key === 'dn' ||
                    key === 'objectclass' ||
                    key === '_owner' ||
                    key === '_parent' ||
                    typeof (update[key]) === 'function') {
                    return acc;
                }
                var change = { modification : {} };
                if (update[key] === null) {
                    change.type = 'delete';
                    change.modification[key] = [];
                    acc.push(change);
                } else if (update[key]) {
                    change.type = 'replace';
                    change.modification[key] = update[key];
                    acc.push(change);
                }
                return acc;
            }, []);


            if (!ldapChanges.length) {
                cb(null);
            } else {
                self.modify(dn, ldapChanges, function (err3) {
                    if (err3) {
                        cb(translateError(err3));
                    } else {
                        self.getDcLocalConfig(uuid, account, datacenter, cb);
                    }
                });
            }
        }
    });
};

/**
 * deletes the dclocalconfig child object of a given user.
 *
 * @param {String} uuid - uuid string.
 * @param {String} account - (Optional) main account uuid for subusers.
 * @param {Function} cb standard callback.
 */
UFDS.prototype.deleteDcLocalConfig =
function deleteDcLocalConfig(uuid, account, datacenter, cb) {
    var dn;

    if (typeof (datacenter) === 'function') {
        cb = datacenter;
        datacenter = account;
        account = null;
    }

    if (!account) {
        dn = sprintf(DCLC_USER_FMT, datacenter, uuid);
    } else {
        dn = sprintf(DCLC_SUBUSER_FMT, datacenter, account, uuid);
    }
    cb = once(cb);

    this.del(dn, cb);
};

/**
 * inserts a foreign dc by authorized dev & key.
 *
 * @param {Object} user the object you got back from getUser.
 * @param {String} authdev the authorized developer key
 * @param {Object} dc the foreign datacenter. Must have a unique name,
 *                 and at least url & token
 * @param {Function} callback of the form fn(err, key)
 * @throws {TypeError} on bad input
 */

UFDS.prototype.addForeigndc = function addForeigndc(user, authdev, dc, cb) {

    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
    }
    assert.string(authdev, 'authdev');
    assert.func(cb, 'callback');
    assert.object(dc, 'dc');
    assert.string(dc.name, 'dc.name');
    assert.string(dc.url, 'dc.url');
    assert.string(dc.token, 'dc.token');

    cb = once(cb);

    var self = this;


    function _addfdc(err, user) {
        if (err) {
            cb(err);
        } else {
            var opts = {
                scope: 'one',
                filter: sprintf('(&(objectclass=authdev)(authdev=%s))',
                        authdev)
            };

            self.search(user.dn, opts, function (err, devlist) {
                if (err) {
                    cb(err);
                    return;
                }

                if (devlist.length !== 0) {
                    var dcdn = sprintf(AUTHDEV_FMT, authdev, user.uuid);
                    var dcopts = {
                        scope: 'one',
                        filter: sprintf(
                            '(&(objectclass=foreigndc)(foreigndc=%s))',
                            dc.name)
                    };

                    self.search(dcdn, dcopts, function (err2, dclist) {
                        if (err2) {
                            cb(err2);
                            return;
                        }

                        if (dclist.length !== 0) {
                            // The dc already exists,
                            // so we're replacing the token and/or url
                            var changes = [
                                {
                                    type: 'replace',
                                    modification: { 'url' : dc.url }
                                },
                                {
                                    type: 'replace',
                                    modification: { 'token' : dc.token }
                                }
                            ];
                            var moddn = sprintf(FOREIGNDC_FMT, dc.name,
                                authdev, user.uuid);
                            self.modify(moddn, changes, cb);
                        } else {
                            var insertdn = sprintf(FOREIGNDC_FMT, dc.name,
                                    authdev, user.uuid);
                            var obj = {
                                foreigndc: dc.name,
                                url: dc.url,
                                token: dc.token,
                                objectclass: 'foreigndc'
                            };
                            self.add(insertdn, obj, cb);
                        }
                    });
                } else  { // insert the dev first
                    var insertdevdn = sprintf(AUTHDEV_FMT, authdev, user.uuid);
                    var devobj = { authdev: authdev, objectclass: 'authdev' };
                    self.add(insertdevdn, devobj, function (err2, deventry) {
                        if (err2) {
                            cb(err2);
                            return;
                        }
                        var insertdn = sprintf(FOREIGNDC_FMT, dc.name, authdev,
                                               user.uuid);
                        var obj = {
                            foreigndc: dc.name,
                            url: dc.url,
                            token: dc.token,
                            objectclass: 'foreigndc'
                        };
                        self.add(insertdn, obj, cb);
                    });
                }
            });
        }
    }

    if (typeof (user) === 'object') {
        _addfdc(null, user);
    } else {
        this.getUser(user, _addfdc);
    }
};


/**
 * Retrieves metadata by key.
 *
 * @param {Object} user the object you got back from getUser.
 * @param {String} appkey the metadata key.
 * @param {String} (Optional) account uuid for a customer sub-user
 * @param {Function} callback of the form fn(err, metadata).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.getMetadata =
function getMetadata(user, key, account, cb, noCache) {
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }
    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
        if (user.account) {
            account = user.account;
        }
    }
    assert.string(key, 'key');
    assert.func(cb, 'callback');
    if (account) {
        assert.string(account, 'account');
    }

    cb = once(cb);

    var self = this;

    function _getMetadata(user) {
        assert.object(user, 'user');
        assert.string(user.uuid, 'user.uuid');

        var dn = (account) ?
            sprintf(SUBUSER_METADATA_FORMAT, key, user.uuid, account) :
            sprintf(METADATA_FMT, key, user.uuid);

        var opts = {
            scope: 'base',
            filter: '(objectclass=capimetadata)'
        };
        self.search(dn, opts, function (err, md) {
            if (err) {
                cb(err);
            } else {
                cb(null, md ? md[0] : null);
            }
        }, noCache);
    }

    if (typeof (user) === 'object') {
        _getMetadata(user);
    } else {
        this.getUser(user, account, function (err, user) {
            if (err) {
                cb(err);
            } else {
                _getMetadata(user);
            }
        });
    }
};


/**
 * Adds new metadata to a given user record.
 *
 * takes a CAPI metadata key and an object of arbitrary fields (not nested)
 *
 * This method will return you the full metadata as processed by UFDS.
 *
 * @param {Object} user the user record you got from getUser.
 * @param {String} key the CAPI metadata key (application key)
 * @param {Object} metadata the CAPI metadata to be inserted
 * @param {String} (Optional) account uuid for a customer sub-user
 * @param {Function} callback of the form fn(err, metadata).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.addMetadata =
function addMetadata(user, key, metadata, account, cb) {
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }
    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
        if (user.account) {
            account = user.account;
        }
    }
    assert.string(key, 'key');
    assert.object(metadata, 'metadata');
    assert.func(cb, 'callback');
    if (account) {
        assert.string(account, 'account');
    }

    cb = once(cb);

    var self = this;

    function _addMetadata(user) {
        assert.object(user, 'user');
        assert.string(user.uuid, 'user.uuid');

        var dn = (account) ?
            sprintf(SUBUSER_METADATA_FORMAT, key, user.uuid, account) :
            sprintf(METADATA_FMT, key, user.uuid);

        metadata.objectclass = 'capimetadata';
        if (!metadata.cn) {
            metadata.cn = key;
        }

        // We are searching keys by fingerprint or name before allowing
        // addition of a new one with same fingerprint or name:
        self.getMetadata(user, key, account, function (err, k) {
            if (err && err.statusCode === 404) {
                self.add(dn, metadata, function (err2) {
                    if (err2) {
                        cb(translateError(err2));
                    } else {
                        self.getMetadata(user, key, account, cb);
                    }
                });
            } else {
                cb(new InvalidArgumentError(sprintf('Metadata with key %s ' +
                                                    'already exists', key)));
            }
        }, true);
    }

    if (typeof (user) === 'object') {
        _addMetadata(user);
    } else {
        this.getUser(user, account, function (err, user) {
            if (err) {
                cb(err);
            } else {
                _addMetadata(user);
            }
        });
    }
};


/**
 * modifies metadata entries to a given user record's metadata.
 *
 * takes a CAPI metadata key and an object of arbitrary fields (not nested)
 *
 *
 * This method will return you the full metadata as processed by UFDS.
 *
 * @param {Object} user the user record you got from getUser.
 * @param {String} key the CAPI metadata key (application key)
 * @param {Object} metadata the CAPI metadata to be inserted
 * @param {String} (Optional) account uuid for a customer sub-user*
 * @param {Function} callback of the form fn(err, metadata).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.modifyMetadata =
function modifyMetadata(user, key, md, account, cb) {
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }
    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
        if (user.account) {
            account = user.account;
        }
    }
    assert.string(key, 'key');
    assert.object(md, 'metadata');
    assert.func(cb, 'callback');
    if (account) {
        assert.string(account, 'account');
    }

    cb = once(cb);

    var self = this;

    function _modMetadata(user) {
        assert.object(user, 'user');
        assert.string(user.uuid, 'user.uuid');

        var dn = (account) ?
            sprintf(SUBUSER_METADATA_FORMAT, key, user.uuid, account) :
            sprintf(METADATA_FMT, key, user.uuid);
        md.objectclass = 'capimetadata';

        self.getMetadata(user, key, account, function (err) {
            if (err && err.statusCode === 404) {
                self.add(dn, md, function (err2) {
                    if (err2) {
                        cb(translateError(err2));
                    } else {
                        self.getMetadata(user, key, account, cb);
                    }
                });
            } else {
                var ldapChanges = [];
                Object.keys(md).forEach(function (k) {
                    if (k === 'dn' ||
                        k === 'objectclass' ||
                        k === '_owner' ||
                        k === '_parent' ||
                        typeof (md[k]) === 'function') {
                        return;
                    }

                    var change = {
                        modification: {}
                    };
                    if (md[k] === null) {
                        change.type = 'delete';
                        change.modification[k] = [];
                    } else {
                        change.type = 'replace';
                        change.modification[k] = md[k];
                    }

                    ldapChanges.push(change);
                });

                if (!ldapChanges.length) {
                    cb(null);
                } else {
                    self.modify(dn, ldapChanges, cb);
                }
            }
      }, true);
    }

    if (typeof (user) === 'object') {
        _modMetadata(user);
    } else {
        this.getUser(user, account, function (err, user) {
            if (err) {
                cb(err);
            } else {
                _modMetadata(user);
            }
        });
    }
};


/**
 * Deletes Metadata key under a user.
 *
 * @param {User} the object you got back from getUser.
 * @param {String} key the CAPI metadata key (application key)
 * @param {String} (Optional) account uuid for a customer sub-user
 * @param {Function} callback of the form fn(err, md).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.deleteMetadata =
function deleteMetadata(user, key, account, cb) {
    if (typeof (account) === 'function') {
        cb = account;
        account = null;
    }
    if (typeof (user) !== 'string') {
        assert.object(user, 'user');
        if (user.account) {
            account = user.account;
        }
    }
    assert.string(key, 'key');
    assert.func(cb, 'callback');
    if (account) {
        assert.string(account, 'account');
    }

    cb = once(cb);

    var self = this;
    function _delMeta(user, key) {
        if (!ldap.parseDN(user.dn).parentOf(key.dn)) {
            cb(new NotAuthorizedError(key.dn + ' not a child of ' + user.dn));
        } else {
            self.del(key.dn, cb);
        }
    }

    function _getMeta(user) {
        self.getMetadata(user, key, account, function (err, key) {
            if (err) {
                cb(err);
            } else {
                _delMeta(user, key);
            }
        }, true);
    }

    if (typeof (user) === 'object') {
        _getMeta(user);
    } else {
        this.getUser(user, account, function (err, user) {
            if (err) {
                cb(err);
            } else {
                _getMeta(user);
            }
        });
    }
};


/**
 * Lists access policies for a given account.
 *
 * @param {String} account string the uuid of main account user.
 * @param {Function} callback of the form fn(err, policies).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.listPolicies = function listPolicies(account, cb, noCache) {
    assert.string(account, 'account');
    assert.func(cb, 'callback');

    cb = once(cb);

    var opts = {
        scope: 'one',
        filter: '(objectclass=sdcaccountpolicy)'
    };

    var dn = sprintf(USER_FMT, account);
    this.search(dn, opts, function (err, policies) {
        if (err) {
            cb(err);
        } else {
            cb(null, policies);
        }
    }, noCache);
};


/**
 * Creates a policy for a given account
 *
 * @param {String} account string the uuid of main account user.
 * @param {Object} policy the policy to add.
 * @param {Function} callback of the form fn(err, policy).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.addPolicy = function addPolicy(account, policy, cb) {
    assert.string(account, 'account');
    assert.object(policy, 'policy');
    assert.string(policy.name, 'policy.name');
    assert.func(cb, 'callback');

    if (!policy.uuid) {
        policy.uuid = uuid();
    }

    cb = once(cb);

    var self = this;

    var dn = sprintf(POLICY_FMT, policy.uuid, account);
    var entry = clone(policy);
    entry.objectclass = 'sdcaccountpolicy';

    this.add(dn, entry, function (err) {
        if (err) {
            cb(translateError(err));
        } else {
            self.getPolicy(account, policy.uuid, cb);
        }
    });
};



/**
 * Gets a policy for the given account
 *
 * @param {String} account string the uuid of main account user.
 * @param {String} policy the UUID or name of the policy to retrieve.
 * @param {Function} callback of the form fn(err, policy).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.getPolicy = function getPolicy(account, policy, cb, noCache) {
    assert.string(account, 'account');
    assert.string(policy, 'policy');
    assert.func(cb, 'callback');

    cb = once(cb);
    var dn = sprintf(USER_FMT, account);
    var opts = {
        scope: 'one',
        filter: sprintf(
                '(&(objectclass=sdcaccountpolicy)(|(uuid=%s)(name=%s)))',
                policy, policy)
    };

    this.search(dn, opts, function (err, policies) {
        if (err) {
            cb(err);
        } else {
            if (!policies.length) {
                cb(new ResourceNotFoundError(policy + ' does not exist'));
                return;
            }
            var r = policies[0];
            cb(null, r);
        }
    }, noCache);
};


/**
 * modifies a given account policy.
 *
 * @param {String} account string the uuid of main account user.
 * @param {String} policy the UUID of the policy to modify.
 * @param {Object} changes the modifications to be inserted
 * @param {Function} callback of the form fn(err, policy).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.modifyPolicy =
function modifyPolicy(account, policy, changes, cb) {
    assert.string(policy, 'policy');
    assert.string(account, 'account');
    assert.object(changes, 'changes');
    assert.func(cb, 'callback');

    cb = once(cb);
    var self = this;
    var dn = sprintf(POLICY_FMT, policy, account);
    var entry = clone(changes);
    entry.objectclass = 'sdcaccountpolicy';

    this.getPolicy(account, policy, function (err) {
        if (err && err.statusCode === 404) {
            self.add(dn, entry, function (err2) {
                if (err2) {
                    cb(translateError(err2));
                } else {
                    self.getPolicy(account, policy, cb);
                }
            });
        } else {
            var ldapChanges = [];
            Object.keys(changes).forEach(function (k) {
                if (k === 'dn' ||
                    k === 'objectclass' ||
                    k === 'uuid' ||
                    k === '_owner' ||
                    k === '_parent' ||
                    typeof (changes[k]) === 'function') {
                    return;
                }

                var change = {
                    modification: {}
                };
                if (changes[k] === null) {
                    change.type = 'delete';
                    change.modification[k] = [];
                    ldapChanges.push(change);
                } else if (changes[k]) {
                    change.type = 'replace';
                    change.modification[k] = changes[k];
                    ldapChanges.push(change);
                }
            });

            if (!ldapChanges.length) {
                cb(null);
            } else {
                self.modify(dn, ldapChanges, function (err3) {
                    if (err3) {
                        cb(translateError(err3));
                    } else {
                        self.getPolicy(account, policy, cb);
                    }
                });
            }
        }
    }, true);
};


/**
 * Deletes a policy for the given account.
 *
 * @param {String} account string the uuid of main account user.
 * @param {String} policy the UUID of the policy to retrieve.
 * @param {Function} callback of the form fn(err).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.deletePolicy = function deletePolicy(account, policy, cb) {
    assert.string(account, 'account');
    assert.string(policy, 'policy');
    assert.func(cb, 'callback');

    cb = once(cb);

    this.del(sprintf(POLICY_FMT, policy, account), cb);
};


/**
 * Lists roles for a given account.
 *
 * @param {String} account string the uuid of main account user.
 * @param {String} filter string optional filter for roles search.
 * @param {Function} callback of the form fn(err, roles).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.listRoles = function listRoles(account, filter, cb, noCache) {
    assert.string(account, 'account');
    if (typeof (filter) === 'function') {
        noCache = cb;
        cb = filter;
        filter = '(objectclass=sdcaccountrole)';
    }
    assert.func(cb, 'callback');

    cb = once(cb);
    var opts = {
        scope: 'one',
        filter: filter
    };
    var dn = sprintf(USER_FMT, account);

    this.search(dn, opts, cb, noCache);
};


/**
 * Creates a role for a given account
 *
 * @param {String} account string the uuid of main account user.
 * @param {Object} role the role to add.
 * @param {Function} callback of the form fn(err, role).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.addRole = function addRole(account, role, cb) {
    assert.string(account, 'account');
    assert.object(role, 'role');
    assert.string(role.name, 'role.name');
    assert.func(cb, 'callback');

    if (!role.uuid) {
        role.uuid = uuid();
    }

    cb = once(cb);
    var self = this;
    var dn = sprintf(ROLE_FMT, role.uuid, account);
    var entry = clone(role);
    entry.objectclass = 'sdcaccountrole';

    this.add(dn, entry, function (err) {
        if (err) {
            cb(translateError(err));
        } else {
            self.getRole(account, role.uuid, cb);
        }
    });
};



/**
 * Gets a role for the given account
 *
 * @param {String} account string the uuid of main account user.
 * @param {String} role the UUID or name of the role to retrieve.
 * @param {Function} callback of the form fn(err, role).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.getRole = function getRole(account, role, cb, noCache) {
    assert.string(account, 'account');
    assert.string(role, 'role');
    assert.func(cb, 'callback');

    cb = once(cb);
    var dn = sprintf(USER_FMT, account);
    var opts = {
        scope: 'one',
        filter: sprintf('(&(objectclass=sdcaccountrole)(|(uuid=%s)(name=%s)))',
                role, role)
    };

    this.search(dn, opts, function (err, roles) {
        if (err) {
            cb(err);
        } else {
            if (!roles.length) {
                cb(new ResourceNotFoundError(role + ' does not exist'));
                return;
            }
            cb(null, roles[0]);
        }
    }, noCache);
};


/**
 * modifies a given account role.
 *
 * @param {String} account string the uuid of main account user.
 * @param {String} role the UUID or name of the role to modify.
 * @param {Object} changes the modifications to be inserted
 * @param {Function} callback of the form fn(err, role).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.modifyRole =
function modifyRole(account, role, changes, cb) {
    assert.string(role, 'role');
    assert.string(account, 'account');
    assert.object(changes, 'changes');
    assert.func(cb, 'callback');

    cb = once(cb);

    var self = this;

    var dn = sprintf(ROLE_FMT, role, account);
    var entry = clone(changes);
    entry.objectclass = 'sdcaccountrole';

    self.getRole(account, role, function (err) {
        if (err && err.statusCode === 404) {
            self.add(dn, entry, function (err2) {
                if (err2) {
                    cb(translateError(err2));
                } else {
                    self.getRole(account, role, cb);
                }
            });
        } else {
            var ldapChanges = [];
            Object.keys(changes).forEach(function (k) {
                if (k === 'dn' ||
                    k === 'objectclass' ||
                    k === 'uuid' ||
                    k === '_owner' ||
                    k === '_parent' ||
                    typeof (changes[k]) === 'function') {
                    return;
                }

                var change = {
                    modification: {}
                };
                if (changes[k] === null) {
                    change.type = 'delete';
                    change.modification[k] = [];
                    ldapChanges.push(change);
                } else if (changes[k]) {
                    change.type = 'replace';
                    change.modification[k] = changes[k];
                    ldapChanges.push(change);
                }
            });

            if (!ldapChanges.length) {
                cb(null);
            } else {
                self.modify(dn, ldapChanges, function (err3) {
                    if (err3) {
                        cb(translateError(err3));
                    } else {
                        self.getRole(account, role, cb);
                    }
                });
            }
        }
    }, true);
};


/**
 * Deletes a role for the given account.
 *
 * @param {String} account string the uuid of main account user.
 * @param {String} role the UUID of the role to delete.
 * @param {Function} callback of the form fn(err).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.deleteRole = function deleteRole(account, role, cb) {
    assert.string(account, 'account');
    assert.string(role, 'role');
    assert.func(cb, 'callback');

    cb = once(cb);
    this.del(sprintf(ROLE_FMT, role, account), cb);
};


/**
 * Lists virtual resources for a given account.
 *
 * @param {String} account string the uuid of main account user.
 * @param {Function} callback of the form fn(err, resources).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.listResources = function listResources(account, cb, noCache) {
    assert.string(account, 'account');
    assert.func(cb, 'callback');

    cb = once(cb);
    var opts = {
        scope: 'one',
        filter: '(objectclass=sdcaccountresource)'
    };
    var dn = sprintf(USER_FMT, account);

    this.search(dn, opts, cb, noCache);
};


/**
 * Creates a virtual resource for a given account
 *
 * @param {String} account string the uuid of main account user.
 * @param {Object} resource the virtual resource to add.
 * @param {Function} callback of the form fn(err, resource).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.addResource = function addResource(account, resource, cb) {
    assert.string(account, 'account');
    assert.object(resource, 'resource');
    assert.string(resource.name, 'resource.name');
    assert.func(cb, 'callback');

    if (!resource.uuid) {
        resource.uuid = uuid();
    }

    cb = once(cb);
    var self = this;
    var dn = sprintf(RESOURCE_FMT, resource.uuid, account);
    var entry = clone(resource);
    entry.objectclass = 'sdcaccountresource';

    this.add(dn, entry, function (err) {
        if (err) {
            cb(translateError(err));
        } else {
            self.getResource(account, resource.uuid, cb);
        }
    });
};



/**
 * Gets a virtual resource for the given account
 *
 * @param {String} account string the uuid of main account user.
 * @param {String} respource the UUID  or path of the resource to retrieve.
 * @param {Function} callback of the form fn(err, resource).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.getResource =
function getResource(account, resource, cb, noCache) {
    assert.string(account, 'account');
    assert.string(resource, 'policy');
    assert.func(cb, 'callback');

    cb = once(cb);

    var dn = sprintf(USER_FMT, account);
    var opts = {
        scope: 'one',
        filter: sprintf(
                '(&(objectclass=sdcaccountresource)(|(uuid=%s)(name=%s)))',
                resource, resource)
    };

    this.search(dn, opts, function (err, resources) {
        if (err) {
            cb(err);
        } else {
            if (!resources.length) {
                cb(new ResourceNotFoundError(resource + ' does not exist'));
                return;
            }
            var r = resources[0];
            cb(null, r);
        }
    }, noCache);
};


/**
 * modifies a given account virtual resource.
 *
 * @param {String} account string the uuid of main account user.
 * @param {String} resource the UUID of the resource to modify.
 * @param {Object} changes the modifications to be inserted
 * @param {Function} callback of the form fn(err, resource).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.modifyResource =
function modifyResource(account, resource, changes, cb) {
    assert.string(resource, 'policy');
    assert.string(account, 'account');
    assert.object(changes, 'changes');
    assert.func(cb, 'callback');

    cb = once(cb);
    var self = this;
    var dn = sprintf(RESOURCE_FMT, resource, account);
    var entry = clone(changes);
    entry.objectclass = 'sdcaccountresource';

    this.getResource(account, resource, function (err) {
        if (err && err.statusCode === 404) {
            self.add(dn, entry, function (err2) {
                if (err2) {
                    cb(translateError(err2));
                } else {
                    self.getResource(account, resource, cb);
                }
            });
        } else {
            var ldapChanges = [];
            Object.keys(changes).forEach(function (k) {
                if (k === 'dn' ||
                    k === 'objectclass' ||
                    k === 'uuid' ||
                    k === '_owner' ||
                    k === '_parent' ||
                    typeof (changes[k]) === 'function') {
                    return;
                }

                var change = {
                    modification: {}
                };
                if (changes[k] === null) {
                    change.type = 'delete';
                    change.modification[k] = [];
                } else {
                    change.type = 'replace';
                    change.modification[k] = changes[k];
                }

                ldapChanges.push(change);
            });

            if (!ldapChanges.length) {
                cb(null);
            } else {
                self.modify(dn, ldapChanges, function (err3) {
                    if (err3) {
                        cb(translateError(err3));
                    } else {
                        self.getResource(account, resource, cb);
                    }
                });
            }
        }
    }, true);
};


/**
 * Deletes a resource for the given account.
 *
 * @param {String} account string the uuid of main account user.
 * @param {String} resource the UUID of the resource to retrieve.
 * @param {Function} callback of the form fn(err).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.deleteResource = function deleteResource(account, resource, cb) {
    assert.string(account, 'account');
    assert.string(resource, 'resource');
    assert.func(cb, 'callback');

    cb = once(cb);

    this.del(sprintf(RESOURCE_FMT, resource, account), cb);
};


/**
 * Lists all datacenters for a region.
 *
 * @param {String} the region name
 * @param {Function} callback of the form fn(err, resolvers).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.listDatacenters = function listDatacenters(region, cb, noCache) {
    assert.string(region, 'region');
    assert.func(cb, 'cb');

    cb = once(cb);
    var dn = sprintf(REGION, region);
    var opts = {
        scope: 'sub',
        filter: '(objectclass=datacenter)'
    };

    this.search(dn, opts, cb, noCache);
};


/**
 * Lists all resolvers for a region.
 *
 * @param {String} the region name
 * @param {Function} callback of the form fn(err, resolvers).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.listResolvers = function listResolvers(region, cb, noCache) {
    assert.string(region, 'region');
    assert.func(cb, 'cb');

    cb = once(cb);
    var dn = sprintf(REGION, region);
    var opts = {
        scope: 'sub',
        filter: '(objectclass=resolver)'
    };

    this.search(dn, opts, cb, noCache);
};


/**
 * Low-level API to wrap up UFDS add operations.
 *
 * See ldapjs docs.
 *
 * @param {String} dn of the record to add.
 * @param {Object} entry record attributes.
 * @param {Function} callback of the form fn(error, entries).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.add = function add(dn, entry, cb) {
    assert.string(dn, 'dn');
    assert.object(entry, 'entry');
    assert.func(cb, 'callback');

    cb = once(cb);
    var self = this;

    this.client.add(dn, entry, function (err) {
        if (err) {
            cb(translateError(err));
        } else {
            self._newCache();
            cb(null);
        }
    });
};


/**
 * Low-level API to wrap up UFDS delete operations.
 *
 * See ldapjs docs.
 *
 * @param {String} dn dn to delete.
 * @param {Function} callback of the form fn(error).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.del = function del(dn, cb) {
    assert.string(dn, 'key');
    assert.func(cb, 'callback');

    cb = once(cb);
    var self = this;

    this.client.del(dn, function (err) {
        if (err) {
            cb(translateError(err));
        } else {
            self._newCache();
            cb(null);
        }
    });
};


/**
 * Low-level API to wrap up UFDS modify operations.
 *
 * See ldapjs docs.
 *
 * @param {String} dn to update
 * @param {Object} changes to make.
 * @param {Function} callback of the form fn(error).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.modify = function modify(dn, changes, cb) {
    assert.string(dn, 'key');
    assert.object(changes, 'changes');
    assert.func(cb, 'callback');

    cb = once(cb);
    var self = this;

    this.client.modify(dn, changes, function (err) {
        if (err) {
            cb(translateError(err));
        } else {
            self._newCache();
            cb(null);
        }
    });
};


/**
 * Low-level API to wrap up UFDS search operations.
 *
 * See ldapjs docs.
 *
 * @param {String} base search base.
 * @param {Object} options search options.
 * @param {Array} controls search controls.
 * @param {Function} callback of the form fn(error, entries).
 * @param {Boolean} noCache optional flag to force skipping the cache.
 * @return {Boolean} true if callback was invoked from cache, false if not.
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.search = function search(base, options, controls, cb, noCache) {
    assert.string(base, 'key');
    assert.object(options, 'changes');
    if (typeof (controls) === 'function') {
        // Shift arguments over if 'controls' is omitted
        noCache = cb;
        cb = controls;
        controls = [];
    } else {
        if (controls instanceof ldap.Control) {
            controls = [controls];
        } else if (!Array.isArray(controls)) {
            throw new TypeError('controls (Control,[Control]) required');
        }
    }
    assert.func(cb, 'callback');

    cb = once(cb);
    if (this.hidden) {
        controls = controls.concat(HIDDEN);
    }
    var self = this;
    var key = base + '::' + JSON.stringify(options);
    var tmp;

    if (!noCache && (tmp = (this.cache ? this.cache.get(key) : false))) {
        cb(null, clone(tmp));
        return;
    }

    this.client.search(base, options, controls, function (start_err, res) {
        if (start_err) {
            cb(translateError(start_err));
            return;
        }

        var entries = [];
        res.on('searchEntry', function (entry) {
            entries.push(entry.object);
        });

        res.on('error', function (err) {
            cb(translateError(err));
        });

        res.on('end', function () {
            if (entries.length && self.cache)
                self.cache.put(key, clone(entries));

            cb(null, entries);
        });
    });
};


/*
 * Low-level API to wrap up UFDS compare operations.
 *
 * See ldapjs docs.
 * @param {String} name the DN of the entry to compare attributes with.
 * @param {String} attr name of an attribute to check.
 * @param {String} value value of an attribute to check.
 * @param {Function} callback of the form fn(error, ok).
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.compare = function compare(dn, attr, val, cb) {
    assert.string(dn, 'dn');
    assert.string(attr, 'attr');
    assert.string(val, 'val');
    assert.func(cb, 'callback');

    cb = once(cb);

    this.client.compare(dn, attr, val, cb);
};


UFDS.prototype.unbind = function unbind(cb) {
    if (this.client.connected) {
        this.client.unbind(cb);
    } else {
        cb(null);
    }
};


UFDS.prototype.setLogLevel = function setLogLevel(level) {
    this.log.level(level);
    if (this.client)
        this.client.log.level(level);
};



// --- "Private" methods

UFDS.prototype._newCache = function _newCache() {
    this.cache = null;
    if (this.cacheOptions)
        this.cache = cache.createCache(this.cacheOptions);
};
