/*
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 *
 * This is the new UFDS client, including support for multiple account users,
 * roles and policies. It requires an ufds server including changes until
 * February 5th, 2014. (version >= c8d683200e)
 */

var crypto = require('crypto');
var EventEmitter = require('events').EventEmitter;
var util = require('util');

var assert = require('assert-plus');
var backoff = require('backoff');
var bunyan = require('bunyan');
var httpSignature = require('http-signature');
var clone = require('clone');
var ldap = require('ldapjs');
var once = require('once');
var restify = require('restify');
var libuuid = require('libuuid');
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
    'connect',
    'connectTimeout',
    'close',
    'end',
    'error',
    'socketTimeout',
    'timeout'
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

var AUTHDEV_FMT = 'authdev=%s, ' + USER_FMT;
var FOREIGNDC_FMT = 'foreigndc=%s, ' + AUTHDEV_FMT;

var REGION = 'region=%s, ' + SUFFIX;

var UUID_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

// --- Internal Functions

function createClient(opts, cb) {
    assert.object(opts, 'options');
    assert.func(cb, 'callback');

    cb = once(cb);

    var dn = opts.credentials.dn;
    var log = opts.log;
    var passwd = opts.credentials.passwd;
    var retryOpts = clone(opts.retry || {});
    retryOpts.maxDelay = retryOpts.maxDelay || retryOpts.maxTimeout || 30000;
    retryOpts.retries = retryOpts.retries || Infinity;

    function _createClient(_, _cb) {

        _cb = once(_cb);

        function onConnect() {
            client.removeListener('error', onError);
            log.trace('ufds: connected');
            client.bind(dn, passwd, function (err) {
                if (err) {
                    if (err.name === 'InvalidCredentialsError') {
                        log.error({bindDN: dn, err: err},
                            'UFDS: invalid credentials; aborting');
                        retry.abort();
                    } else {
                        log.error({bindDN: dn, err: err},
                            'UFDS: unexpected bind error');
                    }
                    _cb(err);
                    return;
                }

                log.trace({
                    bindDN: dn
                }, 'UFDS: connected and bound');

                _cb(null, client);
            });
        }

        function onError(err) {
            client.removeListener('connect', onConnect);
            _cb(err);
        }

        var client = ldap.createClient(opts);
        client.once('connect', onConnect);
        client.once('error', onError);
        client.once('connectTimeout', function () {
            onError(new Error('connect timeout'));
        });
    }

    var retry = backoff.call(_createClient, null, cb);
    retry.setStrategy(new backoff.ExponentialStrategy(retryOpts));
    retry.failAfter(retryOpts.retries);

    retry.on('backoff', function (number, delay) {
        var level;
        if (number === 0) {
            level = 'info';
        } else if (number < 5) {
            level = 'warn';
        } else {
            level = 'error';
        }

        log[level]({
            attempt: number,
            delay: delay
        }, 'ufds: connection attempt failed');
    });

    retry.start();
    return (retry);
}


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
        retry: opts.retry || {},
        tlsOptions: {
            rejectUnauthorized: false
        },
        timeout: opts.clientTimeout || opts.timeout,
        url: opts.url,
        idleTimeout: opts.idleTimeout || 90000
    };

    this.controls = (opts.hidden) ? HIDDEN : [];

    this.connect();
}
util.inherits(UFDS, EventEmitter);
module.exports = UFDS;


UFDS.prototype.connect = function connect() {
    var self = this;
    return (function conn() {
        self.connecting = createClient(self.ldapOpts, function (err, client) {
            self.connecting = false;

            // We only get error if credentials are invalid
            if (err) {
                self.emit('error', err);
                return;
            }

            if (self.closed && client) {
                client.unbind();
                return;
            }

            function handleClose() {
                if (self.client && !self.connecting && !self.closed) {
                    self.log.info('LDAP client disconnected');
                    self.client = null;
                }
            }

            function handleError() {
                handleClose();
                conn();
            }

            client.once('error', handleError);
            client.once('close', handleClose);
            // HAProxy timeout client is set to 2 mins. Default client idle
            // timeout is set to 90 seconds
            client.socket.setTimeout(self.ldapOpts.idleTimeout, function () {
                self.log.debug('Closing as a result of idleness');
            });

            LDAP_PROXY_EVENTS.forEach(function reEmit(event) {
                client.on(event, self.emit.bind(self, event));
            });

            self.client = client;
            self.emit('connect');
            self.emit('ready'); // backwards compatible
        });
    })();
};


/**
 * Unbinds the underlying LDAP client.
 *
 * @param {Function} callback of the form f(err).
 */
UFDS.prototype.close = function close(cb) {
    assert.func(cb, 'callback');

    cb = once(cb);

    var self = this;

    this.closed = true;
    if (!this.client) {
        if (this.connecting) {
            this.connecting.abort();
        }
        cb();
        return;
    }

    LDAP_PROXY_EVENTS.forEach(function reEmit(event) {
        self.client.removeAllListeners(event);
    });

    this.client.unbind(function (err) {
        if (err) {
            cb(translateError(err));
        } else {
            process.nextTick(self.emit.bind(self, 'close'));
            cb();
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

        // Do not load them, just make roles available through the user:
        entries[0].roles = function roles(cb) {
            var filter = sprintf(
                '(&(objectclass=sdcaccountrole)(uniquemember=%s))',
                entries[0].dn.toString());
            return self.listRoles(account, filter, cb, noCache);
        };

        // Same for default roles:
        entries[0].defaultRoles = function defaultRoles(cb) {
            var filter = sprintf(
                '(&(objectclass=sdcaccountrole)(uniquememberdefault=%s))',
                entries[0].dn.toString());
            return self.listRoles(account, filter, cb, noCache);
        };

        // Now load the groups they're in
        opts = {
            scope: 'sub',
            filter: sprintf(
                    '(&(objectclass=groupofuniquenames)(uniquemember=%s))',
                    entries[0].dn.toString())
        };
        self.search(SUFFIX, opts, function (groupErr, groups) {
            if (groupErr) {
                cb(groupErr);
                return;
            }

            entries[0].memberof = groups.map(function (v) {
                return (v.dn);
            });

            cb(null, extendUser(self, entries[0]));

        }, noCache);
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

    self.getPolicy(account, policy, function (err) {
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
    this.search(dn, opts, function (err, resources) {
        if (err) {
            cb(err);
        } else {
            cb(null, resources);
        }
    }, noCache);
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

    self.getResource(account, resource, function (err) {
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

    var self = this;
    var dn = sprintf(REGION, region);
    var opts = {
        scope: 'sub',
        filter: '(objectclass=datacenter)'
    };
    self.search(dn, opts, cb, noCache);
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

    var self = this;
    var dn = sprintf(REGION, region);
    var opts = {
        scope: 'sub',
        filter: '(objectclass=resolver)'
    };
    self.search(dn, opts, cb, noCache);
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

    function _add() {
        self.client.add(dn, entry, function (err) {
            if (err) {
                cb(translateError(err));
            } else {
                self._newCache();
                cb(null);
            }
        });
    }

    if (!this.client) {
        self.once('connect', _add);
        if (!this.connecting) {
            self.connect();
        }
    } else {
        _add();
    }
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

    function _del() {
        self.client.del(dn, function (err) {
            if (err) {
                cb(translateError(err));
            } else {
                self._newCache();
                cb(null);
            }
        });
    }

    if (!this.client) {
        self.once('connect', _del);
        if (!this.connecting) {
            self.connect();
        }
    } else {
        _del();
    }
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

    function _modify() {
        self.client.modify(dn, changes, function (err) {
            if (err) {
                cb(translateError(err));
            } else {
                self._newCache();
                cb(null);
            }
        });

    }

    if (!this.client) {
        self.once('connect', _modify);
        if (!this.connecting) {
            self.connect();
        }
    } else {
        _modify();
    }
};


/**
 * Low-level API to wrap up UFDS search operations.
 *
 * See ldapjs docs.
 *
 * @param {String} base search base.
 * @param {Object} options search options.
 * @param {Function} callback of the form fn(error, entries).
 * @param {Boolean} noCache optional flag to force skipping the cache.
 * @return {Boolean} true if callback was invoked from cache, false if not.
 * @throws {TypeError} on bad input.
 */
UFDS.prototype.search = function search(base, options, cb, noCache) {
    assert.string(base, 'key');
    assert.object(options, 'changes');
    assert.func(cb, 'callback');

    cb = once(cb);

    var self = this;

    function _search() {
        var key = base + '::' + JSON.stringify(options);

        var tmp;

        if (!noCache && (tmp = (this.cache ? this.cache.get(key) : false))) {
            cb(null, clone(tmp));
            return;
        }

        self.client.search(base, options, self.controls,
                function (start_err, res) {
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
    }

    if (!this.client) {
        self.once('connect', _search);
        if (!this.connecting) {
            self.connect();
        }
    } else {
        _search();
    }

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

    var self = this;

    function _compare() {
        self.client.compare(dn, attr, val, function (err, ok) {
            cb(err, ok);
        });
    }

    if (!this.client) {
        self.once('connect', _compare);
        if (!this.connecting) {
            self.connect();
        }
    } else {
        _compare();
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



// --- "Tests"
if (require.main === module) {

// Follow prompts:

    (function test() {
        var vasync = require('vasync');
        assert.ok(process.env.UFDS_IP,
                  'UFDS_IP must be set in your environment');

        function test_cb(test, cb) {
            function _cb(err) {
                if (err) {
                    console.error('\tFAIL: unable to %s: %s', test, err + '');
                } else {
                    console.log('\tOK: %s', test);
                }
                cb(err);
            }

            return (_cb);
        }
        vasync.pipeline({
            arg: {},
            funcs: [
                function connect(opts, cb) {
                    console.log('\ncreating client...');
                    var client = new UFDS({
                        bindDN: 'cn=root',
                        bindPassword: 'secret',
                        log: bunyan.createLogger({
                            level: process.env.LOG_LEVEL || 'info',
                            name: 'ufds_test_client',
                            serializers: bunyan.stdSerializers,
                            stream: process.stdout
                        }),
                        url: 'ldaps://' + process.env.UFDS_IP + ':636'
                    });

                    client.once('connect', function () {
                        console.log('\tOK: connected');
                        opts.client = client;
                        cb();
                    });

                    client.once('error', function (err) {
                        console.error('\tFAIL: unable to connect: %s',
                                      err.toString());
                        cb(err);
                    });
                },

                function getUser(opts, cb) {
                    console.log('\nfetching a user...');
                    opts.client.getUser('admin', test_cb('getUser', cb), true);
                },

                function reconnect(opts, cb) {
                    function para(callback) {
                        opts.client.getUser(
                            'admin', test_cb('get User', callback), true);
                    }
                    console.log('\nKILL THE UFDS SERVER OR WAIT 90 SECONDS ' +
                            'FOR THE client.socket.timeout EVENT');
                    opts.client.once('error', function (err) {
                        console.log('\t\terror received');
                    });
                    opts.client.once('close', function () {
                        console.log('\t\tclose received');
                        opts.client.on('connect', function () {
                            console.log('\t\treconnect: ok');
                        });

                        vasync.parallel({
                            funcs: [para, para, para]
                        }, function (err, res) {
                            console.log('\t\tparallel requests: ok');
                            cb(err);
                        });
                    });
                },
                function close(opts, cb) {
                    console.log('\nclosing client...');
                    opts.client.close(test_cb('close', cb));
                }
            ]
        }, function (err) {
            if (err) {
                console.error('\nTests FAILED');
                process.exit(1);
            } else {
                console.log('\nTests PASSED');
                process.exit(0);
            }
        });
    })();
}
