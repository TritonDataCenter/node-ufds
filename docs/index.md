---
title: node-ufds
markdown2extras: tables, code-friendly
---

# node-ufds

node-ufds (`npm install ufds`) is a node.js client library for the Triton
internal UFDS service.

# UFDS API Client

## UFDS(options)

Creates a UFDS client instance.

Options must be an object that contains

| Name | Type | Description |
| ---- | ---- | ----------- |
| url | String | UFDS location |
| bindDN | String | admin bindDN for UFDS. |
| password | String | password to said adminDN |
| cache | Object or *false* | age(Default 60s) size(default 1k) *false* to disable |


## close(callback)

Unbinds the underlying LDAP client.

| Name | Type | Description |
| ---- | ---- | ----------- |
| callback | Function | (optional) callback of the form ``f(err)``. |


## authenticate(login, password, [account,] cb)

Checks a user's password in UFDS.

Returns a RestError of '401' if password mismatches. Returns the same user
object as getUser on success.

### Arguments:

| Name | Type | Description |
| ---- | ---- | ----------- |
| login | String | login one of login, uuid or the result of getUser. |
| password | String | password correct password. |
| account | String | (optional) sub-user uuid. |
| cb | Function | callback of the form ``fn(err, user)``. |

### Throws:

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input |


## addUser(user, callback)

Adds a new user into UFDS.

This call expects the user object to look like the `sdcPerson` UFDS
schema, minus objectclass/dn/uuid.

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | Object | the entry to add. |
| callback | Function | callback of the form ``fn(err, user).`` |

### Throws

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input |


## getUser(login, [account,] callback)

Looks up a user by login to UFDS.

| Name | Type | Description |
| ---- | ---- | ----------- |
| login | String | login (or uuid) for a customer. |
| account | String | (optional) sub-user uuid. |
| callback | Function | callback of the form f(err, user). |

### Throws

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input. |


## updateUser(user, changes, [account,] callback)

Updates a user record.

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | String or Object | The user UUID or login string or a user object with a `user.dn`, `user.uuid` or `user.login` (i.e. a user object as from `getUser`).user the user record you got from getUser. |
| changes | Object | Changes to the object you want merged in. For example: `{myfield: "blah"}` will add/replace the existing `myfield`. You can delete an existing field by passing in a null value, e.g.: `{addthisfield: "blah", rmthisfield: null}`. |
| account | String | (optional) sub-user uuid. |
| callback | Function | callback of the form `function (err, user)`. |

### Throws

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input. |


## deleteUser(user, [account,] callback)

Deletes a user record.

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | Object | user the user record you got from getUser. |
| account | String | (optional) sub-user uuid. |
| callback | Function | callback of the form ``fn(err, user)``. |

### Throws

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input |


## addKey(user, key, [account,] callback)

Adds a new SSH key to a given user record.

You can either pass in an SSH public key (string) or an object of the form

    {
      name: foo,
      openssh: public key
    }

This method will return you the full key as processed by UFDS. If you don't
pass in a name, then the name gets set to the fingerprint of the SSH key.

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | Object | the user record you got from getUser. |
| key | String | the OpenSSH public key. |
| account | String | (optional) sub-user uuid. |
| callback | Function | callback of the form `fn(err, key)`. |

### Throws

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input. |


## getKey(user, fingerprint, [account,] callback)

Retrieves an SSH key by fingerprint.

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | Object | user the object you got back from getUser. |
| fingerprint | String | fingerprint the SSH fp (or name) of the SSH key you want. |
| account | String | (optional) sub-user uuid. |
| callback | Function | callback of the form `fn(err, key)`. |

### Throws

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input. |


## listKeys(user, [account,] callback)

Loads all keys for a given user.

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | Object | user the user you got from getUser. |
| account | String | (optional) sub-user uuid. |
| callback | Function | callback of the form fn(err, keys). |

### Throws

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input. |


## deleteKey(user, key, [account,] callback)

Deletes an SSH key under a user.

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | User | the object you got back from getUser. |
| key | Object | key the object you got from getKey. |
| account | String | (optional) sub-user uuid. |
| callback | Function | callback of the form fn(err, key). |

### Throws

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input. |


## listLimits(user, [account,] callback)

Lists "CAPI" limits for a given user.

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | Object | the object returned from ``getUser`` |
| account | String | (optional) sub-user uuid. |
| callback | Function | callback of the form ``fn(err, limits)`` |

### Throws

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input. |


## getLimit(user, datacenter, callback)

Gets a "CAPI" limit for a given user.

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | Object | user the object returned from getUser. |
| datacenter | String | datacenter the datacenter name. |
| callback | Function | callback of the form fn(err, limits). |

### Throws

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input. |


## addLimit(user, limit, callback)

Creates a "CAPI"" limit for a given user.

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | Object | the object returned from getUser. |
| limit | Object | the limit to add. |
| callback | Function | callback of the form ``fn(err, limits)`` |


## updateLimit(user, limit, callback)

Updates a "CAPI"" limit for a given user.

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | Object | the object returned from getUser. |
| limit | Object | the limit to add. |
| callback | Function | callback of the form ``fn(err, limits)`` |

### Throws

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input. |


## deleteLimit(user, limit, callback)

Deletes a "CAPI"" limit for a given user.

Note that this deletes _all_ limits for a datacenter, so if you just want
to purge one, you probably want to use updateLimit.

| Name | Type | Description |
| ---- | ---- | ----------- |
| user | Object | the object returned from getUser. |
| limit | Object | the limit to delete. |
| callback | Function callback of the form ``fn(err)``. |

### Throws

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input. |


## add(dn, entry, callback)

Low-level API to wrap up UFDS add operations.

See ldapjs docs.

| Name | Type | Description |
| ---- | ---- | ----------- |
| dn | String | dn of the record to add. |
| entry | Object | entry record attributes. |
| callback | Function | callback of the form ``fn(error, entries).`` |

### Throws

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input. |


## del(dn, callback)

Low-level API to wrap up UFDS delete operations.

See ldapjs docs.

| Name | Type | Description |
| ---- | ---- | ----------- |
| dn | String | dn dn to delete. |
| callback | Function | callback of the form ``fn(error)``. |

### Throws

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input. |


## modify(dn, changes, callback)

Low-level API to wrap up UFDS modify operations.

See ldapjs docs.

| Name | Type | Description |
| ---- | ---- | ----------- |
| dn | String | dn to update |
| changes | Object | changes to make. |
| callback | Function | callback of the form fn(error). |

### Throws

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input. |


## search(base, options, callback)

Low-level API to wrap up UFDS search operations.
See ldapjs docs.

| Name | Type | Description |
| ---- | ---- | ----------- |
| base | String | search base. |
| options | Object | search options. |
| callback | Function | callback of the form ``fn(error, entries)``. |

### Returns

| Type | Description |
| ---- | ----------- |
| Boolean | true if callback was invoked from cache, false if not. |

### Throw

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input. |


## setLogLevel(level)

Convenience mechanism to set the LDAP log level.

| Name | Type | Description |
| ---- | ---- | ----------- |
| level | String | see Log4js levels. |

### Throws

| Error | Description |
| ----- | ----------- |
| TypeError | on bad input. |
