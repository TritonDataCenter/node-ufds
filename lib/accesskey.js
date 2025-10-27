/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Routines for generating and validating secret access keys.
 *
 * Copyright 2025 Edgecast Cloud LLC.
 */

var crypto = require('crypto');
var crc32 = require('crc').buffer.crc32;
var assert = require('assert-plus');

var TO_B64_REG = new RegExp('[+/=]', 'g');
var FROM_B64_REG = new RegExp('[-_]', 'g');

var DEFAULT_PREFIX = 'tdc_';
var DEFAULT_BYTE_LENGTH = 32;

// Don't have base64url encoded Buffers until Node v14
function toBase64url(input) {
  return input
    .toString('base64')
    .replace(TO_B64_REG, function (c) {
        if (c === '+') {
          return '-';
        }
        if (c === '/') {
          return '_';
        }
        if (c === '=') {
          return '';
        }
        return null;
    });
}

function fromBase64url(input) {
  var base64 = input.replace(FROM_B64_REG, function (c) {
    if (c === '-') {
      return '+';
    }
    if (c === '_') {
      return '/';
    }
    return null;
  });

  // Restore padding
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }

  return Buffer.from(base64, 'base64');
}

/**
 * Generate a random secret access key inspired by suggestions from Github's
 * Secret Scanning Partner Program[0] and how they structure their keys[1]:
 *   [0] https://i.no.de/c12f50d544eececf
 *   [1] https://i.no.de/5a4e8cea87c0a873
 *
 * Instead of using Base62 as Github does, base64url encoding is used instead.
 *
 * Keys generated from this function have:
 *   - A uniquely defined prefix (e.g. "tdc_" for "Triton DataCenter")
 *   - High entropy random strings (32 random bytes from node crypto)
 *   - A 32-bit crc checksum (to validate token structure)
 *
 * An example key:
 *
 *    tdc_SU4xWXL-HzrMIDM_A8GH94sl-uc-aX8mqsEMiK4JSVdAGyjH
 *
 *    +--------+--------------------------------------------+--------+
 *    | PREFIX |             RANDOM BYTES                   | CRC32  |
 *    +--------+--------------------------------------------+--------+
 *    |  tdc_  | SU4xWXL-HzrMIDM_A8GH94sl-uc-aX8mqsEMiK4JSV | dAGyjH |---+
 *    +--------+--------------------------------------------+--------+   |
 *             |                 BASE64 URL ENCODED                  |   |
 *    +--------+--------------------------------------------+--------+   |
 *    |       CRC32 coverage (PREFIX + RANDOM BYTES)        | <----------+
 *    +-----------------------------------------------------+
 *
 * @param {String} prefix string for the token.
 * @param {Number} byte count to randomly generate.
 * @param {Function} callback of the form fn(err, key).
 * @throws {TypeError} on bad input.
 */
function generate(prefix, bytes, done) {
    assert.string(prefix, 'prefix');
    assert.number(bytes, 'bytes');
    assert.func(done, 'done');

    crypto.randomBytes(bytes, function generateBytes(err, randBytes) {
        if (err) {
            done(err);
            return;
        }

        // Create a buffer containing the prefix and random bytes
        var prefixBuf = Buffer.alloc(prefix.length, prefix);
        var tokenBuf = Buffer.concat([prefixBuf, randBytes]);

        // Obtain CRC32 from prefix + random bytes
        var crc = crc32(tokenBuf);

        // Write the CRC32 into a new buffer encoded as a 32-bit signed int
        var crcBuf = Buffer.alloc(4);
        if (crcBuf.writeInt32LE(crc, 0) !== 4) {
            done(new Error('Failed to generate access key'));
            return;
        }

        // Base64 URL the encode random bytes + CRC32, prepend the prefix
        var key = prefix + toBase64url(Buffer.concat([randBytes, crcBuf]));

        done(null, key);
        return;
    });
}

/**
 * Validates the structure of a secret access key. Does NOT validate that the
 * token is active and valid for authentication purposes it only validates that
 * the token structure is correct. This function can be used to toss out a
 * garbage token before attempting to look it up against UFDS.
 *
 * @param {String} prefix string for the token.
 * @param {Number} byte count expected in the token.
 * @param {String} secret key string.
 * @throws {TypeError} on bad input.
 */
function validate(prefix, bytes, secret) {
    assert.string(prefix, 'prefix');
    assert.number(bytes, 'bytes');
    assert.string(secret, 'secret');

    if (secret.indexOf(prefix) !== 0) {
        return false;
    }

    // Remove prefix from the secret
    var body = secret.slice(prefix.length);

    // Base64 URL decode the body containing random bytes + CRC32
    var parts = fromBase64url(body);

    // Must contain the expected number of random bytes + 4 bytes for the CRC32
    if (parts.length !== (bytes + 4)) {
        return false;
    }

    // Create a buffer containg the prefix
    var prefixBuf = Buffer.alloc(prefix.length, secret.slice(0, prefix.length));

    // Create a buffer containing the random bytes
    var randBytesBuf = parts.slice(0, -4);

    // Create a buffer from the CRC32 at the end of the secret
    var crc32Buf = parts.slice(-4);

    // Create a new buffer containing the prefix + random bytes
    var tokenBuf = Buffer.concat([prefixBuf, randBytesBuf]);

    // Recompute CRC32 and compare with the CRC32 obtained from the secret
    return (crc32(tokenBuf) === crc32Buf.readInt32LE());
}

module.exports = {
    generate: generate,
    validate: validate,
    DEFAULT_PREFIX: DEFAULT_PREFIX,
    DEFAULT_BYTE_LENGTH: DEFAULT_BYTE_LENGTH
};