<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<!--
    Copyright 2020 Joyent, Inc.
    Copyright 2023 MNX Cloud, Inc.
-->

# node-ufds

This repository is part of the Triton project. See the [contribution
guidelines](https://github.com/TritonDataCenter/triton/blob/master/CONTRIBUTING.md) and
general documentation at the main [Triton
project](https://github.com/TritonDataCenter/triton) page.

This is a Node.js client library for Triton's
[UFDS](https://github.com/TritonDataCenter/sdc-ufds) service.


# Development

Before commiting/pushing run `make prepush` and, if possible, get a code
review. Refer to the test section below for reference on setup and how to run
the test suites.

# Testing

    UFDS_IP=...
    UFDS_LDAP_ROOT_PASSWORD=...
    DC=... # defaults to 'coal'
    make test
