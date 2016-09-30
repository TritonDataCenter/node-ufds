#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright 2016 Joyent, Inc.
#

#
# Tools
#
# Get md2man-roff from <https://github.com/sunaku/md2man>
NODEUNIT		:= ./node_modules/.bin/nodeunit
NPM			:= npm

#
# Files
#
DOC_FILES		 = index.md
JS_FILES	:= $(shell find lib test -name '*.js')
JSL_CONF_NODE	 = tools/jsl.node.conf
JSL_FILES_NODE   = $(JS_FILES)
JSSTYLE_FILES	 = $(JS_FILES)
JSSTYLE_FLAGS    = -f tools/jsstyle.conf

CLEAN_FILES += node_modules

include ./tools/mk/Makefile.defs

#
# Repo-specific targets
#
.PHONY: all
all: $(SMF_MANIFESTS) deps

.PHONY: deps
deps: | $(REPO_DEPS) $(NPM_EXEC)
	$(NPM_ENV) $(NPM) install

.PHONY: test
test: deps
	$(NODEUNIT) test/*.test.js --reporter tap


include ./tools/mk/Makefile.deps
include ./tools/mk/Makefile.targ
