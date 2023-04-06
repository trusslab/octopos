# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

DIRS := mailbox pmu emulator
LINUX_DIR := untrusted_linux 

.PHONY: umode

umode:
	for dir in $(DIRS); do \
		$(MAKE) umode -C $$dir; \
	done
	for dir in $(LINUX_DIR); do \
		$(MAKE) defconfig ARCH=um -C $$dir; \
		$(MAKE) ARCH=um -C $$dir; \
	done

clean:
	for dir in $(DIRS); do \
		$(MAKE) clean -C $$dir; \
	done
	for dir in $(LINUX_DIR); do \
		$(MAKE) clean ARCH=um -C $$dir; \
	done
