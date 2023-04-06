# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

DIRS := fs_loop fs_test ipc_receiver ipc_sender secure_login simple_loop \
	socket_client secure_interact attest_client bank_client health_client

.PHONY: umode

umode:
	for dir in $(DIRS); do \
		$(MAKE) umode -C $$dir; \
	done

clean:
	rm -r bin/
	for dir in $(DIRS); do \
		$(MAKE) clean -C $$dir; \
	done
