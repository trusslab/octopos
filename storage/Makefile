# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

umode:
	g++ -Wall -Werror -I ../include/ -I ../arch/umode/include/ storage.c ../arch/umode/mailbox_interface/mailbox_storage.c ../util/tpm/hash.c ../util/tpm/tpm.c -o storage -lpthread -lrt -lwolftpm -lcrypto

clean:
	rm storage
