# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

umode:
	g++ -Wall -Werror -I ../include/ -I ../arch/umode/include/ bluetooth.c ../arch/umode/mailbox_interface/mailbox_bluetooth.c ../util/tpm/hash.c ../util/tpm/tpm.c ../util/tpm/rsa.c -o bluetooth -lpthread -lrt -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto

clean:
	rm bluetooth
