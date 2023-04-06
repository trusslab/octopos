# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

umode:
	g++ -Wall -Werror -I ../include/ -I ../arch/umode/include/ -D ROLE_INSTALLER installer.c ../os/file_system.c ../util/file_system/wrapper.c ../util/tpm/hash.c ../util/tpm/rsa.c -o installer -lcrypto

clean:
	rm installer copy_* aligned_*
