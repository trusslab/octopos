# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

umode:
	g++ -Wall -Werror -I ../include/ -I ../arch/umode/include/ -D ROLE_OS os.c shell.c syscall.c file_system.c scheduler.c ipc.c storage.c network.c boot.c ../arch/umode/mailbox_interface/mailbox_os.c ../arch/umode/pmu_interface/pmu.c ../util/tpm/hash.c ../util/tpm/tpm.c -o os -lpthread -lrt -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto 

clean:
	rm os
