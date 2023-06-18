# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

umode:
	g++ -Wall -I ../include/ -I ../arch/umode/include/ bootloader.c bootloader_storage.c ../os/file_system.c ../util/file_system/wrapper.c ../util/tpm/hash.c ../util/tpm/tpm.c ../util/tpm/rsa.c -o bootloader_storage -ldl -lpthread -lwolftpm -lcrypto
	g++ -Wall -I ../include/ -I ../arch/umode/include/ -D ROLE_BOOTLOADER_OS bootloader.c bootloader_os.c ../os/file_system.c ../os/storage.c ../arch/umode/mailbox_interface/mailbox_os.c ../util/tpm/hash.c ../util/tpm/tpm.c ../util/tpm/rsa.c -o bootloader_os -ldl -lpthread -lwolftpm -lcrypto
	g++ -Wall -I ../include/ -I ../arch/umode/include/ bootloader.c bootloader_other.c ../util/tpm/hash.c ../util/tpm/tpm.c ../util/tpm/rsa.c -o bootloader_other -ldl -lpthread -lwolftpm -lcrypto

clean:
	rm -f bootloader_storage bootloader_os bootloader_other keyboard serial_out os storage network bluetooth runtime* linux
