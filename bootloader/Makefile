umode:
	g++ -Wall -I ../include/ -I ../arch/umode/include/ bootloader.c bootloader_storage.c ../os/file_system.c ../util/file_system/wrapper.c ../util/tpm/hash.c ../util/tpm/tpm.c ../util/tpm/rsa.c ../util/tpm/queue.c -o bootloader_storage -ldl -lpthread -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto -lrt
	g++ -Wall -I ../include/ -I ../arch/umode/include/ -D ROLE_BOOTLOADER_OS bootloader.c bootloader_os.c ../os/file_system.c ../os/storage.c ../arch/umode/mailbox_interface/mailbox_os.c ../util/tpm/hash.c ../util/tpm/tpm.c ../util/tpm/rsa.c ../util/tpm/queue.c -o bootloader_os -ldl -lpthread -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto -lrt
	g++ -Wall -I ../include/ -I ../arch/umode/include/ bootloader.c bootloader_other.c ../util/tpm/hash.c ../util/tpm/tpm.c ../util/tpm/rsa.c ../util/tpm/queue.c -o bootloader_other -ldl -lpthread -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto -lrt

clean:
	rm -f bootloader_storage bootloader_os bootloader_other keyboard serial_out os storage network bluetooth runtime* linux
