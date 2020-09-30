umode:
	g++ -Wall -I ../include/ -I ../arch/umode/include/ bootloader.c bootloader_storage.c ../os/file_system.c ../util/file_system/wrapper.c -o bootloader_storage -ldl -lpthread -ltss2-esys -ltss2-rc
	g++ -Wall -I ../include/ -I ../arch/umode/include/ -D ROLE_BOOTLOADER_OS bootloader.c bootloader_os.c ../os/file_system.c ../os/storage.c ../arch/umode/mailbox_interface/mailbox_os.c -o bootloader_os -ldl -lpthread -ltss2-esys -ltss2-rc
	g++ -Wall -I ../include/ -I ../arch/umode/include/ bootloader.c bootloader_other.c -o bootloader_other -ldl -lpthread -ltss2-esys -ltss2-rc

clean:
	rm bootloader_storage bootloader_os bootloader_other keyboard serial_out os storage network runtime*
