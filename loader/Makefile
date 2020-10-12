umode:
	g++ -Wall -I ../include/ -I ../arch/umode/include/ loader.c loader_storage.c ../os/file_system.c ../util/file_system/wrapper.c -o loader_storage -ldl -lpthread -ltss2-esys -ltss2-rc
	g++ -Wall -I ../include/ -I ../arch/umode/include/ -D ROLE_LOADER_OS loader.c loader_os.c ../os/file_system.c ../os/storage.c ../arch/umode/mailbox_interface/mailbox_os.c -o loader_os -ldl -lpthread -ltss2-esys -ltss2-rc
	g++ -Wall -I ../include/ -I ../arch/umode/include/ loader.c loader_other.c -o loader_other -ldl -lpthread -ltss2-esys -ltss2-rc

clean:
	rm loader_storage loader_os loader_other keyboard serial_out os storage runtime*
