umode:
	g++ -Wall -Werror -I ../include/ -I ../arch/umode/include/ -D ROLE_INSTALLER installer.c ../os/file_system.c ../util/file_system/wrapper.c ../util/tpm/hash.c -o installer -lcrypto

clean:
	rm installer copy_* aligned_*
