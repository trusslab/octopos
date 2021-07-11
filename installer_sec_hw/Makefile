umode:
	g++ -Wall -Werror -I ../include/ -I ../arch/umode/include/ -I ../arch/sec_hw/include/ -Wno-comment -D ROLE_INSTALLER -D ARCH_SEC_HW installer.c ../os/file_system.c ../util/file_system/wrapper.c -o installer -lcrypto

clean:
	rm installer copy_* aligned_*
