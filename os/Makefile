umode:
	g++ -Wall -Werror -I ../include/ -I ../arch/umode/include/ -D ROLE_OS os.c shell.c syscall.c file_system.c scheduler.c ipc.c storage.c network.c boot.c ../arch/umode/mailbox_interface/mailbox_os.c ../arch/umode/pmu_interface/pmu.c ../util/tpm/hash.c ../util/tpm/tpm.c ../util/mailbox/mailbox.c -o os -lpthread -lrt -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto 

clean:
	rm os
