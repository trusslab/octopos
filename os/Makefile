umode:
	g++ -Wall -Werror -I ../include/ -I ../arch/umode/include/ os.c shell.c syscall.c file_system.c scheduler.c ipc.c storage.c network.c ../arch/umode/mailbox_interface/mailbox_os.c ../arch/umode/pmu_interface/pmu.c -o os -lpthread -lrt 

clean:
	rm os
