umode:
	g++ -Wall -I ../include/ -I ../arch/umode/include/ tpm.c -o tpm.so -lpthread -lrt -ltss2-esys -ltss2-rc -shared -fPIC
	g++ -Wall -I ../include/ -I ../arch/umode/include/ tpm_monitor.c tpm.c -o tpm_monitor -lpthread -lrt -ltss2-esys -ltss2-rc

clean:
	rm tpm_monitor
	rm tpm
