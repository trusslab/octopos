umode:
	g++ -Wall -Werror tpm_shutdown.c -o tpm_shutdown -lpthread -lrt -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto 
	mkdir -p ../bin

clean:
	rm tpm_shutdown
