umode:
	g++ -Wall -Wno-narrowing -I ../include/ -I ../arch/umode/include/ tpm.c ../arch/umode/mailbox_interface/mailbox_tpm.c -o tpm -lpthread -lrt -ltss2-esys -ltss2-rc

clean:
	rm tpm
