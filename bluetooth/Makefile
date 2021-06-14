umode:
	g++ -Wall -Werror -I ../include/ -I ../arch/umode/include/ bluetooth.c ../arch/umode/mailbox_interface/mailbox_bluetooth.c ../util/tpm/hash.c ../util/tpm/tpm.c ../util/tpm/rsa.c ../util/tpm/queue.c -o bluetooth -lpthread -lrt -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto

clean:
	rm bluetooth
