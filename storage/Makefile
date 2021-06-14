umode:
	g++ -Wall -Werror -I ../include/ -I ../arch/umode/include/ storage.c ../arch/umode/mailbox_interface/mailbox_storage.c ../util/tpm/hash.c ../util/tpm/tpm.c ../util/tpm/queue.c -o storage -lpthread -lrt -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto

clean:
	rm storage
