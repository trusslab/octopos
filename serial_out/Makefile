umode:
	g++ -Wall -Werror -I ../include/ -I ../arch/umode/include/ -I ../arch/umode/include/ serial_out.c ../arch/umode/mailbox_interface/mailbox_serial_out.c ../util/tpm/hash.c ../util/tpm/tpm.c ../util/tpm/rsa.c -o serial_out -lpthread -lrt -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto

clean:
	rm serial_out
