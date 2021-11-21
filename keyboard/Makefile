umode:
	g++ -Wall -Werror -I ../include/ -I ../arch/umode/include/ keyboard.c ../arch/umode/mailbox_interface/mailbox_keyboard.c ../util/tpm/hash.c ../util/tpm/tpm.c ../util/tpm/rsa.c -o keyboard -lpthread -lrt -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto

clean:
	rm keyboard
