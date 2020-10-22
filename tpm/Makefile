umode:
	g++ -Wall -Wno-narrowing -I ../include/ -I ../arch/umode/include/ ../arch/umode/mailbox_interface/mailbox_tpm.c libtpm.c quote.c extend.c tpm.c -o tpm -lpthread -lrt -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto 

clean:
	rm tpm
