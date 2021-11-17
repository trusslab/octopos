umode:
	g++ -Wall -Werror create_primary.c -o create_primary -ldl -lpthread -lrt -ltss2-esys -ltss2-sys -ltss2-rc -lcrypto -ljson-c
	g++ -Wall -Werror tpm_shutdown.c -o tpm_shutdown -lpthread -lrt -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto
	g++ -Wall -Werror reset_keys.c -o reset_keys -ldl -lpthread -lrt -ltss2-esys -ltss2-fapi -ltss2-rc -lcrypto -ljson-c

clean:
	rm create_primary
	rm tpm_shutdown
