umode:
	g++ -Wall -Werror -Wno-address-of-packed-member -I ../arch/umode/include/ -I ../../include/ attest_client.c ../../util/tpm/tpm.c -o attest_client.so -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp attest_client.so ../bin/
	g++ attest_server.c -o attest_server -lrt -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto 

clean:
	rm attest_client.so attest_server
