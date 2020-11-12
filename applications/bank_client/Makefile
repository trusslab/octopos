umode:
	g++ -Wall -Werror -I ../../include/ bank_client.c -o bank_client.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp bank_client.so ../bin/
	g++ -Wall -Werror -I ../../include/ bank_server.c ../../util/tpm/hash.c -o bank_server -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto -ljson

clean:
	rm bank_client.so bank_server
