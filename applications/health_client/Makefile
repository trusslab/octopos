umode:
	g++ -Wall -Werror -Wno-address-of-packed-member -I ../../include/ health_client.c ../../util/tpm/tpm.c -o health_client.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp health_client.so ../bin/
	g++ -Wall -Werror -I ../../include/ health_server.c ../../util/tpm/hash.c -o health_server -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto -ljson-c

clean:
	rm health_client.so health_server
