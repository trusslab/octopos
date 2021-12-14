umode:
	g++ -Wall -Werror -I ../../include/ health_client.c ../../util/tpm/tpm.c ../../util/tpm/aes.c -o health_client.so -shared -fPIC -fvisibility=hidden -ldl -lpthread -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto -ljson-c
	mkdir -p ../bin
	cp health_client.so ../bin/
	g++ -Wall -Werror -I ../../include/ health_server.c ../../util/tpm/hash.c ../../util/tpm/aes.c -o health_server -ldl -lpthread -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto -lrt -ljson-c

clean:
	rm health_client.so health_server
