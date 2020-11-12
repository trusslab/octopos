umode:
	g++ -Wall -Werror -I ../../include/ bank_client.c -o bank_client.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp bank_client.so ../bin/
	g++ bank_server.c -o bank_server

clean:
	rm bank_client.so bank_server
