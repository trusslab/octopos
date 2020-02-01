umode:
	g++ -Wall -Werror -I ../../include/ socket_client.c -o socket_client.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp socket_client.so ../bin/
	g++ socket_server.c -o socket_server
