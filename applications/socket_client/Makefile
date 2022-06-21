umode:
	g++ -Wall -Wno-address-of-packed-member -I ../../include/ socket_client.c -o socket_client.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp socket_client.so ../bin/
	# g++ socket_server.c -o socket_server
	# g++ socket_server_test_latency.c -o socket_server_test_latency
	g++ socket_server_test_throughput.c -o socket_server

clean:
	rm socket_client.so socket_server
