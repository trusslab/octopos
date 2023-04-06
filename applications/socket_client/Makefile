# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

umode:
	g++ -Wall -Wno-address-of-packed-member -I ../../include/ socket_client.c -o socket_client.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp socket_client.so ../bin/
	g++ socket_server.c -o socket_server
	g++ socket_server_test_latency.c -o socket_server_test_latency
	g++ socket_server_test_throughput.c -o socket_server_test_throughput

clean:
	rm socket_client.so socket_server socket_server_test_latency socket_server_test_throughput
