# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

umode:
	g++ -Wall -Werror -Wno-address-of-packed-member -I ../../include/ health_client.c ../../util/tpm/tpm.c -o health_client.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp health_client.so ../bin/
	g++ -Wall -Werror -I ../../include/ health_server.c ../../util/tpm/hash.c -o health_server -lwolftpm -lcrypto

clean:
	rm health_client.so health_server
