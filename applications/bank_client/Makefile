# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

umode:
	g++ -Wall -Werror -Wno-address-of-packed-member -I ../../include/ bank_client.c ../../util/tpm/tpm.c -o bank_client.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp bank_client.so ../bin/
	g++ -Wall -Werror -I ../../include/ bank_server.c ../../util/tpm/hash.c -o bank_server -lwolftpm -lcrypto

clean:
	rm bank_client.so bank_server
