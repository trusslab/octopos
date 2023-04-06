# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

umode:
	g++ -Wall -Werror -Wno-address-of-packed-member -I ../arch/umode/include/ -I ../../include/ attest_client.c ../../util/tpm/tpm.c -o attest_client.so -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp attest_client.so ../bin/
	g++ attest_server.c -o attest_server -lrt -ltss2-esys -ltss2-rc -ltss2-fapi -lcrypto 

clean:
	rm attest_client.so attest_server
