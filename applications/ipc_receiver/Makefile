# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

umode:
	g++ -Wall -Werror -I ../../include/ ipc_receiver.c -o ipc_receiver.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp ipc_receiver.so ../bin/

clean:
	rm ipc_receiver.so
