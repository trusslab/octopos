# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

umode:
	g++ -Wall -Werror -I ../../include/ fs_loop.c -o fs_loop.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp fs_loop.so ../bin/

clean:
	rm fs_loop.so
