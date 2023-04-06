# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

umode:
	g++ -Wall -Werror -I ../../include/ simple_loop.c -o simple_loop.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp simple_loop.so ../bin/

clean:
	rm simple_loop.so
