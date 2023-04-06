# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

umode:
	g++ -Wall -Werror -Wno-format-overflow -I ../../include/ secure_login.c -o secure_login.so -shared -fPIC -fvisibility=hidden
	mkdir -p ../bin
	cp secure_login.so ../bin/

clean:
	rm secure_login.so
