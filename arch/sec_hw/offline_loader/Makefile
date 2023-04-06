# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

loader:
	gcc -m32 -ggdb3 -O0 -pedantic-errors -fpermissive -D ARCH_SEC_HW_OFFLINE_LOADER loader.c srec.c -o loader

clean:
	rm offline_loader
