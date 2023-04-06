# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

umode:
	g++ -Wall -Werror -I ../include/ -I ../arch/umode/include/ -I ../arch/umode/include/ serial_out.c ../arch/umode/mailbox_interface/mailbox_serial_out.c -o serial_out -lpthread -lrt

clean:
	rm serial_out
