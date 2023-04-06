# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

OBJS	= arp.o arp_cache.o
SUBDIR	= arp

all:arp_obj.o
arp_obj.o:$(OBJS)
	@echo " [LD] $(SUBDIR)/$@"
	$(Q)$(LD) -r -o $@ $^

%.o:%.c
	@echo " [CC] $(SUBDIR)/$@"
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o
