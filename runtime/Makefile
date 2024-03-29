# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

#### User configure  ###############
CONFIG_DEBUG = n
CONFIG_DEBUG_PKB = n
CONFIG_DEBUG_WAIT = n
CONFIG_DEBUG_SOCK = n
CONFIG_DEBUG_ARP_LOCK = n
CONFIG_DEBUG_ICMPEXCFRAGTIME = n
CONFIG_TOPLOGY = 2
#### End of User configure #########

LD = ld
CC = gcc
CFLAGS = -Wall -Werror -Wno-address-of-packed-member -I ../include/ -I ../include/network/ -I ../../include/network/ -I ../../../include/ -I ../../../include/network/ -I ../arch/umode/include/
LFLAGS = -ldl -lpthread -lrt -lwolftpm -lcrypto
export LD CC CFLAGS

ifeq ($(CONFIG_DEBUG), y)
	CFLAGS += -g
endif

ifeq ($(CONFIG_DEBUG), y)
	CFLAGS += -DDEBUG_PKB
endif

ifeq ($(CONFIG_DEBUG_SOCK), y)
	CFLAGS += -DSOCK_DEBUG
endif

ifeq ($(CONFIG_DEBUG_ICMPEXCFRAGTIME), y)
	CFLAGS += -DICMP_EXC_FRAGTIME_TEST
endif

ifeq ($(CONFIG_DEBUG_WAIT), y)
	CFLAGS += -DWAIT_DEBUG
endif

ifeq ($(CONFIG_DEBUG_ARP_LOCK), y)
	CFLAGS += -DDEBUG_ARPCACHE_LOCK
endif

ifeq ($(CONFIG_TOPLOGY), 1)
	CFLAGS += -DCONFIG_TOP1
else
	CFLAGS += -DCONFIG_TOP2
endif

RUNTIME_OBJS =  runtime.o 						\
		storage_client.o					\
		../arch/umode/mailbox_interface/mailbox_runtime.o	\
		network_client.o					\
		network/socket/socket_obj.o				\
		network/udp/udp_obj.o					\
		network/tcp/tcp_obj.o					\
		../util/network/lib_obj.o				\
		../util/tpm/hash.o					\
		../util/tpm/tpm.o

umode:runtime

runtime:$(RUNTIME_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LFLAGS)

network/udp/udp_obj.o:network/udp/*.c
	@make -C network/udp/
network/tcp/tcp_obj.o:network/tcp/*.c
	@make -C network/tcp/
network/socket/socket_obj.o:network/socket/*.c
	@make -C network/socket/
../util/network/lib_obj.o:../util/network/*.c
	@make -C ../util/network/

clean:
	find -name "*.o" | xargs rm -f
	rm -f runtime
	rm -f ../arch/umode/mailbox_interface/mailbox_runtime.o
	rm -f ../util/network/lib_obj.o
	rm -f ../util/tpm/hash.o
	rm -f ../util/tpm/tpm.o
