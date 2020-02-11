#### User configure  ###############
# FIXME: do we need these options?
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
CFLAGS = -Wall -Werror -I ../include/ -I ../include/network/ -I ../../include/ -I ../../include/network/ -I ../arch/umode/include/
LFLAGS = -ldl -lpthread -lrt
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

NETWORK_OBJS =  network.o 			\
		net/net_obj.o   		\
		ip/ip_obj.o     		\
		arp/arp_obj.o   		\
		../util/network/lib_obj.o

umode:network

network:$(NETWORK_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LFLAGS)

net/net_obj.o:net/*.c
	@make -C net/
ip/ip_obj.o:ip/*.c
	@make -C ip/
arp/arp_obj.o:arp/*.c
	@make -C arp/
../util/network/lib_obj.o:../util/network/*.c
	@make -C ../util/network/

clean:
	find . -name *.o | xargs rm -f
	rm -f network
