DIRS := applications keyboard mailbox os runtime serial_out storage	   

.PHONY: all

all:
	for dir in $(DIRS); do \
		$(MAKE) -C $$dir; \
	done

