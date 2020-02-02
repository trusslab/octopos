DIRS := applications arch keyboard os runtime serial_out storage network
DIRS_CLEAN := applications arch keyboard os runtime serial_out storage network util/network

.PHONY: umode

umode:
	for dir in $(DIRS); do \
		$(MAKE) umode -C $$dir; \
	done

clean:
	for dir in $(DIRS_CLEAN); do \
		$(MAKE) clean -C $$dir; \
	done
