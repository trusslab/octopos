DIRS := applications arch keyboard os runtime serial_out storage	   

.PHONY: umode

umode:
	for dir in $(DIRS); do \
		$(MAKE) umode -C $$dir; \
	done
