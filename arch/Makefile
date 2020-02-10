DIRS := umode

.PHONY: umode

umode:
	for dir in $(DIRS); do \
		$(MAKE) umode -C $$dir; \
	done

clean:
	for dir in $(DIRS); do \
		$(MAKE) clean -C $$dir; \
	done
