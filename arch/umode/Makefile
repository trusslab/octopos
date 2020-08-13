DIRS := mailbox 
LINUX_DIR := untrusted_linux 

.PHONY: umode

umode:
	for dir in $(DIRS); do \
		$(MAKE) umode -C $$dir; \
	done
	for dir in $(LINUX_DIR); do \
		$(MAKE) ARCH=um -C $$dir; \
	done

clean:
	for dir in $(DIRS); do \
		$(MAKE) clean -C $$dir; \
	done
	for dir in $(LINUX_DIR); do \
		$(MAKE) ARCH=um clean -C $$dir; \
	done
