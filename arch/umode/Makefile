DIRS := mailbox 
LINUX_DIR := untrusted_linux 

.PHONY: umode

umode:
	for dir in $(DIRS); do \
		$(MAKE) umode -C $$dir; \
	done
	for dir in $(LINUX_DIR); do \
		$(MAKE) defconfig ARCH=um -C $$dir; \
		$(MAKE) ARCH=um -C $$dir; \
	done

clean:
	for dir in $(DIRS); do \
		$(MAKE) clean -C $$dir; \
	done
	for dir in $(LINUX_DIR); do \
		$(MAKE) clean ARCH=um -C $$dir; \
	done
