DIRS := applications arch keyboard os runtime serial_out storage network tpm loader installer
DIRS_CLEAN := applications arch keyboard os runtime serial_out storage network util/network tpm loader util/tpm installer

EXTERNAL_DIR := ./external

umode:
	./sync_untrusted_linux.sh
	for dir in $(DIRS); do \
		$(MAKE) umode -C $$dir; \
	done
	./installer/installer > /dev/null 2>&1

.PHONY: umode clean install

install: 
	$(MAKE) install -C $(EXTERNAL_DIR)

clean:
	for dir in $(DIRS_CLEAN); do \
		$(MAKE) clean -C $$dir; \
	done
