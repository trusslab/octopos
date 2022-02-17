DIRS := applications arch keyboard os runtime serial_out storage network bluetooth bootloader installer util/tpm/tools
DIRS_CLEAN := applications arch keyboard os runtime serial_out storage network bluetooth util/network bootloader installer util/tpm/tools

EXTERNAL_DIR := ./external

umode:
ifeq ("$(wildcard $(EXTERNAL_DIR)/INSTALLED)","")
	$(MAKE) install -C $(EXTERNAL_DIR)
endif
	./sync_untrusted_linux.sh
	for dir in $(DIRS); do \
		$(MAKE) umode -C $$dir; \
	done
	./installer/install.sh

.PHONY: umode clean install

install:
	$(MAKE) install -C $(EXTERNAL_DIR)

clean:
	for dir in $(DIRS_CLEAN); do \
		$(MAKE) clean -C $$dir; \
	done

uninstall-local:
	rm NVChip
	$(MAKE) uninstall-local -C $(EXTERNAL_DIR)

hard-reset:
	rm -f NVChip
	rm -f storage/octopos_partition_*
	sudo rm -rf /usr/local/var/lib/tpm2-tss/system/keystore/
	sudo rm -rf /tmp/octopos_*
