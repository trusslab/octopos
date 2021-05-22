DIRS := applications arch keyboard os runtime serial_out storage network bluetooth bootloader installer util/tpm/tpm_shutdown
DIRS_CLEAN := applications arch keyboard os runtime serial_out storage network bluetooth util/network bootloader installer util/tpm/tpm_shutdown

EXTERNAL_DIR := ./external

umode:
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
