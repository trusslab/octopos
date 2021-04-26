DIRS := applications arch keyboard os runtime serial_out storage network bluetooth bootloader installer util/tpm/tpm_shutdown display
DIRS_CLEAN := applications arch keyboard os runtime serial_out storage network bluetooth util/network bootloader installer util/tpm/tpm_shutdown display

EXTERNAL_DIR := ./external

UNTRUSTED_ROOT_FS_SRC_PATH=./arch/umode/untrusted_linux/CentOS6.x-AMD64-root_fs
UNTRUSTED_ROOT_FS_PARTITION_PATH=./storage/octopos_partition_1_data

umode:
	./sync_untrusted_linux.sh
	for dir in $(DIRS); do \
		$(MAKE) umode -C $$dir; \
	done
	./installer/installer
	if [ ! -f $(UNTRUSTED_ROOT_FS_PARTITION_PATH) ]; then \
		cp $(UNTRUSTED_ROOT_FS_SRC_PATH) $(UNTRUSTED_ROOT_FS_PARTITION_PATH); \
	fi 

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
