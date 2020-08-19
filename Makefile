DIRS := applications arch keyboard os runtime serial_out storage network tpm
DIRS_CLEAN := applications arch keyboard os runtime serial_out storage network util/network tpm

EXTERNAL_DIR := ./external

umode:
	for dir in $(DIRS); do \
		$(MAKE) umode -C $$dir; \
	done

.PHONY: umode clean install

install: 
	$(MAKE) install -C $(EXTERNAL_DIR)

clean:
	for dir in $(DIRS_CLEAN); do \
		$(MAKE) clean -C $$dir; \
	done
