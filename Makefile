DIRS := applications arch keyboard os runtime serial_out storage network
DIRS_CLEAN := applications arch keyboard os runtime serial_out storage network util/network

EXTERNAL_DIR = ./external

all: umode

.PHONY: lib emu umode clean

lib:
	$(MAKE) lib -C $(EXTERNAL_DIR)

emu:
	$(MAKE) emu -C $(EXTERNAL_DIR)

umode:
	for dir in $(DIRS); do \
		$(MAKE) umode -C $$dir; \
	done

clean:
	for dir in $(DIRS_CLEAN); do \
		$(MAKE) clean -C $$dir; \
	done
