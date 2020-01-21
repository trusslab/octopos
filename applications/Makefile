DIRS := fs_loop fs_test ipc_receiver ipc_sender secure_login	   

.PHONY: all

all:
	for dir in $(DIRS); do \
		$(MAKE) -C $$dir; \
	done

