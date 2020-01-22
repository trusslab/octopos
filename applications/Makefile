DIRS := fs_loop fs_test ipc_receiver ipc_sender secure_login simple_loop

.PHONY: umode

umode:
	for dir in $(DIRS); do \
		$(MAKE) umode -C $$dir; \
	done

