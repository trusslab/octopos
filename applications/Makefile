DIRS := fs_loop fs_test ipc_receiver ipc_sender secure_login simple_loop \
	socket_client secure_interact attest_client bank_client health_client \
	high_performance

.PHONY: umode

umode:
	for dir in $(DIRS); do \
		$(MAKE) umode -C $$dir; \
	done

clean:
	rm -r bin/
	for dir in $(DIRS); do \
		$(MAKE) clean -C $$dir; \
	done
