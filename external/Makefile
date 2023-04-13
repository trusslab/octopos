# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

WOLF_REPO := wolfTPM
WOLF_PATCH_FILE := wolfTPM.patch

SWTPM_REPO := ibmswtpm2
SWTPM_PATCH_FILE := ibmswtpm2.patch

apply_patch:
ifeq ("$(wildcard $(REPO)/.git)","")
	@echo "Error: Run 'git submodule update --init --recursive' first"
	exit 1
endif
	cd $(REPO) && \
	if ! git apply --check --reverse ../$(PATCH) 2>/dev/null; then \
		git apply ../$(PATCH); \
	fi

revert_patch:
	cd $(REPO) && \
	if git apply --check --reverse ../$(PATCH) 2>/dev/null; then \
		git apply -R ../$(PATCH); \
	fi

wolf_install:
	make apply_patch REPO=$(WOLF_REPO) PATCH=$(WOLF_PATCH_FILE)
	cd $(WOLF_REPO) && \
		./autogen.sh && \
		./configure --disable-wolfcrypt --enable-swtpm --disable-examples && \
		make -j$(nproc) && \
		sudo make install

wolf_clean:
	sudo make uninstall -C ./wolfTPM
	make clean -C ./wolfTPM
	make revert_patch REPO=$(WOLF_REPO) PATCH=$(WOLF_PATCH_FILE)

swtpm_install:
	make apply_patch REPO=$(SWTPM_REPO) PATCH=$(SWTPM_PATCH_FILE)
	make -j$(nproc) -C ./ibmswtpm2/src
	mv ./ibmswtpm2/src/tpm_server ./ibmswtpm2/tpm_server

swtpm_clean:
	make clean -C ./ibmswtpm2/src
	rm -f ./ibmswtpm2/tpm_server
	make revert_patch REPO=$(SWTPM_REPO) PATCH=$(SWTPM_PATCH_FILE)

install: wolf_install swtpm_install
	touch INSTALLED

clean: wolf_clean swtpm_clean
	rm -f INSTALLED

.PHONY: install clean
