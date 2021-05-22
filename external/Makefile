install: tss abrmd emu

tss:
	cd tpm2-tss && ./bootstrap
	cd tpm2-tss && ./configure
	make -j$(nproc) -C ./tpm2-tss
	sudo make install -C ./tpm2-tss
	sudo udevadm control --reload-rules && sudo udevadm trigger && sudo ldconfig

abrmd:
	cd tpm2-abrmd && ./bootstrap
	cd tpm2-abrmd && ./configure \
		--with-dbuspolicydir=/etc/dbus-1/system.d \
		--with-systemdsystemunitdir=/lib/systemd/system \
		--with-systemdpresetdir=/lib/systemd/system-preset
	make -j$(nproc) -C ./tpm2-abrmd
	sudo make install -C ./tpm2-abrmd
	sudo ldconfig && sudo pkill -HUP dbus-daemon && sudo systemctl daemon-reload

emu:
	make -j$(nproc) -C ./ibmtpm/src
	mv ./ibmtpm/src/tpm_server ./ibmtpm/tpm_server

clean:
	make clean -C ./tpm2-tss
	make clean -C ./tpm2-abrmd
	make clean -C ./ibmtpm/src

uninstall:
	make uninstall -C ./tpm2-abrmd
	make uninstall -C ./tpm2-tss
	rm ./ibmtpm/tpm_server

uninstall-local:
	make uninstall-local -C ./tpm2-tss
