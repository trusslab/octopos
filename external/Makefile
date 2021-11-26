install: tss abrmd emu

tss:
	cd tpm2-tss/files/tss && ./bootstrap
	cd tpm2-tss/files/tss && ./configure --disable-doxygen-doc
	make -j$(nproc) -C ./tpm2-tss/files/tss
	sudo make install -C ./tpm2-tss/files/tss
	sudo udevadm control --reload-rules && sudo udevadm trigger && sudo ldconfig

abrmd:
	cd tpm2-abrmd/files/abrmd && ./bootstrap
	cd tpm2-abrmd/files/abrmd && ./configure \
		--with-dbuspolicydir=/etc/dbus-1/system.d \
		--with-systemdsystemunitdir=/lib/systemd/system \
		--with-systemdpresetdir=/lib/systemd/system-preset
	make -j$(nproc) -C ./tpm2-abrmd/files/abrmd
	sudo make install -C ./tpm2-abrmd/files/abrmd
	sudo ldconfig && sudo pkill -HUP dbus-daemon && sudo systemctl daemon-reload

emu:
	make -j$(nproc) -C ./ibmtpm/files/emu
	mv ./ibmtpm/files/emu/tpm_server ./ibmtpm/tpm_server

clean:
	make clean -C ./tpm2-tss/files/tss
	make clean -C ./tpm2-abrmd/files/abrmd
	make clean -C ./ibmtpm/files/emu

uninstall:
	make uninstall -C ./tpm2-abrmd/files/abrmd
	make uninstall -C ./tpm2-tss/files/tss
	rm ./ibmtpm/files/tpm_server

uninstall-local:
	make uninstall-local -C ./tpm2-tss/files/tss
