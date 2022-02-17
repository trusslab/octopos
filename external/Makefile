install: tss abrmd emu fin

tss:
	cd tpm2-tss/ && ./bootstrap
	cd tpm2-tss/ && ./configure --disable-doxygen-doc
	make -j$(nproc) -C ./tpm2-tss/
	sudo make install -C ./tpm2-tss/
	sudo udevadm control --reload-rules && sudo udevadm trigger && sudo ldconfig

abrmd:
	cd tpm2-abrmd/ && ./bootstrap
	cd tpm2-abrmd/ && ./configure \
		--with-dbuspolicydir=/etc/dbus-1/system.d \
		--with-systemdsystemunitdir=/lib/systemd/system \
		--with-systemdpresetdir=/lib/systemd/system-preset
	make -j$(nproc) -C ./tpm2-abrmd/
	sudo make install -C ./tpm2-abrmd/
	sudo ldconfig && sudo pkill -HUP dbus-daemon && sudo systemctl daemon-reload

emu:
	make -j$(nproc) -C ./ibmtpm/
	sudo cp ./ibmtpm/tpm_server /usr/local/bin/

fin:
	touch INSTALLED

clean:
	make clean -C ./tpm2-tss/
	make clean -C ./tpm2-abrmd/
	make clean -C ./ibmtpm/

uninstall:
	make uninstall -C ./tpm2-abrmd/
	make uninstall -C ./tpm2-tss/
	rm ./ibmtpm/tpm_server
	rm /usr/local/bin/tpm_server
	rm INSTALLED

uninstall-local:
	make uninstall-local -C ./tpm2-tss/
