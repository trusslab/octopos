DIRS := applications arch keyboard os runtime serial_out storage network bluetooth bootloader installer util/tpm/tpm_shutdown
DIRS_CLEAN := applications arch keyboard os runtime serial_out storage network bluetooth util/network bootloader installer util/tpm/tpm_shutdown

EXTERNAL_DIR := ./external

umode:
	./sync_untrusted_linux.sh
	for dir in $(DIRS); do \
		$(MAKE) umode -C $$dir; \
	done
	./installer/install.sh

install: 
	$(MAKE) install -C $(EXTERNAL_DIR)

clean:
	for dir in $(DIRS_CLEAN); do \
		$(MAKE) clean -C $$dir; \
	done

uninstall-local:
	rm NVChip
	$(MAKE) uninstall-local -C $(EXTERNAL_DIR)

clean_sechw:
	rm -f ${PETALINUX_PRODUCTS}/system_mb*.bit
	rm -f ${OCTOPOS_DIR}/bin/rootfs.img
	rm -rf ${OCTOPOS_DIR}/bin/rootfs_mount
	rm -f ${OCTOPOS_DIR}/storage/storage.srec
	rm -f ${OCTOPOS_DIR}/os/os.srec
	rm -f ${OCTOPOS_DIR}/serial_out/serial_out.srec
	rm -f ${OCTOPOS_DIR}/keyboard/keyboard.srec
	rm -f ${OCTOPOS_DIR}/runtime/runtime1.srec
	rm -f ${OCTOPOS_DIR}/runtime/runtime2.srec
	rm -f ${OCTOPOS_DIR}/installer_sec_hw/installer
	rm -f ${OCTOPOS_DIR}/storage/octopos_partition_*

sechw:
	mkdir -p ${OCTOPOS_DIR}/bin

	if [[ ${PETALINUX_PRODUCTS} == ${OCTOPOS_DIR}* ]]; then
		echo "PETALINUX_PRODUCTS is local"
	else
		cp -r ${PETALINUX_PRODUCTS%/} ${OCTOPOS_DIR}/bin/
		echo "Copying PETALINUX_PRODUCTS to local"
	fi

	echo "Merging bootloaders into bitstream..."
	${VITIS_INSTALLATION}/2020.1/bin/updatemem -bit ${HW_DESIGN_WITH_ARBITTER}/zcu102_octopos.runs/impl_1/design_1_wrapper.bit \
	-meminfo ${HW_DESIGN_WITH_ARBITTER}/zcu102_octopos.runs/impl_1/design_1_wrapper.mmi \
	-data ${VITIS_BOOTLOADERS}/serialout_bootloader/Debug/serialout_bootloader.elf \
	-proc design_1_i/secure_serial_out/microblaze_0 \
	-out ${PETALINUX_PRODUCTS}/system_mb0.bit -force
	${VITIS_INSTALLATION}/2020.1/bin/updatemem -bit ${PETALINUX_PRODUCTS}/system_mb0.bit \
	-meminfo ${HW_DESIGN_WITH_ARBITTER}/zcu102_octopos.runs/impl_1/design_1_wrapper.mmi \
	-data ${VITIS_BOOTLOADERS}/keyboard_bootloader/Debug/keyboard_bootloader.elf \
	-proc design_1_i/secure_serial_in/microblaze_1 \
	-out ${PETALINUX_PRODUCTS}/system_mb1.bit -force
	${VITIS_INSTALLATION}/2020.1/bin/updatemem -bit ${PETALINUX_PRODUCTS}/system_mb1.bit \
	-meminfo ${HW_DESIGN_WITH_ARBITTER}/zcu102_octopos.runs/impl_1/design_1_wrapper.mmi \
	-data ${VITIS_BOOTLOADERS}/enclave0_bootloader/Debug/enclave0_bootloader.elf \
	-proc design_1_i/enclave0_subsys/microblaze_2 \
	-out ${PETALINUX_PRODUCTS}/system_mb2.bit -force
	${VITIS_INSTALLATION}/2020.1/bin/updatemem -bit ${PETALINUX_PRODUCTS}/system_mb2.bit \
	-meminfo ${HW_DESIGN_WITH_ARBITTER}/zcu102_octopos.runs/impl_1/design_1_wrapper.mmi \
	-data ${VITIS_BOOTLOADERS}/enclave1_bootloader/Debug/enclave1_bootloader.elf \
	-proc design_1_i/enclave1_subsys/microblaze_3 \
	-out ${PETALINUX_PRODUCTS}/system_mb3.bit -force
	${VITIS_INSTALLATION}/2020.1/bin/updatemem -bit ${PETALINUX_PRODUCTS}/system_mb3.bit \
	-meminfo ${HW_DESIGN_WITH_ARBITTER}/zcu102_octopos.runs/impl_1/design_1_wrapper.mmi \
	-data ${VITIS_BOOTLOADERS}/storage_bootloader/Debug/storage_bootloader.elf \
	-proc design_1_i/storage_subsystem/microblaze_4 \
	-out ${PETALINUX_PRODUCTS}/system_mb4.bit -force
	${VITIS_INSTALLATION}/2020.1/bin/updatemem -bit ${PETALINUX_PRODUCTS}/system_mb4.bit \
	-meminfo ${HW_DESIGN_WITH_ARBITTER}/zcu102_octopos.runs/impl_1/design_1_wrapper.mmi \
	-data ${VITIS_BOOTLOADERS}/os_bootloader/Debug/os_bootloader.elf \
	-proc design_1_i/OS_subsys/microblaze_6 \
	-out ${PETALINUX_PRODUCTS}/system_mb6.bit -force

	echo "Building final boot image..."
	${VITIS_INSTALLATION}/2020.1/bin/bootgen \
	-image ${OCTOPOS_DIR}/arch/sec_hw/bootgen/output.bif \
	-arch zynqmp -o ${OCTOPOS_DIR}/bin/BOOT.bin -w on

	echo "Building Untrusted domain rootfs..."
	rm -f ${OCTOPOS_DIR}/bin/rootfs.img
	rm -rf ${OCTOPOS_DIR}/bin/rootfs_mount
	dd if=/dev/zero of=${OCTOPOS_DIR}/bin/rootfs.img bs=512 count=65536
	mkfs.ext4 -F ${OCTOPOS_DIR}/bin/rootfs.img
	mkdir ${OCTOPOS_DIR}/bin/rootfs_mount
	sudo mount ${OCTOPOS_DIR}/bin/rootfs.img ${OCTOPOS_DIR}/bin/rootfs_mount
	cd ${OCTOPOS_DIR}/bin/rootfs_mount && sudo -s pax -rvf ${PETALINUX_PRODUCTS}/rootfs.cpio
	sudo umount ${OCTOPOS_DIR}/bin/rootfs_mount

	echo "Building all PL domains..."
	${VITIS_INSTALLATION}/2020.1/gnu/microblaze/lin/bin/mb-objcopy \
	-O srec ${VITIS_DOMAINS}/storage/Debug/storage.elf ${OCTOPOS_DIR}/storage/storage.srec
	${VITIS_INSTALLATION}/2020.1/gnu/microblaze/lin/bin/mb-objcopy \
	-O srec ${VITIS_DOMAINS}/oss/Debug/oss.elf ${OCTOPOS_DIR}/os/os.srec
	${VITIS_INSTALLATION}/2020.1/gnu/microblaze/lin/bin/mb-objcopy \
	-O srec ${VITIS_DOMAINS}/serialout/Debug/serialout.elf ${OCTOPOS_DIR}/serial_out/serial_out.srec
	${VITIS_INSTALLATION}/2020.1/gnu/microblaze/lin/bin/mb-objcopy \
	-O srec ${VITIS_DOMAINS}/keyboard/Debug/keyboard.elf ${OCTOPOS_DIR}/keyboard/keyboard.srec
	${VITIS_INSTALLATION}/2020.1/gnu/microblaze/lin/bin/mb-objcopy \
	-O srec ${VITIS_DOMAINS}/enclave0/Debug/enclave0.elf ${OCTOPOS_DIR}/runtime/runtime1.srec
	${VITIS_INSTALLATION}/2020.1/gnu/microblaze/lin/bin/mb-objcopy \
	-O srec ${VITIS_DOMAINS}/enclave1/Debug/enclave1.elf ${OCTOPOS_DIR}/runtime/runtime2.srec

	echo "Installing binaries into local octopos filesystem..."
	cd ${OCTOPOS_DIR}/installer_sec_hw && make
	${OCTOPOS_DIR}/installer_sec_hw/installer

install_sechw_boot: 
	rm ${BOOT_MEDIA}/*
	cp ${PETALINUX_PRODUCTS}/boot.scr ${BOOT_MEDIA}/
	cp ${OCTOPOS_DIR}/bin/BOOT.bin ${BOOT_MEDIA}/
	cp ${PETALINUX_PRODUCTS}/image.ub ${BOOT_MEDIA}/
	sync
	echo "Done. Please remove media."

install_sechw_storage: 
	rm ${SEC_STORAGE_MEDIA}/*
	cp ${OCTOPOS_DIR}/bin/rootfs.img ${SEC_STORAGE_MEDIA}/octopos_partition_1_data
	echo -n "" > ${SEC_STORAGE_MEDIA}/octopos_partition_1_create
	cp ${OCTOPOS_DIR}/storage/octopos_partition_0_* ${SEC_STORAGE_MEDIA}/
	echo -n "" > ${SEC_STORAGE_MEDIA}/octopos_partition_1_create
	sync
	echo "Done. Please remove media."

.PHONY: umode sechw clean install
