=======================
OctopOS SecHw Petalinux
=======================

:Author: - Zephyr Yao <z.yao@uci.edu>

This guide covers the Petalinux setup for OctopOS Secure Hardware. 

Software versions
=================
Ubuntu 20.04
Xilinx tools 2020.1 (mixing different versions will not work)

Install Petalinux Dependencies
==============================
For v2020.1, please refer to newer guide (UG1144).

After installation, add "source <path-to-installed-PetaLinux>/settings.sh" to ~/.bashrc

Create Petalinux Project
========================
petalinux-create --type project -s /media/zephyr/d1s0/octopos/INSTALL/xilinx-zcu102-v2020.1-final.bsp --name untrusted

Sync Hardware
=============
After Vivado has done generating bitstreams, click File -> Export -> Export Hardware. The hdf file is in <Vivado_Proj_Path>/<Proj_Name.sdk>/\*.hdf.

Re-config every time when the hardware design changes. Note that the --get-hw-description takes the path of the directory that contains a hdf file, not the path to a hdf file.
petalinux-config --get-hw-description=<Path_to_sdk>

petalinux-config
================
After syncing hardware, run petalinux-config

#1 (by default) In settings, enable sd boot settings for both kernel(image.ub) and boot image

#2 In settings, change linux and uboot source to local

#3 (skip) In settings, select uart(0 or 1) and baud rate

To set the UART used by R5, goto the R5 BSP settings in the SDK. You can config stdout/stdin there.
Petalinux's UART setting is in "Subsystem AUTO Hardware Settings". However, this is not enough to prevent linux from accessing the other UART used by R5. Add the lines below to ./project-spec/meta-user/recipes-bsp/device-tree/files/system-user.dtsi (This file is only available after a petalinux-build).
	&uart1 {
		status="disabled";
	};

#4 In settings, select 2nd ethernet (axi), uncheck auto ip assignment

#5 (skip) In settings, select memory pa range (in case you need to reserve for other subsystems) under "Subsystem AUTO Hardware Settings" -> "Memory Settings".
It is difficult to limit the memory range for DDR controller (generated through MIG). Please see the questions below for the mapping details.
https://www.xilinx.com/support/answers/51790.html
https://forums.xilinx.com/t5/Memory-Interfaces-and-NoC/How-to-map-the-AXI4-address-to-the-ddr4-memory-address/td-p/954407

#6 (skip) In settings, avoid axi and interrupt conflicts.
Petalinux generates interrupt configurations for lines connected to pl_ps_irq0 and pl_ps_irq1 automatically. Therefore, R5 will no longer have access to these interrupts when Linux is booted.

To route an interrupt to R5, add the line below to ./project-spec/meta-user/recipes-bsp/device-tree/files/system-user.dtsi
/delete-node/ &<INTR_LINE_NAME0>

#7 (optional) To enable mkfs
petalinux-config -c rootfs:
	Filesystem Packages -> Base -> e2fsprogs

#8 Redirect rootfs
petalinux-config
Image Packaging Configuration -> Root filesystem type -> Choose SD Card
Set "Device node of SD device" to "/dev/octopos_blk"

#9 shrink kernel and rootfs size
================================
Remove these drivers/packages:

petalinux-config -c kernel
	Kernel driver: PCI bus; MTD; Serial ATA; SPI; GPIO; Multimedia; Sound; USB; LED; Virtio; Staging driver; extcon; Industrial IO; Reliability; Android; FPGA;

Remove these drivers/packages unless otherwise noted:

petalinux-config -c rootfs
	FS->base->fpga management; havged; mtd-utils

	(! SKIP) FS->Console->network

	FS->Console->Utils->pciutils

	Filesystem Packages  → devel  → run-postinsts (first one)

	Filesystem Packages  → misc  → eudev -> udev-extraconf

	(! DO NOT REMOVE THIS) Filesystem Packages  → misc  → packagegroup-core-boot

	Filesystem Packages  → misc  → packagegroup-core-ssh-dropbear

	Filesystem Packages  → misc  → tcf-agent

	Filesystem Packages  → misc  → watchdog-init

	(! SKIP) Filesystem Packages  → net; Filesystem Packages  → network

	Filesystem Packages  → power management -> hellopm

	Image features: ssh-server-dropbear, hwcodecs, debug-tweaks


#10 
	cp <octopos_repo>/arch/sec_hw/untrusted/system-user.dtsi ./project-spec/meta-user/recipes-bsp/device-tree/files/system-user.dtsi

If the target folder does not exist, 1) petalinux-build, 2) copy, and 3) petalinux-build again.

Build Petalinux
===============
petalinux-build. 

Post-build Configs (SKIP)
=========================
Note: we have added a pre-configured dtsi file to octopos repo because large amount of clk, intr, and naming changes are made to the device tree. USE THE FILE COMES WITH OCTOPOS SOURCE, AND SKIP THIS STEP.

After build, there will be two dtsi files
./components/plnx_workspace/device-tree/device-tree/pl.dtsi

./project-spec/meta-user/recipes-bsp/device-tree/files/system-user.dtsi

pl.dtsi is not editable. It will be flushed at build time.

In system-user.dtsi, apply the changes pending in the "Configurations" step.

1) disable uart, interrupt, memory and other resources that are NOT used by this petalinux (see "Configurations" step)

2) disable amba_pl

3) copy pl.dtsi and paste at the end of system-user.dtsi

4) add interrupt-names, interrupt-parent, interrupts, for each mailbox control interface



Troubleshooting
===============
#1 If serial input is not working, disable Hardware Flow Control prior to powering the board, and disconnect JTAG cable.

#2 Unlike umode, sec_hw Untrusted domain need to manually run,
while true; do source /dev/octopos_mailbox | xargs echo \"@\" > /dev/octopos_mailbox; done

Installation guide for Petalinux v2019.1
========================================
We originally develop based on v2019.1. If the older version is ever needed, please follow the steps below.

Please refer to UG1144(v2019.1) for dependencies and installation guide.
https://www.xilinx.com/support/documentation/sw_manuals/xilinx2019_1/ug1144-petalinux-tools-reference-guide.pdf

Errata: 
On Page 11, correct dependencies:
	sudo apt-get install -y gcc git make net-tools libncurses5-dev tftpd zlib1g-dev libssl-dev flex bison libselinux1 gnupg wget diffstat chrpath socat xterm autoconf libtool tar unzip texinfo zlib1g-dev gcc-multilib build-essential zlib1g:i386 screen pax gzip gawk

On page 12, it says,
"Note: Do not change the installer permissions to CHMOD 775 as it can cause BitBake errors."

"chmod 764" works.

The correct Petalinux bsp is, xilinx-zcu102-v2019.1-final.bsp. Do not use other revisions.
