===================================
OctopOS Secure Hardware Vitis Setup
===================================

:Authors: - Zephyr Yao (z.yao@uci.edu)

Vitis project overview
======================
Vitis SDK is a Java-based IDE for devloping software on top of FPGA designs. Given a FPGA design, Vitis SDK prepares a development environment, including library OS and compiler chain for any recognized processors in the FPGA design, including PS cores and PL cores. 

Due to unknown error with Vitis SDK, hardware design changes invalidates the Vitis SDK design wrappers, causing "Platform Out-of-date" error and compilation failures. This error is reproduced accross several machines. We see similar errors on the Xilinx forum, 

https://support.xilinx.com/s/question/0D52E00006hpX0BSAU/platform-outofdate?language=en_US

https://support.xilinx.com/s/question/0D52E00006hpKp0SAE/vitis-force-and-update-of-xparametersh-after-vivado-hw-updates?language=en_US

We tried the solutions in these answer records, but unfortunately they do not solve the problem. Our guess is that the changes we made to the design wrapper (such as the Standalone library OS's interrupt handler, PMOD device driver, etc.) may have further confused Vitis and results in an invalid state when hardware design changes, which also updates the design wrapper. 

To workaround this issue, we came up with a semi-automatic way to build Vitis project from scratch. This process is needed at the first time of building OctopOS and repeated everytime the hardware design is changed. 

There is one Vitis project for all the bootloaders and another Vitis project for all the domains (which bootloader loads). The bootloader binaries will be written to as the BRAM's initial content in the bitstream, and the domain binaries will be converted into srec files and be stored to OctopOS secure storage. This process is automatically done by OctopOS Makefile.

Steps to re-create Vitis project
================================

Please refer to Step 6-23 in OctopOS Hardware setup guide,
https://github.com/trusslab/octopos_hardware/blob/main/README.md

Useful Debug Tips
-----------------
On the right corner of Vitis IDE, you can toggle to debug view. By default, debug view will not be enabled until you launch the project through this Vitis IDE window.

To use debug view, you can create a dummy launch profile and launch it on the hardware. The dummy launch profile may not properly run OctopOS on hardware without other components in the sec_hw Makefile. However, it is enough for Vitis IDE to enable debug view.

To create a launch profile, double click any subsystem (for example, storage_system in the octopos_proj_dom project), single click the first item opened for that subsystem (e.g., storage with a `c` icon on the left), right-click it, and then click Run as->Run configurations.

In the Launch window, double click `Single Application Debug`, right click the debugger below it (make sure it's not gdb debug), click Duplicate.
In the duplicate window, select not to use FSBL, and keep everything else default except for Target Setup. In Target Setup, enable all FPGA cores by clicking the checkbox at each line. 

Debug hardware exception
------------------------
If a Microblaze halt due to hardware exception (for example, accessing a register while the device is being reset / disconnected), or bad memory access, the debugger module will not turn address to line. You can use mb-objdump to get the annotated asm of the binary and find the crashing line.

mb-objdump is available at <Vitis_installation>/gnu/microblaze/lin/bin/mb-objdump -Ds <binary.elf>

Known Issues
============

Vitis stale build
-----------------

In rare cases, Vitis stop to track code changes and build stale binaries. If you suspect the binaries are stale, right-click each subsystem and select "clean" and then "build". Repeat for both the bootloader projects and the domain projects.

Grounding issues
----------------

The board must share ground with 1) TPM RaspberryPi, 2) serial debugging device (Arduino). If the ground is not shared, Serial communications will have a lot of noise, and the system will not work.

Connector issues
----------------

Loose connectors can cause TPM communication failure. PMOD connectors are usually stable, but if pushing SD card too many times (especially in wrong direction), PMOD connector can fail. Unplug and reconnect it if you suspect an issue.

JTAG affecting Untrusted Domain boot
------------------------------------

We noticed Petalinux sometimes won't boot when JTAG is connected. We recommand unplugging JTAG unless you need it to debug.

USB Serial issues
-----------------

Pay attention to hardware flow control (must be disabled) in the UART settings above. If it is not configured exactly as instructed, UART will fail to provide input to the board.

In rare cases, USB serial does not work. Exit everything and unplug everything, try again.
