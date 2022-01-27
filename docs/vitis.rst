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

#1 Create a Vitis project for bootloaders
Step 1: (If you have not already done so) In Vivado, open the design. Navigate to File->Export->xsa file.
Step 2: Launch Vitis;
Step 3: Select a (new) path for Vitis project. We use `<xxx>/octopos_proj`;
Step 4: Import the hardware design by selecting the xsa file exported in Step 1.
Step 5: Create these subsystems:
	
storage_bootloader, 
os_bootloader, 
keyboard_bootloader, 
serialout_bootloader, 
enclave0_bootloader, 
enclave1_bootloader, 
network_bootloader

For each subsystem except storage_bootloader, select empty-project(c) as the template. For storage_bootloader, select empty-project(c++) as the template. Keep all other settings default. Please make sure to put each subsystem on correct FPGA cores, for example, storage_bootloader should be put on microblaze_storage. Adding subsystems might take a while.

#2 Create a Vitis project for domains
Step 1: Launch another Vitis;
Step 2: Select a (new, and diffrent from the Vitis project path for bootloaders) path for Vitis project. We use `<xxx>/octopos_proj_dom`;
Step 4: Import the hardware design by selecting the same xsa file exported previously.
Step 5: Create these subsystems:
	
storage, 
oss, 
keyboard, 
serialout, 
enclave0, 
enclave1,
network

Note: "oss" means "os". Vitis requires at least 3 chars for subproject name.

For each subsystem except storage, select empty-project(c) as the template. For storage, select empty-project(c++) as the template. Keep all other settings default. Please make sure to put each subsystem on correct FPGA cores, for example, storage should be put on microblaze_storage. Adding subsystems might take a while.

#3 Mount OctopOS
Run ". mount_octopos.sh <path_to_octopos_repo> <path_to_octopos_proj>"
Run ". mount_octopos.sh <path_to_octopos_repo> <path_to_octopos_proj_dom>"

This will mount OctopOS code to each repositories. Changes to the code in `<path_to_octopos_repo>` will be synced to Vitis project.

#4 Patching design wrapper
Run ". vitis_setup.sh <path_to_octopos_proj> <path_to_octopos_proj_dom>"

Our script automatically patches the design wrapper, which do these behind the scene,

1. Fix libsrc/Pmod Makefile and copy utility folder to include
2. Replace all linkers to use our rom fuse and memory layout.
3. Fix libsrc/DXSPIDVOL.cpp by defining XPAR_PMODSD_0_DEVICE_ID in xparameter.h
4. Replace all interrupt handlers.

#5 Update build settings
For each subsystem (in both bootloader project and domain project), edit c/c++ build settings. To open c/c++ build settings, double click any subsystem (for example, storage_system in the octopos_proj_dom project), single click the first item opened for that subsystem (e.g., storage with a `c` icon on the left), right-click it, and select c/c++ build settings. 
1) add definitions below, 

Storage Bootloader
ARCH_SEC_HW_BOOT ARCH_SEC_HW PROJ_CPP ARCH_SEC_HW_BOOT_STORAGE ARCH_SEC_HW_STORAGE
OS Bootloader
ARCH_SEC_HW ARCH_SEC_HW_OS ARCH_SEC_HW_BOOT ARCH_SEC_HW_BOOT_OS
keyboard Bootloader
ARCH_SEC_HW ARCH_SEC_HW_KEYBOARD ARCH_SEC_HW_BOOT ARCH_SEC_HW_BOOT_KEYBOARD ARCH_SEC_HW_BOOT_OTHER
Serialout Bootloader
ARCH_SEC_HW ARCH_SEC_HW_SERIAL_OUT ARCH_SEC_HW_BOOT ARCH_SEC_HW_BOOT_SERIAL_OUT ARCH_SEC_HW_BOOT_OTHER
Enclave0 Bootloader
ARCH_SEC_HW ARCH_SEC_HW_RUNTIME ARCH_SEC_HW_BOOT ARCH_SEC_HW_BOOT_RUNTIME_1 ARCH_SEC_HW_BOOT_OTHER RUNTIME_ID=1
Enclave1 Bootloader
ARCH_SEC_HW ARCH_SEC_HW_RUNTIME ARCH_SEC_HW_BOOT ARCH_SEC_HW_BOOT_RUNTIME_2 ARCH_SEC_HW_BOOT_OTHER RUNTIME_ID=2
Network Bootloader
ARCH_SEC_HW ARCH_SEC_HW_NETWORK ARCH_SEC_HW_BOOT ARCH_SEC_HW_BOOT_OTHER ARCH_SEC_HW_BOOT_NETWORK

Storage
ARCH_SEC_HW PROJ_CPP ARCH_SEC_HW_STORAGE
OS
ARCH_SEC_HW ARCH_SEC_HW_OS ROLE_OS
keyboard
ARCH_SEC_HW_KEYBOARD
Serialout
ARCH_SEC_HW_SERIAL_OUT
Enclave0
RUNTIME_ID=1 ARCH_SEC_HW ARCH_SEC_HW_RUNTIME
Enclave1
RUNTIME_ID=2 ARCH_SEC_HW ARCH_SEC_HW_RUNTIME
Network
ARCH_SEC_HW ARCH_SEC_HW_NETWORK HW_MAILBOX_BLOCKING
2) add include paths: `<octopos>/arch/include` and `<octopos>/include`, 
3) select `optimize for size`
4) Upon exit from each subsystem c/c++ setting, Vitis will ask you if you want to build it right away. Select No, and we will build all of them later.

#6 Build all
Select all subsystems in a project, right-click, select `Build`. The initial build may take longer.

#7 Debug
On the right corner of Vitis IDE, you can toggle to debug view. By default, debug view will not be enabled until you launch the project through this Vitis IDE window.
To use debug view, you can create a dummy launch profile and launch it on the hardware. The dummy launch profile may not properly run OctopOS on hardware without other components in the sec_hw Makefile. However, it is enough for Vitis IDE to enable debug view.

To create a launch profile, double click any subsystem (for example, storage_system in the octopos_proj_dom project), single click the first item opened for that subsystem (e.g., storage with a `c` icon on the left), right-click it, and then click Run as->Run configurations.
In the Launch window, double click `Single Application Debug`, right click the debugger below it (make sure it's not gdb debug), click Duplicate.
In the duplicate window, select not to use FSBL, and keep everything else default except for Target Setup. In Target Setup, enable all FPGA cores by clicking the checkbox at each line. 

#8 Debug hardware exception
If a Microblaze halt due to hardware exception (for example, accessing a register while the device is being reset / disconnected), or bad memory access, the debugger module will not turn address to line. You can use mb-objdump to get the annotated asm of the binary and find the crashing line.
mb-objdump is available at <Vitis_installation>/gnu/microblaze/lin/bin/mb-objdump -Ds <binary.elf>

#9 UART monitor
Open three terminals, and run `sudo minicom -s` on each of them.
In the first terminals, configure as ttyUSB0 - 115200 - no hardware flow control
In the second terminals, configure as ttyUSB2 - 9600 - no hardware flow control
In the first terminals, configure as ttyACM0 - 115200 - yes hardware flow control
Note that your tty serial number may be different, replace ttyUSB0 with the first serial port from your board, and replace ttyUSB2 with the third port from your board, and replace ttyACM0 with the Arduino serial debugger port.

## Known Issues

#1 TPM does not respond
Ctrl-C to quit the TPM client program, and launch it again. If the TPM client terminal shows no inbound hash, reboot the TPM.

#2 SD card failure
If the OctopOS system doesn't boot, first try to reprogram the SD cards and re-connect the cards to the board.

#3 Vitis stale build
In rare cases, Vitis stop to track code changes and build stale binaries. If you suspect the binaries are stale, right-click each subsystem and select "clean" and then "build". Repeat for both the bootloader projects and the domain projects.

#4 Grounding issues
The board must share ground with 1) TPM RaspberryPi, 2) serial debugging device (Arduino). If the ground is not shared, Serial communications will have a lot of noise, and the system will not work.

#5 Connector issues
Loose connectors can cause TPM communication failure. PMOD connectors are usually stable, but if pushing SD card too many times (especially in wrong direction), PMOD connector can fail. Unplug and reconnect it if you suspect an issue.

#6 JTAG affecting Untrusted Domain boot
We noticed Petalinux won't boot when JTAG is connected. The problem is gone. However, Untrusted domain may be able to access JTAG (which breaks isolation). We recommand unplugging JTAG unless you need it to debug.

#7 USB Serial issues
Pay attention to hardware flow control in the UART settings above. If it is not configured exactly as instructed, UART will fail to provide input to the board.
In rare cases, USB serial does not work. Exit everything and unplug everything, try again.
