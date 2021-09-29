===================================
OctopOS Secure Hardware Vitis Setup
===================================

:Authors: - Zephyr Yao (z.yao@uci.edu)

Steps to re-create Vitis project
================================
#1 Launch Vitis, create a project called "octopos_proj".
This project will host all bootloaders.

Run ". mount_octopos.sh <path_to_octopos_repo> <path_to_octopos_proj>"

Create sub-projects using default settings, for corresponding microblazes:
"storage_bootloader, os_bootloader, keyboard_bootloader, serialout_bootloader, enclave0_bootloader, enclave1_bootloader"

#2 Lunch another Vitis window, create a project called "octopos_proj_dom".
This project will host all secure hardware domains.

Run ". mount_octopos.sh <path_to_octopos_repo> <path_to_octopos_proj_dom>"

Create sub-projects using default settings, for corresponding microblazes:
"storage, oss, keyboard, serialout, enclave0, enclave1"

Note: "oss" means "os". Vitis requires at least 3 chars for subproject name.

#3 Run ". vitis_setup.sh <path_to_octopos_proj> <path_to_octopos_proj_dom>"

#4 Follow instructions printed by vitis_setup.sh,
Edit c/c++ build settings, 1) add following -D, 2) add include, 3) optimize for size

Tricks we did (which are now part of the script)
================================================
1. Fix libsrc/Pmod Makefile and copy utility folder to include
2. Fix libsrc/DXSPIDVOL.cpp by defining XPAR_PMODSD_0_DEVICE_ID in xparameter.h