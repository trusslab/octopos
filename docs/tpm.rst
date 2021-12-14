===============================
OctopOS Trusted Platform Module
===============================

:Author: - Mingyi Chen <mingyic4@uci.edu>

The Trusted Platform Module (TPM) in OctopOS supports module integrity verification.

Setting up the TPM dependencies
===============================
The TPM relies on the functions provided by TPM2-TSS libraries and TPM2-ABRMD resource manager daemon.
They have been included in OctopOS as submodules under external/.

To build the TPM2-TSS library and TPM2-ABRMD daemon, you need to install the following packages:

- autoconf-archive
- libcmocka0
- libcmocka-dev
- procps
- iproute2
- build-essential
- git
- pkg-config
- gcc
- libtool
- automake
- libssl-dev
- uthash-dev
- autoconf
- doxygen
- libjson-c-dev
- libini-config-dev
- libcurl4-openssl-dev
- libgcrypt-dev
- libglib2.0-dev

On Ubuntu, you could use the following command:

$ sudo apt -y install autoconf-archive libcmocka0 libcmocka-dev procps \
    iproute2 build-essential git pkg-config gcc libtool automake libssl-dev \
    uthash-dev autoconf libjson-c-dev libini-config-dev \
    libcurl4-openssl-dev libgcrypt-dev libglib2.0-dev

Then use the following command to build and install the library:

$ make install

Remote mode
===========
TPM module is also designed to work in remote mode. The message is generated
and then sent to the mailbox. To enable remote mode, you need to set the

-DTPM_REMOTE

flag in the Makefile.

Potential problems
==================
Problem 1. Recipe for target 'tss' failed
Solution: The library is linked by submodule. You can type

$ git submodule update --init --recursive
to pull the entire contents.

Problem2. TPM is in DA lockout mode
Solution: Execute the tpm_shutdown in util/tpm/tools/ folder.

It was caused by abnormal shutdown of tpm that making the tpm don't receive
TPM_SHUTDOWN signal.

Update: tpm_shutdown does not always resolve the lockout problem.
For now, a temporary hack was added to the simulator.
To solve this issue correctly, we need to send the shutdown command to the TPM
everytime we halt OctopOS.

Problem 3. Integrity check failed
Solution: Execute the create_primary in util/tpm/tools/ folder.
