===============================
OctopOS Trusted Platform Module
===============================

:Author: - Mingyi Chen <mingyic4@uci.edu>

The Trusted Platform Module (TPM) in OctopOS supports module integrity verification.

Setting up the TPM dependencies
===============================
We emulate the TPM in OctopOS using the TPM2.0 simulator provided by IBM. And we use the wolfTPM library to communicate with the TPM. They have been included in OctopOS as submodules under external/.

To build the emulator and the library, you need to install the following packages:

- build-essential
- git
- autoconf
- libtool
- libssl-dev

On Ubuntu, you could use the following command:

$ sudo apt -y install build-essential git autoconf libtool libssl-dev

Then use the following command to build and install the emulator and the library:

$ make install

Potential problems
==================
To be added.
