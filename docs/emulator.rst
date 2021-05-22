======================
OctopOS Umode Emulator
======================

:Author: - Ardalan Amiri Sani <arrdalan@gmail.com>

The Umode emulator is an easy way to test OctopOS.

Setting up the emulator
=======================
After cloning the repo, fetch all its submodules using:

$ git submodule update --init --recursive

Then download a rootfs and copy to arch/umode/untrusted_linux/.
We recommend using CentOS6.x-AMD64-root_fs.
You can download it from http://fs.devloop.org.uk/

Then follow the "Setting up the TPM dependencies" instructions under docs/tpm.rst to download and build all TPM modules.

Build the emulator by running:

$ make umode

Running the emulator
====================
You can run the emulator using:

$ arch/umode/emulator/emulator.sh [octopos root directory absolute path]

For example, if you've cloned octopos to your home directory, do:

$ arch/umode/emulator/emulator.sh ~/octopos

Note that running the emulator requires tmuxp. You can install is as follows:

$ sudo apt-get install tmux
$ pip3 install tmuxp

Testing the emulator
====================
To use the emulator's shell, use the last window (bottom right) in the tmux panel.

To test secure applications, simply type their names in the shell, for example:

$ fs_test

or

$ secure_login

To send a command to the untrusted domain, use @cmd, for example:

$ @uname
