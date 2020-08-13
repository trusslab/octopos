======================
OctopOS Umode Emulator
======================

:Author: - Ardalan Amiri Sani <arrdalan@gmail.com>

The Umode emulator is an easy way to test OctopOS.

Setting up the emulator
=======================
After cloning the repo and its submodules, go to the arch/umode/untrusted_linux/ and download a rootfs.
We recommend using OpenSuse-12.1-amd64-root_fs.
You can download it from http://fs.devloop.org.uk/

Running the emulator
====================
You can run the emulator using:

$ arch/umode/emulator/emulator.sh [octopos root directory absolute paty]

Once the emulator is loaded, enter the following command in the bottom window (the untrusted Linux domain):

$ while true; do source /dev/octopos_mailbox | xargs echo "@" > /dev/octopos_mailbox; done

Testing the emulator
====================
To use the emulator's shell, type in the keyboard window (the middle one in the top row).
The shell output will be seen in the serial_out window (the middle one in the second row).
To test secure applications, simply type their names in the shell, for example:

$ fs_test

or

$ secure_login

To send a command to the untrusted domain, use @cmd, for example:

$ @uname
