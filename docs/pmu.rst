===========
OctopOS PMU
===========

:Author: - Ardalan Amiri Sani <arrdalan@gmail.com>

The Power Management Unit (PMU) has the following roles. These roles are currently based on the Umode implementation.

Role 1: it powers up all processors at boot time.

Role 2: it supports processor-triggered reboots. For example, when a runtime processors finishes executing an app and wants to reboot, the PMU takes care of that.

Role 3: it implements a command interface for the OS. The OS can ask the PMU to (1) shut down the system, (2) reboot the system, and (3) reset a specific processor.

A couple of note:

Note 1: when resetting a processor, the PMU resets the corresponding queues by sending command to the mailbox.

Note 2: For Role 3, PMU performs several security checks by querying the mailbox. PMU rejects the shutdown and reboot commands if there are any secure delegations (e.g., a runtime securely using the keyboard or using secure IPC). It also rejects the command to reset a specific processor if that processor is involved in any secure delegations.

Note 3: For the Umode emulator, the PMU process also acts as the terminal, passing inputs to the keyboard and receiving outputs from serial_out. It also routes the stdout of other processes to some FIFOs that can be read and displayed by the log_view program.
