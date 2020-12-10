============
OctopOS Boot
============

:Author: - Ardalan Amiri Sani <arrdalan@gmail.com>

Here, we discuss the process of booting the system in OctopOS. We do not discuss how bootloaders are loaded into the processors here and mainly focus on the process afterwards. All images are stored in the storage medium and hence need to be read through the storage service. Therefore, the storage service and the OS (which manages access to services) play critical roles in this process. The booting process works as follows.

First, bootloaders are executed in all of the processes.

Second, the bootloader of the storage service directly reads the storage service image from the storage medium and executes it. Before executing it, it sends its measurement to the TPM. However, the storage processor does not have access to the TPM queues in the beginning. Therefore, it waits for the access (which is granted by the OS bootloader as discussed next).

Third, the bootloader of the OS delegates the TPM_IN queue to the storage processor so that it can fully boot. It then uses the storage queues to read the OS image from the boot partition through the storage service and boot it. The OS bootloader is equipped with the OctopOS file system and hence can read files off the boot partition. The OS bootloader sends the measurement of the OS image to TPM before executing it.

Finally, the bootloaders of other processors wait for access to the storage queues. The OS grants them the access one by one. Each bootloader, upon receiving access to the STORAGE_DATA_OUT queue, reads its own image from the boot partition. The OS uses its file system to send commands to the storage service on what blocks to send onto its DATA_OUT queue (which are read by the bootloaders). Moreover, these processors infer the number of blocks that they need to read through mailbox attestation. Each processor sends the measurement of the image to TPM before loading it. For this, it waits for access to the TPM_IN queue granted by the OS.

A few issues are noteworthy.

Note 1: For the untrusted domain, the bootloader loads the Linux kernel. The root file system of the untrusted domain is hosted as a separate partition in OctopOS storage service as well. The Linux kernel uses OctopOS block driver to access its root fs.

Note 2: The installer program prepares the data for the boot partition. It initializes the OctopOS file system in this partition and copies all the images to it. Therefore, three programs in our source code use the OctopOS file system: the OS, its bootloader, and the installer.
