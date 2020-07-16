========================
OctopOS Storage Protocol
========================

:Author: - Ardalan Amiri Sani <arrdalan@gmail.com>

The storage service in OctopOS supports normal and secure access to storage partitions.

Secure Access to a Partition
============================
A secure app can use a secure partition as follows:

Step 1: the app asks the OS to allocate a partition to it using the SYSCALL_REQUEST_SECURE_STORAGE_CREATION syscall. 
The OS communicates with the storage service through its designated mailbox/channel and allocates an unused partition, if available.
It then sets a temporary lock key on the partition and returns it to the app when responding to the syscall.

Step 2: the app requests and receives secure access to the storage service.
That is, the app will have exclusive access to a mailbox/channel that it can use to talk to the service.

Step 3: the app uses the temporary key for the partition to unlock the partition through messages sents on its secure mailbox/channel.
It then sets a new key for the partition in order to prevent the OS from using the old key successfully to access the partition.
When done using the partition for the time being, the app locks the partition and then yields its exclusive access to the mailbox/channel.
The app can later unlock the partition and continue to use it assuming it can successfully get secure access to a mailbox/channel.

Step 4: when the app is fully done with the partition, it can wipe it.
This makes the partition available for others to use.

Other notes
===========
Note 1: upon reset, the storage service locks all in-use partitions.
This prevents unauthorized access after reboot.

Note 2: the OS can't reclaim in-use partitions.
To prevent a malicious app from never releasing a partition, a few solutions are possible:

  - Allow the user to directly send messages from the keyboard service to the storage service to delete some partitions.
  - Allow a special app to delete partitions.

OctopOS currently does not support either of these solutions.
Given that apps using these partitions are trusted and given the abundant storage space, this is not an urgent issue.
