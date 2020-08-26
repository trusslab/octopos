========================
OctopOS Untrusted Domain
========================

:Author: - Ardalan Amiri Sani <arrdalan@gmail.com>

The untrusted domain runs an existing OS.
However, this OS needs to ask the OS for access to I/O services.

Setting up Linux for the untrusted domain
=========================================
The untrusted domain shares a lot of functionality with the secure runtime. 
Therefore, they share a lot of code.
Here's a list of shared files for Linux (UML mode used in OctopOS umode):

  - octopos/include/octopos/mailbox.h -> linux/include/octopos/mailbox.h
  - octopos/include/octopos/runtime.h -> linux/include/octopos/runtime.h
  - octopos/include/octopos/syscall.h -> linux/include/octopos/syscall.h
  - octopos/include/octopos/syscall.h -> linux/include/octopos/error.h
  - octopos/include/octopos/syscall.h -> linux/include/octopos/storage.h
  - octopos/include/runtime/runtime.h -> linux/drivers/block/octopos_blk/runtime.h
  - octopos/include/runtime/storage_client.h -> linux/drivers/block/octopos_blk/storage_client.h
  - octopos/runtime/storage_client.c -> linux/drivers/block/octopos_blk/storage_client.c

In addition, here's where the files under untrusted/ map to in the Linux source tree:

  - octopos/untrusted/octopos_mailbox -> linux/arch/um/drivers/octopos_mailbox.c
  - octopos/untrusted/octopos_mailbox_interface_user.c -> linux/arch/um/os-Linux/drivers/octopos_mailbox_interface_user.c
  - octopos/untrusted/octopos_blk_drv.c -> linux/drivers/block/octopos_blk/octopos_blk_drv.c
