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

  - octopos/include/octopos/mailbox.h -> untrusted_linux/include/octopos/mailbox.h
  - octopos/include/octopos/runtime.h -> untrusted_linux/include/octopos/runtime.h
  - octopos/include/octopos/syscall.h -> untrusted_linux/include/octopos/syscall.h
  - octopos/include/octopos/error.h -> untrusted_linux/include/octopos/error.h
  - octopos/include/octopos/storage.h -> untrusted_linux/include/octopos/storage.h
  - octopos/include/runtime/runtime.h -> untrusted_linux/include/octopos/runtime/runtime.h
  - octopos/include/runtime/storage_client.h -> untrusted_linux/drivers/block/octopos_blk/storage_client.h
  - octopos/runtime/storage_client.c -> untrusted_linux/drivers/block/octopos_blk/storage_client.c
  - octopos/include/runtime/network_client.h -> untrusted_linux/drivers/net/network_client.h
  - octopos/runtime/network_client.c -> untrusted_linux/drivers/net/network_client.c
  - octopos/arch/umode/include/arch/syscall.h -> untrusted_linux/include/octopos/syscall_umode.h
  - octopos/arch/umode/include/arch/mailbox.h -> untrusted_linux/include/octopos/mailbox_umode.h
  - octopos/include/octopos/io.h -> untrusted_linux/include/octopos/io.h

In addition, here's where the files under untrusted/ map to in the Linux source tree:

  - octopos/untrusted/octopos_mailbox.c -> untrusted_linux/arch/um/drivers/octopos_mailbox.c
  - octopos/untrusted/octopos_mailbox_interface_user.c -> untrusted_linux/arch/um/os-Linux/drivers/octopos_mailbox_interface_user.c
  - octopos/untrusted/octopos_blk_drv.c -> untrusted_linux/drivers/block/octopos_blk/octopos_blk_drv.c
  - octopos/untrusted/octopos_net.c -> untrusted_linux/drivers/net/octopos_net.c
  - octopos/untrusted/octopos_net.h -> untrusted_linux/include/net/octopos_net.h
