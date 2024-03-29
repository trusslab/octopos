# Copyright (c) 2019 - 2023, The OctopOS Authors
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

mkdir arch/umode/untrusted_linux/include/os
cp include/octopos/mailbox.h arch/umode/untrusted_linux/include/octopos/mailbox.h
cp include/octopos/runtime.h arch/umode/untrusted_linux/include/octopos/runtime.h
cp include/octopos/syscall.h arch/umode/untrusted_linux/include/octopos/syscall.h
cp include/octopos/error.h arch/umode/untrusted_linux/include/octopos/error.h
cp include/octopos/storage.h arch/umode/untrusted_linux/include/octopos/storage.h
cp include/runtime/runtime.h arch/umode/untrusted_linux/include/octopos/runtime/runtime.h
cp include/runtime/storage_client.h arch/umode/untrusted_linux/drivers/block/octopos_blk/storage_client.h
cp runtime/storage_client.c arch/umode/untrusted_linux/drivers/block/octopos_blk/storage_client.c
cp include/runtime/network_client.h arch/umode/untrusted_linux/drivers/net/network_client.h
cp runtime/network_client.c arch/umode/untrusted_linux/drivers/net/network_client.c
cp untrusted/octopos_mailbox.c arch/umode/untrusted_linux/arch/um/drivers/octopos_mailbox.c
cp untrusted/octopos_mailbox_interface_user.c arch/umode/untrusted_linux/arch/um/os-Linux/drivers/octopos_mailbox_interface_user.c
cp untrusted/octopos_blk_drv.c arch/umode/untrusted_linux/drivers/block/octopos_blk/octopos_blk_drv.c
cp untrusted/octopos_net.c arch/umode/untrusted_linux/drivers/net/octopos_net.c
cp untrusted/octopos_net.h arch/umode/untrusted_linux/include/net/octopos_net.h
cp arch/umode/include/arch/syscall.h arch/umode/untrusted_linux/include/octopos/syscall_umode.h
cp arch/umode/include/arch/mailbox.h arch/umode/untrusted_linux/include/octopos/mailbox_umode.h
cp include/octopos/io.h arch/umode/untrusted_linux/include/octopos/io.h
cp include/os/network.h arch/umode/untrusted_linux/include/os/network.h
