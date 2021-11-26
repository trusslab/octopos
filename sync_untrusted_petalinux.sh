 cp include/octopos/mailbox.h ../petalinux_proj/linux-xlnx/include/octopos/mailbox.h
 cp include/octopos/runtime.h ../petalinux_proj/linux-xlnx/include/octopos/runtime.h
 cp include/octopos/syscall.h ../petalinux_proj/linux-xlnx/include/octopos/syscall.h
 cp include/octopos/error.h ../petalinux_proj/linux-xlnx/include/octopos/error.h
 cp include/octopos/storage.h ../petalinux_proj/linux-xlnx/include/octopos/storage.h
 cp include/runtime/runtime.h ../petalinux_proj/linux-xlnx/include/octopos/runtime/runtime.h
 cp include/runtime/storage_client.h ../petalinux_proj/linux-xlnx/drivers/block/octopos_blk/storage_client.h
 cp runtime/storage_client.c ../petalinux_proj/linux-xlnx/drivers/block/octopos_blk/storage_client.c
 cp arch/sec_hw/untrusted/octopos_mailbox.c ../petalinux_proj/linux-xlnx/drivers/octopos/octopos_mailbox.c
 cp arch/sec_hw/untrusted/octopos_mailbox_hw.c ../petalinux_proj/linux-xlnx/drivers/octopos/octopos_mailbox_hw.c
#cp include/runtime/network_client.h ../petalinux_proj/linux-xlnx/drivers/net/network_client.h
#cp runtime/network_client.c ../petalinux_proj/linux-xlnx/drivers/net/network_client.c

cp untrusted/octopos_blk_drv.c ../petalinux_proj/linux-xlnx/drivers/block/octopos_blk/octopos_blk_drv.c
#cp untrusted/octopos_net.c ../petalinux_proj/linux-xlnx/drivers/net/octopos_net.c
#cp untrusted/octopos_net.h ../petalinux_proj/linux-xlnx/include/net/octopos_net.h
cp arch/sec_hw/include/arch/syscall.h ../petalinux_proj/linux-xlnx/include/octopos/syscall_sechw.h
