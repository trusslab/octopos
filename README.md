# OctopOS and the Split-Trust Hardware Design User Guide

Authors: Zhihao "Zephyr" Yao, Seyed Mohammadjavad Seyed Talebi, Mingyi Chen, Ardalan Amiri Sani, Thomas Anderson
(Collectively, "The OctopOS Authors")

:paperclip: [OctopOS Paper *(to be updated)*]()
:orange_book: [OctopOS Technical Reference Manual](https://github.com/trusslab/octopos_hardware/raw/main/docs/OctopOS-TRM-2023-04-03.pdf)

:computer: [OctopOS Repository](https://github.com/trusslab/octopos)
:electric_plug: [Split-Trust Hardware Repository](https://github.com/trusslab/octopos_hardware)

:flashlight: [Formal Verification](https://github.com/trusslab/octopos_hardware/tree/main/formal_verification)
:beer: [Untrusted Domain Petalinux](https://github.com/trusslab/linux-xlnx)
:beer: [OctopOS Emulator](https://github.com/trusslab/octopos/blob/main/docs/emulator.rst)

To run OctopOS on ZCU102 board, please follow the instructions in the [Split-Trust Hardware Repository](https://github.com/trusslab/octopos_hardware).

To run OctopOS on our emulator, please follow the instructions in the [OctopOS Emulator](https://github.com/trusslab/octopos/blob/main/docs/emulator.rst).

## Hardware Prototype Evaluation 

The resource manager domain prints time stamps of booting events, which can be used to evaluate the boot time of OctopOS.

We provide the following apps for evaluating OctopOS I/O performance,
`storage_benchmark`, `(network) latency`, and `(network) throughput`.

The following bash script is used to evaluate the untrusted domain storage performance.

```bash
# For write test
/sbin/sysctl -w vm.drop_caches=3
for i in 1 2 3 4 5 
do 
  time dd if=/dev/zero of=./write bs=1b count=2000 
done 

# For read test
mkfs.vfat /dev/ram0

for i in 1 2 3 4 5
do
  echo 3 > /proc/sys/vm/drop_caches
  time dd if=./write of=/dev/ram0 bs=1b count=2000 
done
```