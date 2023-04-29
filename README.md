# OctopOS and the Split-Trust Hardware Design User Guide

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

After the [hardware prototype](https://github.com/trusslab/octopos_hardware) is built, we evaluate the OctopOS performance on the hardware prototype on a ZCU102 board.

### Boot Time

The boot time of OctopOS is measured by the resource manager domain. The resource manager domain prints time stamps of booting events, which can be used to evaluate the boot time of OctopOS. You can expect the following prints from the resource manager debug outputs:

```
Bootloader   <-- Resource manager bootloader starts
wait done    <-- Resource manager waits for storage domain to finish booting
main: OS init  <-- Resource manager is booted
RESET (BOOT) 0  <-- Resource manager resets the storage domain
init done  <-- Resource manager finishes initialization
keyboard XXX  <-- Resource manager helps the other domains to boot
serial XXX
net XXX
enclave0 XXX
enclave1 XXX
linux XXX
RESET (CREATE) 0  <-- Resource manager serves the untrusted domain's request to use storage (for rootfs)
```

The boot time of each domain is measured in the unit of milliseconds.

### TEE Storage Performance

After the booting is finished, type `storage_benchmark` (or the program name you defined in `https://github.com/trusslab/octopos/blob/main/arch/sec_hw/include/arch/preload_application_map.h`) to launch the storage benchmark. The enclave debug terminal will print the following results:

```
WriteReadYield(verify FO) Write XXX, Read XXX, Req XXX
```

The `Write`, `Read`, and `Yield` are printed at each stage of the benchmark. The `verify` is printed at the end of the benchmark, which indicates the written data has been read back for validation.
The time is measured in the unit of milliseconds.
We write and read 1MB of data (i.e., 512B per block, and approx. 2000 repetitions), and therefore, the read/write throughput is calculated as 1MB divided by the time.

### Untrusted Domain Storage Performance

After the booting is finished, open the untrusted domain terminal, and log in to the untrusted domain with username `root` and password `root`.

The following bash script is used to evaluate the untrusted domain storage performance.

```bash
# For write test
for i in 1 2 3 4 5 
do 
  echo 3 > /proc/sys/vm/drop_caches
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

Similar to the TEE storage experiment, we write 2000 blocks (512B per block), totaling 1MB of data. The read/write throughput is calculated as 1MB divided by the time.

### TEE Network Performance

Run the following commands on the computer connected to the board,

```bash
sudo ifconfig enp0s25 192.168.0.1 netmask 255.255.255.0 up
sudo arp -s 192.168.0.10 00:0a:35:00:22:01
sudo ethtool --offload  enp0s25  rx off  tx off
```

Then, build both the latency and throughput server program (located at `https://github.com/trusslab/octopos/tree/main/applications/socket_client`) on the computer. Launch the latency server on the computer.

After the board is booted, run the latency client by typing `socket_client` from the keyboard domain terminal.
Note that there are two functions, `latency_test` and `throughput_test` in `https://github.com/trusslab/octopos/blob/main/applications/socket_client/socket_client.c`. 
You can choose to run either of them by changing the `main` function. Alternatively, you can create separate programs for the latency and throughput tests, or create a program that runs both tests.

The latency server (running on the computer) will print the following results:

```
main; socket_server init
Waiting for a connection
Received a connection
Here is the first message (n = 1): 1
Here is the second message (n = 1): 2 time passed=XXX
```

The time is measured in the unit of microseconds. We notice the latency is higher in certain environments, possibly due to variations in the server's network stack and board factors (i.e., variation SFP adaptor and FPGA board).

### Untrusted Domain Network Performance

Before the experiment, we need to install `iperf` either through Petalinux configuration (preferred, see: https://support.xilinx.com/s/question/0D52E00006hpspsSAA/how-to-get-iperf3-into-petalinux-20171?language=en_US), or by building from source and copy the binary into the rootfs image.

Run the following commands on the computer connected to the board,

```bash
sudo ifconfig enp0s25 192.168.0.1 netmask 255.255.255.0 up
sudo arp -s 192.168.0.10 00:0a:35:00:22:01
sudo ethtool --offload  enp0s25  rx off  tx off
```

After the board is booted, open the untrusted domain, log in with username `root` and password `root`, and run the following commands,

```bash
# requste the network domain
echo 1 > /dev/octopos_network

# request a port from network domain
echo P 512 > /dev/octopos_network
# You can replace 512 with your desired port number

# setup IP and ethernet address
ifconfig eth0 down
ifconfig eth0 hw ether 00:0a:35:00:22:01
ifconfig eth0 up

ifconfig eth0 192.168.0.10 netmask 255.0.0.0
ip route add 192.168.0.1 dev eth0
```

To run the latency test, run the following commands on the untrusted domain,

```bash
ping 192.168.0.1
```

To run the throughput test, run the following commands,

```bash
### run on your host machine:
iperf3 -s
### run on petalinux::
iperf3 -c 192.168.0.1
```

`ping` and `iperf` will print the latency and throughput results, respectively.

### Mailbox Microbenchmark

We use a fixed timer interrupt to count the number of milliseconds passed. Note that it is possible to create a more accurate fixed timer (e.g., microsecond timer), but that would dramatically slow down the processor, i.e., 1 interrupt per 100 clock cycles on a 100MHz processor, and the interrupt handling would take approx. 50-100 clock cycles, rendering the processor unusable. Therefore, for the throughput experiment, we send 10000 messages (512B each) over the mailbox; and for latency measurement, we repeat it 10000 times and divide the millisecond measurement by 10000.

We provide a minimal hardware and software stack (https://github.com/trusslab/octopos_hardware/tree/main/simple_mailbox_test/) to measure the mailbox latency and throughput without using the full OctopOS hardware design. Note that the interrupt handling, Microblaze hardware configuration (see the hardware design), and compiler optimization level (we use `-Os (optimized for size)`, consistent with the domains in OctopOS hardware design) can affect the performance.

```
[1] init mailbox success
[2] finish PL-PL mbox measurement XXX ms
[3] finish PL-PL mbox latency (10000 times) XXX ms
[4] finish PS-PL box measurement XXX ms
[5] finish PS-PL mbox latency (10000 times) XXX ms
```

To calculate the latency, we divide the time (in [3] and [5], respectively for PL-PL and PS-PL) by 10000 and then times 1000 to get the latency in microseconds.

To calculate the throughput, we divide the amount of data (10000 * 512B) by the time (in [2] and [4], respectively for PL-PL and PS-PL) to get the throughput in B/ms, which can be converted to MB/s.