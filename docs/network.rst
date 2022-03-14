

To run on your PC (some NICs are not supported):
sudo ifconfig enp0s25 192.168.0.1 netmask 255.255.255.0 up
sudo arp -s 192.168.0.10 00:0a:35:00:22:01
sudo ethtool --offload  enp0s25  rx off  tx off

To run on RaspPi4:
sudo ifconfig eth0 192.168.0.1 netmask 255.255.255.0 up
sudo arp -s 192.168.0.10 00:0a:35:00:22:01
sudo ethtool --offload  eth0  rx off  tx off
sudo sysctl -w net.ipv6.conf.eth0.disable_ipv6=1
sudo systemctl disable avahi-daemon
sudo systemctl stop avahi-daemon

To run on the petalinux:

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


# To test the conectivity run:
ping 192.168.0.1

# To test our echo server
on your PC run:
./applications/socket_server

on petalinux run:
telnet 192.168.0.1 12345


## How to reproduce performance experiments reported in paper:
1) Untrusted latency:
   ### run on petalinux after setting up and testing the connectivity: 
      ping 192.168.0.1
2) Untrusted throughput:
   ### run on your host machine:
   iperf3 -s
   ### run on petalinux after setting up and testing the connectivity:
   iperf3 -c 192.168.0.1
3) Trusted latency:
   ### on your host compile and run:
      applications/socket_client/socket_server_test_latency.c
   ### in socket_client.c application
   comment out:   send_receive(api);
   and uncomment: latency_test(api);
   compile run octopos and run socker_client
   (you might need to fine-tune the delay between read and write to prevent the test from failing,
   it is because our implementation of the network in sec_hw is single threaded and signaling between threads is not available.
   the amount of delay in the repo has fine tuned to its minimum to get the round-trip messages working with minimum delay on the testing set-up)

4) Trusted throughput:
   ### on your host compile and run:
      applications/socket_client/socket_server_test_throughput.c
   ### in socket_client.c application
   comment out:   send_receive(api);
   and uncomment: throuput_test(api);
   compile run octopos and run socker_client






