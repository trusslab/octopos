

To run on your PC:
sudo ifconfig enp0s25 192.168.0.1 netmask 255.255.255.0 up
sudo arp -s 192.168.0.10 00:0a:35:00:22:01
sudo ethtool --offload  enp0s25  rx off  tx off


To run on the petalinux:
ifconfig eth0 down
ifconfig eth0 hw ether 00:0a:35:00:22:01
ifconfig eth0 up

ifconfig eth0 192.168.0.10 netmask 255.0.0.0
ip route add 192.168.0.1 dev eth0
~
