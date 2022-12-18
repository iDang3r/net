from scapy.all import *
import time

conf.use_pcap = True

ips = []
pc_ip = get_if_addr(conf.iface)
pc_mac = get_if_hwaddr(conf.iface)

#ip_net = '.'.join(pc_ip.split('.')[:-1]) + '.'
ip_net = "192.168.1."
for cur_ip in range(1, 254):
    print("cur_ip = ", cur_ip)
    ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff", src=pc_mac)
    address = ip_net + str(cur_ip)
    print(address)
    p = ethernet_frame / ARP(op=1, psrc = pc_ip, pdst = address, hwsrc = pc_mac)
    sendp(p)
    pack = sniff(filter='arp'.format(address), count=1, timeout=0.1)
    if pack:
        ip = pack[0].payload.psrc
        if ip == address:
            ips.append((address, str(pack[0].src)))
            print(str(ips[-1]))
    # time.sleep(1)

with open("local_ips.txt", "w") as f:
    f.write(str(ips))