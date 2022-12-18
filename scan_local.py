import os
import re
from scapy.all import *
from ipaddress import ip_address

def get_devices(log=False):
    devices = []
    for device in os.popen('arp -a'): 
        if device[0] != '?':
            device = re.match(r'(\S+) \((\S+)\) at (\S+)', device).groups()
            devices.append({
                'host_name': device[0],
                'ip': device[1],
                'mac': device[2],
            })
        else:
            device = re.match(r'\? \((\S+)\) at (\S+)', device).groups()
            if device[1] != '(incomplete)':
                devices.append({
                    'host_name': '?name? -> ip: ' + device[0] + (' ' * (15 - len(device[0]))) + ' mac: ' + device[1],
                    'ip': device[0],
                    'mac': device[1],
                })

    if log:
        for device in devices:
            print(device)

    return devices

def scan_rev_dns(dns_ip, ip):
    # for i in range(40, 41):
    #     ip_req = ip + str(i)
    ip_req = (ip_address(ip).reverse_pointer)
    res = sr1(IP(dst=dns_ip)/UDP()/DNS(rd=1,qd=DNSQR(qname=ip_req, qtype='PTR')))

    # print(dir(res[0].payload))
    print(res[0].summary)
    if res[0].payload.payload.an:
        host_name = res[0].payload.payload.an.rdata

        print('found:', host_name)
        

if __name__ == '__main__':
    scan_rev_dns("192.168.1.1", "192.168.1.77")
    # get_devices(True)
    # print(ip_address("127.0.0.1").reverse_pointer)
