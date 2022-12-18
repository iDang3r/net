from scapy.all import *

ip=IP(src="10.55.128.98",dst="10.55.134.56")  
SYN=TCP(sport=40509,dport=40509,flags="S",seq=12345)
send(ip/SYN)