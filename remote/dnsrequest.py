#!/usr/bin/python3
from scapy.all import *

f=open("ip_req.bin", "wb")
Qdsec = DNSQR(qname="wixia.example.com")
DNSpkt =  DNS(id=0xAAAA, ar=0, qdcount=1, ancount=0, nscount=0, arcount=0, qd=Qdsec)
IPpkt = IP(dst="serverIPaddress", src="userIPaddress")  #replace to match up with you VMs
UDPpkt = UDP(dport=53, sport=33333, chksum=0)
request = IPpkt/UDPpkt/DNSpkt
f.write(bytes(request))
f.close()

