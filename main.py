# ========================================================================================================================================================================================================
interface = 'wlp0s20f3'
# ========================================================================================================================================================================================================
# Don't touch after this line
# ========================================================================================================================================================================================================

from ipaddress import IPv4Network
from scapy import all as scapy
from socket import *
from fcntl import ioctl
from struct import pack

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

def main():
    netmask = getNetworkMask(interface)
    address = IPv4Network(scapy.get_if_addr(interface) + '/' + netmask, False)
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

if __name__ == '__main__':
    main()