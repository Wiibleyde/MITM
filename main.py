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

def listAllIPs(address, netmask):
    # Get all possible ip addresses of a network in a list
    ip_list = []
    for ip in IPv4Network(address + '/' + netmask, False):
        ip_list.append(str(ip))
    ip_list.remove(ip_list[0])
    ip_list.remove(ip_list[-1])
    return ip_list

def getIpAdress(interface):
    # Get the ip address of the interface
    ip = scapy.get_if_addr(interface)
    return ip

def getNetworkMask(interface):
    # Get the network mask of the interface
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
    address = IPv4Network(getIpAdress(interface) + '/' + netmask, False)
    ip = address.network_address
    mac=[]
    addressMask = address.prefixlen
    answered, unanswered = makeARPRequest(str(ip)+'/'+str(addressMask))
    for element in answered:
        mac.append(element[1].hwsrc)
    print(mac)

if __name__ == '__main__':
    main()