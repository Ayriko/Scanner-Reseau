import sys
import re
from scapy.all import ARP, Ether, srp

def main():
    if sys.argv[1:] == [] :
        ipChoose = input("Rentrez votre addresse IP avec son masque (ex: xxx.xxx.xxx.xxx/xx)\n")
        if valableIp(ipChoose):
            scanARP(ipChoose)
        for i in range(1, len(sys.argv)):
            if valableIp(sys.argv[i]):
                scanARP(sys.argv[i])    
            if "non":
                print("sadge")
            if "nique":
                print("fonce")

    print(sys.argv[1:])

def valableIp(testIp):
    regex = re.search("^(((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(((\/([4-9]|[12][0-9]|3[0-2]))?)|\s?-\s?((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))))(,\s?|$))+", testIp)
    if regex:
        return True
    print("l'ip n'est pas valide")
    main()

def scanARP(ipTest):
    tabIp = []
    tabMac = []
    ipGood = ipTest
    testARP = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipGood), timeout=2, verbose=False)[0]
    for i in range(0, len(testARP)):
        tabIp.append(testARP[i][1].psrc)
        tabMac.append(testARP[i][1].hwsrc)
        with open("rapport.txt", "a") as file:
            file.write("ip : " + tabIp[i] + " mac : " + tabMac[i] + '\n')

main()