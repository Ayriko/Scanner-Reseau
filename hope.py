import sys
import re
from scapy.all import ARP, Ether, srp

def valableIp(testIp):
    regex = re.search("^(((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(((\/([4-9]|[12][0-9]|3[0-2]))?)|\s?-\s?((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))))(,\s?|$))+", testIp)
    if regex:
        return True
    return False


def main():
    tabIp = []
    tabMac = []
    for i in range(1, len(sys.argv)):
        if valableIp(sys.argv[i]):
            testARP, unansARP = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipChoose), timeout=2, verbose=False)
            testARP.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%"))
            for i in range(0,len(testARP)):
                tabIp.append(testARP[i][1].psrc)
                tabMac.append(testARP[i][1].hwsrc)
                with open("ip_list.txt", "a") as file:
                    file.write("ip :  "+ tabIp[i] + " mac : "  + tabMac[i] + '\n')
            else:
                main()
        if "non":
            print("sadge")
        if "nique":
            print("fonce")
        else :
            ipChoose = input("Rentrez votre addresse IP avec son masque (ex: xxx.xxx.xxx.xxx/xx)\n")
            if valableIp(ipChoose):
                testARP, unansARP = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipChoose), timeout=2, verbose=False)
                testARP.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%"))
                for i in range(0,len(testARP)):
                    tabIp.append(testARP[i][1].psrc)
                    tabMac.append(testARP[i][1].hwsrc)
                    with open("ip_list.txt", "a") as file:
                        file.write("ip :  "+ tabIp[i] + " mac : "  + tabMac[i] + '\n')
            else:
                main()
    print(sys.argv[1:])

main()