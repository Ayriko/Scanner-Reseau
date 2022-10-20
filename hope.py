import sys
import re
from scapy.all import ARP, Ether, srp, sr, IP, ICMP

def main():
    if sys.argv[1:] == [] :
        ipChoose = input("Rentrez votre addresse IP avec son masque (ex: xxx.xxx.xxx.xxx/xx)\n")
        if valableIp(ipChoose):
            tabIp = scanARP(ipChoose)
    else:    
        for i in range(1, len(sys.argv)):
            if valableIp(sys.argv[i]):
                tabIp = scanARP(sys.argv[i])
                inputUser = input("Voulez vous ping les differents ip ?[Y/N]")
                if inputUser.toLower() == "y":
                    scanIP(tabIp)
    
    print(tabIp)
    print(sys.argv[1:])

def valableIp(testIp):
    regex = re.search("^([01]?\d\d?|2[0-4]\d|25[0-5])(?:\.[01]?\d\d?|\.2[0-4]\d|\.25[0-5]){3}(?:/[1-2]?\d|/3[0-2])$", testIp)
    if regex:
        return True

    print("l'ip n'est pas valide")
    

def scanARP(ipTest):
    tabIp = []
    tabMac = []
    ipGood = ipTest
    print("Le scan est en cours")
    testARP = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipGood), timeout=2, verbose=False)[0]
    for i in range(0, len(testARP)):
        tabIp.append(testARP[i][1].psrc)
        tabMac.append(testARP[i][1].hwsrc)
        with open("rapport.txt", "a") as file:
            file.write("ip : " + tabIp[i] + " mac : " + tabMac[i] + '\n')
    with open("rapport.txt", "a") as file:
        file.write("------------------------------------------------------------------------------" +  '\n')
    print("Le scan est terminé \n")
    return tabIp

def scanIP(tabIp):
    for i in range(0, len(tabIp)):
        ansIP = sr(IP(dst=tabIp[i])/ICMP(), timeout=1, verbose=False)[0]
        ansIP.summary(lambda s, r: r.sprintf("%IP.src% is alive"))
        print(IP.src)

main()