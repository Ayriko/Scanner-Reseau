import sys
import re
from scapy.all import ARP, Ether, srp, sr, IP, ICMP

def main():
    if sys.argv[1:] == [] :
        ipChoose = input("Rentrez votre addresse IP avec son masque (ex: xxx.xxx.xxx.xxx/xx)\n")
        if valableIp(ipChoose):
            tabIp = scanARP(ipChoose)
        inputUser = input("Voulez vous ping les differents IP ?[Y/N] ").lower()
        if inputUser == "y" or inputUser == "yes":
            scanIP(tabIp)
        
    else:    
        for i in range(1, len(sys.argv)):
            if valableIp(sys.argv[i]):
                tabIp = scanARP(sys.argv[i])
        inputUser = input("Voulez vous ping les differents IP ?[Y/N] ").lower()
        if inputUser == "y" or inputUser == "yes":
            scanIP(tabIp)
    
#    print(tabIp)
#    print(sys.argv[1:])

def valableIp(testIp):
    regex = re.search("^([01]?\d\d?|2[0-4]\d|25[0-5])(?:\.[01]?\d\d?|\.2[0-4]\d|\.25[0-5]){3}(?:/[1-2]?\d|/3[0-2])$", testIp)
    if regex:
        return True

    print("l'ip n'est pas valide")
    

def scanARP(ipTest):
    tabIp = []
    tabMac = []
    testARP = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipTest), timeout=2, verbose=False)[0]
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
    tabICMP = []
    linux = []
    win = []
    for i in range(0, len(tabIp)):
        ansIP = sr(IP(dst=tabIp[i])/ICMP(), timeout=1, verbose=False)[0]
        for i in range(0, len(ansIP)):
            tabICMP.append(ansIP[i][1].src)
    
    for i in tabIp:
        if i in tabICMP:
            linux.append(i)
        else:
            win.append(i)
    
    with open("rapport.txt", "a") as file:
        file.write("ces IP appartiennent surement à un linux ou a un macOs : " + linux + '\n')
        file.write("ces IP appartiennent surement à un windows : " + win + '\n')
        file.write("------------------------------------------------------------------------------" +  '\n')
#    print(tabICMP)
#    return tabICMP

main()