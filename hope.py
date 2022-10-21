import sys
import re
from scapy.all import ARP, Ether, srp, sr, IP, ICMP

def main():
    ip = ""
    port = ""
    found_args = {
        
    } 
    if sys.argv[1:] == [] :
        ipChoose = input("Rentrez votre addresse IP avec son masque (ex: xxx.xxx.xxx.xxx/xx)\n")
        if valableIp(ipChoose):
            tabIp = scanARP(ipChoose)
        else:
            main()
        inputUser = input("Voulez vous ping les differents IP ? [Y/N] ").lower()
        if inputUser == "y" or inputUser == "yes":
            scanIP(tabIp)
        
    else:
        found_args, ip, port = flag(sys.argv)
        if found_args["-h"]:
            print("oe de l'aide")
            return
        if found_args["-i"]:
            tabIp = scanARP(ip)
        # for i in range(1, len(sys.argv)):
        #     if valableIp(sys.argv[i]):
        #         tabIp = scanARP(sys.argv[i])
        if found_args["-p"]:
            print ("le port oe")
            print(port)
        else:
            sys.argv[1:] = []
            main()
            return
        # found_args = {
        # "ip": False,
        # "-h": False,
        # "port": False
        # } 
        # for i in range(1, len(sys.argv)):
        #     if wantIp(sys.argv[i]):
        #         if valableIp(sys.argv[i+1]):
        #             found_args["ip"] = True
        #             tabIp.append(sys.argv[i+1])
        #     elif helpMe(sys.argv[i]):
        #         found_args["-h"] = True
        #     elif wantPort(sys.argv[i]):
        #         if validPort(sys.argv[i+1]):
        #             found_args["port"] = True
        #             tabPort.append(sys.argv[i+1])
            
        #     else:
        #         sys.argv[1:] = []
        #         main()
        #         return
        inputUser = input("Voulez vous ping les differents IP ? [Y/N] ").lower()
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
    testARP = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipTest), timeout=2)[0]
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
        file.write("Ces IP appartiennent surement à un linux ou a un macOs : " + str(linux) + '\n')
        file.write("Ces IP appartiennent surement à un windows : " + str(win) + '\n')
        file.write("------------------------------------------------------------------------------" +  '\n')
#    print(tabICMP)
#    return tabICMP

def helpMe(param):
    if param == "-h":
        return True
    return False

def validPort(param):
    regex = re.search("^([1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$", str(param))
    if regex:
        return True
    else:
        print("le port n'est pas valide")

def wantIp(param):
    if param == "-i":
        return True
    return False

def wantPort(param):
    if param == "-p":
        return True
    return False

def flag(param):
    ip = ""
    port = ""
    found_args = {
        "-i": False,
        "-h": False,
        "-p": False
    }
    for i in range(1, len(param)):
        if wantIp(param[i]):
            if valableIp(param[i+1]):
                found_args["-i"] = True
                ip = param[i+1]
            else:
                sys.argv[1:] = []
                main()
                return
        elif helpMe(param[i]):
            found_args["-h"] = True
        elif wantPort(param[i]):
            if validPort(param[i+1]):
                found_args["-p"] = True
                port = str(param[i+1])
    
    return found_args, ip, port

main()