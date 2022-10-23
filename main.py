import sys
import re
from scapy.all import ARP, TCP, Ether, srp, sr, IP, ICMP, sr1
import random
import socket


def main():
    ip = ""
    port = []
    verifRange = False
    found_args = {

    }
    if sys.argv[1:] == []:
        ipChoose = input("Rentrez l'adresse IP à tester avec son masque (ex: xxx.xxx.xxx.xxx/xx)\n")
        if valableIp(ipChoose):
            tabIp = scanARP(ipChoose)
        else:
            main()
        inputUser = input("Voulez vous faire un scan plus en profondeur ? [Y/N] ").lower()
        if inputUser == "y" or inputUser == "yes":
            tabPort = ["20", "22", "53", "80", "443"]
            scanOS(tabIp)
            scanPort(tabIp, tabPort)
        else:
            return

    else:
        found_args, ip, port, verifRange = flag(sys.argv)
        if found_args["-h"]:
            print("-h, --help\n                 show command help\n-i [ip]\n                 choose a ip for scanning\n-p [port] [port,port...] [port-port]\n                 choose an ip or multiple port to scan")
            return
        if found_args["-i"]:  
            tabIp = scanARP(ip)
            scanOS(tabIp)
            if found_args["-p"]:
                if verifRange:
                    scanPortRange(tabIp, port)
                else:
                    scanPort(tabIp, port)


def valableIp(testIp):
    regex = re.search(
        "^([01]?\d\d?|2[0-4]\d|25[0-5])(?:\.[01]?\d\d?|\.2[0-4]\d|\.25[0-5]){3}(?:/[1-2]?\d|/3[0-2])$", testIp)
    if regex:
        return True

    print("L'ip entrée n'est pas valide")


def scanARP(ipTest):
    tabIp = []
    tabMac = []
    count = 0
    testARP = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                  ARP(pdst=ipTest), timeout=2)[0]
    with open("rapport.txt", "a") as file:
        file.write("\nNouvelle entrée dans le rapport\n")
    for i in range(0, len(testARP)):
        count = count + 1
        tabIp.append(testARP[i][1].psrc)
        tabMac.append(testARP[i][1].hwsrc)
        with open("rapport.txt", "a") as file:
            file.write("ip : " + tabIp[i] + " mac : " + tabMac[i] + '\n')
    with open("rapport.txt", "a") as file:
        file.write(
            "------------------------------------------------------------------------------" + '\n')
    print("Le scan est terminé, hôtes détectés dans le réseau : " + str(count) + "\n")
    return tabIp

def scanOS(tabIp):
    tabICMP = []
    linux = []
    win = []
    macOs = []
    print("Scan en cours...")
    for i in range(0, len(tabIp)):
        ansIP = sr(IP(dst=tabIp[i])/ICMP(), timeout=2)[0]
        for i in range(0, len(ansIP)):
            tabICMP.append(ansIP[i][1].src)
    for i in tabIp:
        print(i)
        if i in tabICMP:
            src_port = random.randint(1025, 65534)
            #test service bonjour macOs
            resp = sr1(
                IP(dst=i)/TCP(sport=src_port, dport=1900, flags="S"),
                timeout=1,
                verbose=0,
            )
            if resp is None:
                linux.append(i)
                continue
            elif (resp.haslayer(TCP)):
                if(resp.getlayer(TCP).flags == 0x12 or resp.getlayer(TCP).flags == 0x14):  #
                    if resp.getlayer(TCP).flags == 0x12 :
                        send_rst = sr(
                        IP(dst=ip)/TCP(sport=src_port, dport=1900, flags='R'),
                                timeout=1,
                                verbose=0,
                            )
                    macOs.append(i)
            else:
                linux.append(i)
        else:
            win.append(i)

    print("Envoi des différents tests terminé, résultat entré dans le rapport")
    with open("rapport.txt", "a") as file:
        file.write(
            "Ces IPs appartiennent potentiellement à un windows (ICMP bloqués) : " + str(win) + '\n')
        file.write(
            "Ces IPs semblent appartenir à un macOs (Service Bonjour (1900) détecté): " + str(macOs) + '\n')
        file.write(
            "Ces IPs appartiennent surement à un linux : " + str(linux) + '\n')
        file.write(
            "------------------------------------------------------------------------------" + '\n')


def scanPort(tabIp, port):
    # Envoi d'une requête Syn depuis un port random vers les ports dst
    for dst_port in port:
        print("Scan Syn pour le port " + dst_port + " sur les IPs du réseau")
        src_port = random.randint(1025, 65534)
        dst_port = int(dst_port)
        for ip in tabIp:
            resp = sr1(
                IP(dst=ip)/TCP(sport=src_port, dport=dst_port, flags="S"), timeout=1,
                verbose=0,
            )

            if resp is None:
                print(f"{ip}:{dst_port} est filtré")
                with open("rapport.txt", "a") as file:
                    file.write(ip + ":" + str(dst_port) +
                               " est filtré (pas de réponse). \n")

            elif(resp.haslayer(TCP)):
                if(resp.getlayer(TCP).flags == 0x12):  # SA
                    # Envoie d'un RST pour fermer la connexion
                    send_rst = sr(
                        IP(dst=ip)/TCP(sport=src_port,
                                       dport=dst_port, flags='R'),
                        timeout=1,
                        verbose=0,
                    )
                    print(f"{ip}:{dst_port} est ouvert.")
                    # print(f"{resp.getlayer(TCP).flags}") repond SA
                    service = socket.getservbyport(dst_port)
                    with open("rapport.txt", "a") as file:
                        file.write(ip + ":" + str(dst_port) +
                                   " est ouvert. Service : " + service + "\n")
                elif (resp.getlayer(TCP).flags == 0x14):  # RST (ou RA)
                    print(f"{ip}:{dst_port} est fermé.")
                    service = socket.getservbyport(dst_port)
                    # print(f"{resp.getlayer(TCP).flags}") repond RA
                    with open("rapport.txt", "a") as file:
                        file.write(ip + ":" + str(dst_port) +
                                   " est fermé. Service : " + service + " \n")

            elif(resp.haslayer(ICMP)):
                if(
                    int(resp.getlayer(ICMP).type) == 3 and
                    int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]
                ):
                    print(f"{ip}:{dst_port} est filtré.")
                    with open("rapport.txt", "a") as file:
                        file.write(ip + ":" + str(dst_port) +
                                   " est filtré (retour ICMP type 3). \n")


def scanPortRange(tabIp, port):  # scan d'un port à un autre
    # Envoi d'une requête Syn depuis un port random vers les ports dst
    print("Scan Syn du port " + port[0] +
          " à " + port[1] + " sur les IPs du réseau")
    src_port = random.randint(1025, 65534)
    port1 = int(port[0])
    port2 = int(port[1])
    while port1 <= port2:
        for ip in tabIp:
            resp = sr1(
                IP(dst=ip)/TCP(sport=src_port, dport=(port1), flags="S"), timeout=1,
                verbose=0,
            )

            if resp is None:
                print(f"{ip}:{port1} est filtré")
                with open("rapport.txt", "a") as file:
                    file.write(ip + ":" + str(port1) +
                               " est filtré (pas de réponse). \n")

            elif(resp.haslayer(TCP)):
                if(resp.getlayer(TCP).flags == 0x12):  # SA
                    # Envoie d'un RST pour fermer la connexion
                    send_rst = sr(
                        IP(dst=ip)/TCP(sport=src_port, dport=port1, flags='R'),
                        timeout=1,
                        verbose=0,
                    )
                    print(f"{ip}:{port1} est ouvert.")
                    # print(f"{resp.getlayer(TCP).flags}") repond SA
                    service = socket.getservbyport(port1)
                    with open("rapport.txt", "a") as file:
                        file.write(ip + ":" + str(port1) +
                                   " est ouvert. Service : " + service + "\n")
                elif (resp.getlayer(TCP).flags == 0x14):  # RST (ou RA)
                    print(f"{ip}:{port1} est fermé.")
                    service = socket.getservbyport(port1)
                    # print(f"{resp.getlayer(TCP).flags}") repond RA
                    with open("rapport.txt", "a") as file:
                        file.write(ip + ":" + str(port1) +
                                   " est fermé. Service : " + service + " \n")

            elif(resp.haslayer(ICMP)):
                if(
                    int(resp.getlayer(ICMP).type) == 3 and
                    int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]
                ):
                    print(f"{ip}:{port1} est filtré.")
                    with open("rapport.txt", "a") as file:
                        file.write(ip + ":" + str(port1) +
                                   " est filtré (retour ICMP type 3). \n")
        port1 = port1 + 1


def helpMe(param):
    if param == "-h" or param == "--help":
        return True
    return False


def validPort(param):
    regex = re.search(
        "^([1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$", str(param))
    if regex:
        return True
    else:
        print("Le port n'est pas valide")


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
    port = []
    split = ""
    verifRange = False
    found_args = {
        "-i": False,
        "-h": False,
        "-p": False
    }
    for i in range(1, len(param)):
        if helpMe(param[i]):
            found_args["-h"] = True
            return found_args, ip, port, verifRange
        elif wantIp(param[i]):
            if len(param) > 2:
                if valableIp(param[i+1]):
                    found_args["-i"] = True
                    ip = param[i+1]
            else:
                print("Merci de renseigner une Ip après le -i")
                exit()
        elif wantPort(param[i]) and found_args["-i"] == False:
            print("Il faut préciser une ip avec -i avant pour utiliser -p")
            exit()
        elif wantPort(param[i]):
            if len(param) > 4:
                port = [param[i+1]]
            else:
                print("Il faut préciser un port après le -p")
                exit()
            for char in param[i+1]:
                if char.isnumeric() == False:
                    if char == ",":
                        split = ","
                    elif char == "-":
                        split = "-"
                        verifRange = True
                    else:
                        print("Vérifier le port fourni après le -p, voir -h pour la forme")
                        exit()
                    port = (str(param[i+1])).split(split)
                    break
            for x in port:
                if validPort(x):
                    found_args["-p"] = True
                else:
                    exit()
    return found_args, ip, port, verifRange


main()