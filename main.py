from scapy.all import ARP, Ether, srp, sr, IP, ICMP
import re


def scanARP():
    tabIp = []
    tabMac = []
    ip = input(
        "Rentrez votre addresse IP avec son masque (ex: xxx.xxx.xxx.xxx/xx)\n")
    regex = re.search(
        "^(((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(((\/([4-9]|[12][0-9]|3[0-2]))?)|\s?-\s?((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))))(,\s?|$))+", ip)
    if regex:
        print("Scanning...")
        #arp_req_frame = ARP(pdst = ip)
        # broadcast_ether_frame = Ether(dst = "ff:ff:ff:ff:ff:ff") -> création d'une frame ethernet  + on va réaliser la requete arp vers la broadcast pour demander à chaque machine
        #broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame
        # answered_list = srp(broadcast_ether_arp_req_frame, timeout = 1, verbose = False)[0]  -> verbose permet de ne pas voir la commande dans la console
        # le [0] permet de stocker que les replys et non les requêtes sans réponses qui ne sont pas utile ici
        # tout ce qu'il y a au dessus peut etre réduit en :
        testARP = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                      ARP(pdst=ip), timeout=2, verbose=False)[0]
        for i in range(0, len(testARP)):
            tabIp.append(testARP[i][1].psrc)
            tabMac.append(testARP[i][1].hwsrc)
            with open("rapport.txt", "a") as file:
                file.write("ip : " + tabIp[i] + " mac : " + tabMac[i] + '\n')
        return tabIp
    else:
        scanARP()


def scanIP(tabIp):
    for i in range(0, len(tabIp)):
        ansIP, unansIP = sr(IP(dst=tabIp[i])/ICMP(), timeout=1, verbose=False)
        ansIP.summary(lambda s, r: r.sprintf("%IP.src% is alive"))
        unansIP.summary(lambda s, r: r.sprintf("%IP.src% is dead")) #indice potentiel windows

# def display_result(result):
#    print("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")
#    for i in result:
#       print("{}\t{}".format(i["ip"], i["mac"]))

#partie test de l'os lors du scan
# list des signatures testables/identifiables :
#ISN, p0f et nmap_fp

#pour linux, possible après un three-way-handshake -> envoyer une trame sans flags TCP et avec un payload
# si ACK en retour -> Linux
# sinon non-linux 
# -> ALORS, peut etre premier test pour bien séparer, ensuite revoir avec les IPs les non-linux, peut faire hypothèse entre mac et windows ducoup
# TROUVER signature mac


scanned_output = scanARP()
scanIP(scanned_output)


# jouter genre un -i pour préciser directement l'ip qu'on souhaite tester sans passer par l'interaction
# 1 ping pas suffisant, temps d'attente arp
