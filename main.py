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
        testARP = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                      ARP(pdst=ip), timeout=2, verbose=False)[0]
        result = []
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
        ansIP = sr(IP(dst=tabIp[i])/ICMP(), timeout=1, verbose=False)[0]
        ansIP.summary(lambda s, r: r.sprintf("%IP.src% is alive"))

# def display_result(result):
#    print("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")
#    for i in result:
#       print("{}\t{}".format(i["ip"], i["mac"]))


scanned_output = scanARP()
scanIP(scanned_output)
