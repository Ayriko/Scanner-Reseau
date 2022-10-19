from datetime import datetime
from scapy.all import ICMP, IP, send, sr

# # sr au lieu de send permet de stocker et aussi de gérer les erreurs
# toto = IP(dst="10.3.1.12")/ICMP()
# sr(toto)
# toto.show()

def main():
    with open("ip_list.txt", "a") as file:
        file.write(datetime.today + '\n')
    for i in range (10,20):
        ipGood = IP(dst="10.3.1." + i)/ICMP()
        if ipGood:
            with open("ip_list.txt", "a") as file:
                file.write(ipGood + '\n')


# scapy.send(scapy.IP()/scapy.ICMP(id=1, seq=1))
