from scapy.all import ICMP, IP, send, sr

# sr au lieu de send permet de stocker et aussi de gérer les erreurs
toto = IP(dst="10.3.1.12")/ICMP()
sr(toto)
toto.show()

# scapy.send(scapy.IP()/scapy.ICMP(id=1, seq=1))
