import platform    # For getting the operating system name
import subprocess  # For executing a shell command


def ping(host):
    """
    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
    """

    # Option for the number of packets as a function of
    param = '-n' if platform.system().lower() == 'windows' else '-c'

    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, '1', host]

    return subprocess.call(command) == 0


# partie récupération ip de l'utilisateur
input_user_ip = input(
    "Renseigner votre IP dans le réseau que vous souhaitez scanner :\n")
input_user_mask = input(
    "Préciser le masque de votre IP, laisser vide si inconnu\n")
# calculer le masque si input vide
with open("ip_list.txt", "a") as file:
    if input_user_mask == "":
        file.write(input_user_ip+"\n")
    else:
        file.write(input_user_ip+"/"+input_user_mask+"\n")


# test des ips dans le réseau et sauvegarde de celle qui répondent
with open("ip_list.txt") as file:
    StockIP = file.read()
    StockIP = StockIP.splitlines()
for ip in StockIP:  # ping for each ip in the file
    verif = ping(ip)
    if verif:
        with open("ip.txt", "a") as file:
            file.write(ip+"\n")

# si on propose une liste d'interface au lancement, aussi ajouter genre un -i pour préciser directement l'ip qu'on souhaite tester
# 1 ping pas suffisant, temps d'attente arp