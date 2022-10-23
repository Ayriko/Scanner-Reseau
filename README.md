# Projet Scanner-Réseau
Le projet Scanner-Réseau est un projet où nous devons scanner un réseau pour découvrir les differentes adresses ip ainsi que leurs ports ouverts.  
Notre outil est utilisable de deux façons différents :  
- d'une manière interactive et progressive via différents lignes de commandes,
- d'une manière directe en précisant divers arguments dès la commande de lancement.  

Dans tout les cas, l'utilisateur va pouvoir récupérer toutes les IPs actives du réseau ainsi que les adresses Mac des machines détectées.  
A partir de ces IPs, il est aussi possible d'obtenir des informations sur les potentiels OS derrières ces IPs et aussi de tester divers ports par défaut.
Afin de savoir s'ils sont ouverts ou non et quelles services sont présents derrières.  
La méthode directe de notre outil est plus libre quand au scan de port, permettant de tester le ou les ports souhaités.  
(voir -help dans la partie : Utilisation)

## Installation 
Ouvrez un terminal  
Entrez dans le dossier où vous voulez installer le projet avec la commande cd
par exemple :
```bash
cd /Desktop
```
Entrez la commande suivante : 
```bash
git clone  https://github.com/Ayriko/Scanner-Reseau
```

Attention il vous faudra obligatoirement python et python-scapy d'installé
```bash
sudo dnf install python3
sudo dnf install python3-scapy
```

Pour lancer le projet il faudra lancer le programme en administrateur
```bash
sudo python3 main.py
```

Vous pourrez voir les résultats du scan dans le rapport.txt
```bash
cat rapport.txt
```

## Utilisation de l'application

Pour plus d'informations sur les commandes réalisables directement : 
```bash
sudo python3 main.py -h
sudo python3 main.py --help
```
Voici ce que montre le --help :
```bash
 -h, --help                
 show help content
 
 -i [ip]                 
 choose a ip for scanning, ip should have these form : xxx.xxx.xxx.xxx/xx

 -p [port] [port,port...] [port-port]
 choose one or multiple ports to scan
 a ',' between ports means to scan each listed ports
 a '-' between ports means to scan each ports between listed ports
```

## Membres du Projet
MENARD Raphaël, MOISKA Aymeric

### Licence
[MIT](https://choosealicense.com/licenses/mit/)