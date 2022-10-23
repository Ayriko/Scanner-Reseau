# Projet Scanner-Réseau
Le projet Scanner-Réseau est un projet où nous devons scanner un réseau pour découvrir les differentes addresses ip ainsi que leurs ports ouverts

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

Pour plus d'information: 
```bash
sudo python3 main.py -h
```

## Membres du Projet
MENARD Raphaël, MOISKA Aymeric

### Licence
[MIT](https://choosealicense.com/licenses/mit/)