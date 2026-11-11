# Changelog

## 1.0.5
- Colonne « Web » : lien cliquable (icône globe) vers chaque interface web détectée (http/https), aussi dans le détail.
- Option `extra_ports` : ports testés en plus du top N (8006 Proxmox, 8123 HA…).

## 1.0.4
- Tableau compacté : une ligne par équipement, OS/fabricant abrégés, ports en numéros, « Vu » relatif ; détail complet au clic sur la ligne ; cartes compteurs cliquables comme filtres.

## 1.0.3
- Correctif : un équipement répondant avec la même MAC sur plusieurs IP (ex. NAS + interface macvlan-shim) n'écrase plus l'une des IP ; alerte « hôte multi-IP ».

## 1.0.2
- Les appareils hors ligne sont aussi reclassés (DHCP / IP fixe) à chaque lecture réussie de Pi-hole.

## 1.0.1
- Correctif : le capteur HA n'était pas publié et l'heure était en UTC (environnement du conteneur vidé par s6-overlay).
- Message explicite quand le mot de passe Pi-hole manque ou est refusé.

## 1.0.0
- Première version : scan nmap quotidien, croisement DHCP Pi-hole v6, panneau ingress, capteur HA, notifications.
