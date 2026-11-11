# Changelog

## 1.0.3
- Correctif : un équipement répondant avec la même MAC sur plusieurs IP (ex. NAS + interface macvlan-shim) n'écrase plus l'une des IP ; alerte « hôte multi-IP ».

## 1.0.2
- Les appareils hors ligne sont aussi reclassés (DHCP / IP fixe) à chaque lecture réussie de Pi-hole.

## 1.0.1
- Correctif : le capteur HA n'était pas publié et l'heure était en UTC (environnement du conteneur vidé par s6-overlay).
- Message explicite quand le mot de passe Pi-hole manque ou est refusé.

## 1.0.0
- Première version : scan nmap quotidien, croisement DHCP Pi-hole v6, panneau ingress, capteur HA, notifications.
