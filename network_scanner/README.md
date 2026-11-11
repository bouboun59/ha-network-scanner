# Network Scanner (app Home Assistant)

Scan quotidien du réseau (nmap) croisé avec le DHCP Pi-hole v6 :
inventaire des équipements, fabricant, ports ouverts, OS probable, et attribution
**DHCP dynamique / DHCP réservé / IP fixe**.

## Installation (app locale)

1. Copier le dossier `network_scanner/` dans `/addons/` de HA (partage Samba `addons` ou app SSH).
2. **Paramètres → Applications → Boutique → ⋮ → Rechercher des mises à jour** : « Network Scanner » apparaît dans *Applications locales*.
3. Installer (build local ~1-2 min), renseigner la configuration, démarrer, activer « Afficher dans la barre latérale ».

## Configuration

| Option | Défaut | Rôle |
|---|---|---|
| `network` | 192.168.1.0/24 | Sous-réseau scanné |
| `scan_time` | 03:00 | Heure du scan quotidien (heure locale HA) |
| `dns_server` | 192.168.1.2 | Résolution inverse des noms |
| `pihole_url` | http://192.168.1.2 | API Pi-hole v6 |
| `pihole_password` | — | **Mot de passe d'application** Pi-hole (Paramètres → Web interface / API → *Configure app password*) |
| `deep_scan` | true | Ports ouverts + détection d'OS |
| `top_ports` | 100 | Ports TCP testés |
| `notify_new_devices` | true | Notification HA pour tout nouvel appareil |
| `forget_after_days` | 60 | Purge des appareils absents depuis N jours |

## Règles d'attribution

| Résultat | Condition |
|---|---|
| **DHCP réservé** | MAC présente dans les réservations Pi-hole (`dhcp.hosts`) |
| **DHCP dynamique** | MAC avec un bail Pi-hole sur l'IP observée |
| **IP fixe** | Ni réservation, ni bail : IP configurée sur l'équipement |

Alertes : IP fixe *dans* la plage DHCP (risque de conflit), réservation non respectée, bail inutilisé.

## Intégration HA

L'app publie `sensor.network_scanner_devices` (état = appareils en ligne, attributs = compteurs + liste).
L'attribut `devices` est volumineux : l'exclure du recorder.

```yaml
recorder:
  exclude:
    entities:
      - sensor.network_scanner_devices

rest_command:
  network_scan_now:
    url: http://127.0.0.1:8099/api/scan
    method: POST
```

Carte tableau (HACS : **flex-table-card**) :

```yaml
type: custom:flex-table-card
title: Appareils réseau
entities:
  include: sensor.network_scanner_devices
sort_by: ip
columns:
  - { name: "", data: devices.online }
  - { name: Nom, data: devices.name }
  - { name: IP, data: devices.ip }
  - { name: MAC, data: devices.mac }
  - { name: Fabricant, data: devices.vendor }
  - { name: Attribution, data: devices.dhcp }
  - { name: Dernière vue, data: devices.last_seen }
```

Le tableau complet (ports, OS, alertes, filtres, export CSV) est dans le panneau **Réseau** de la barre latérale.
