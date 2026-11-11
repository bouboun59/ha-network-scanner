#!/usr/bin/env python3
"""Network Scanner — inventaire réseau quotidien (nmap) croisé avec le DHCP Pi-hole v6."""
import ipaddress
import json
import os
import re
import ssl
import subprocess
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OPTIONS_FILE = "/data/options.json"
DB_FILE = "/data/devices.json"
WEB_DIR = os.path.join(os.path.dirname(__file__), "web")
PORT = 8099
# Ingress (Supervisor) + HA Core (réseau hôte) uniquement
ALLOWED_CLIENTS = {"172.30.32.2", "127.0.0.1", "::1"}
SUPERVISOR = "http://supervisor/core/api"
TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
SENSOR = "sensor.network_scanner_devices"

MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
LEASE_TIME_RE = re.compile(r"^(\d+[smhdw]?|infinite|ignore)$", re.I)
SSL_CTX = ssl._create_unverified_context()  # Pi-hole en HTTPS auto-signé

lock = threading.Lock()
state = {"devices": {}, "last_scan": None, "last_duration": None,
         "last_error": None, "dhcp": {}, "scanning": False}


def log(msg):
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}", flush=True)


def load_options():
    with open(OPTIONS_FILE, encoding="utf-8") as f:
        return json.load(f)


OPT = load_options()


# --------------------------------------------------------------- persistance
def load_db():
    try:
        with open(DB_FILE, encoding="utf-8") as f:
            state.update(json.load(f))
    except FileNotFoundError:
        pass
    except Exception as e:  # noqa: BLE001
        log(f"Base illisible, repart de zéro : {e}")
    state["scanning"] = False


def save_db():
    keep = ("devices", "last_scan", "last_duration", "last_error", "dhcp")
    tmp = DB_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({k: state[k] for k in keep}, f, indent=1, ensure_ascii=False)
    os.replace(tmp, DB_FILE)


# --------------------------------------------------------------------- HTTP
def http_json(method, url, data=None, headers=None, timeout=20):
    body = json.dumps(data).encode() if data is not None else None
    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    ctx = SSL_CTX if url.startswith("https") else None
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


def ha_api(method, path, data=None):
    if not TOKEN:
        return None
    return http_json(method, f"{SUPERVISOR}{path}", data,
                     headers={"Authorization": f"Bearer {TOKEN}"})


# ------------------------------------------------------------------ Pi-hole
def norm_mac(mac):
    return mac.lower().replace("-", ":") if mac else None


def parse_dhcp_host(entry):
    """Ligne dnsmasq dhcp-host : '[mac][,mac][,id:x][,set:x][,ip][,nom][,durée]'."""
    macs, ip, name = [], None, None
    for tok in str(entry).split(","):
        tok = tok.strip()
        if not tok:
            continue
        if MAC_RE.match(tok):
            macs.append(norm_mac(tok))
        elif IP_RE.match(tok):
            ip = tok
        elif ":" in tok or LEASE_TIME_RE.match(tok):
            continue  # id:, set:, tag:, durée de bail
        else:
            name = tok
    return macs, ip, name


def pihole_dhcp():
    base = OPT["pihole_url"].rstrip("/") + "/api"
    headers, sid = {}, None
    if OPT.get("pihole_password"):
        sess = http_json("POST", f"{base}/auth",
                         {"password": OPT["pihole_password"]}).get("session", {})
        if not sess.get("valid"):
            raise RuntimeError("authentification Pi-hole refusée")
        sid = sess.get("sid")
        if sid:
            headers["X-FTL-SID"] = sid
    try:
        leases = http_json("GET", f"{base}/dhcp/leases", headers=headers).get("leases", [])
        cfg = (http_json("GET", f"{base}/config/dhcp", headers=headers)
               .get("config", {}).get("dhcp", {}))
    finally:
        if sid:  # libère la session (nombre de sessions limité côté Pi-hole)
            try:
                http_json("DELETE", f"{base}/auth", headers=headers)
            except Exception:  # noqa: BLE001
                pass

    reservations = {}
    for entry in cfg.get("hosts") or []:
        macs, ip, name = parse_dhcp_host(entry)
        for m in macs:
            reservations[m] = {"ip": ip, "name": name}

    lease_map = {}
    for l in leases:
        mac = norm_mac(l.get("hwaddr"))
        if not mac:
            continue
        name = l.get("name")
        lease_map[mac] = {"ip": l.get("ip"),
                          "name": None if name in (None, "", "*") else name,
                          "expires": l.get("expires") or 0}
    return {"active": cfg.get("active"), "start": cfg.get("start"), "end": cfg.get("end"),
            "reservations": reservations, "leases": lease_map}


def in_dhcp_range(ip, dhcp):
    try:
        a = ipaddress.ip_address(ip)
        return ipaddress.ip_address(dhcp["start"]) <= a <= ipaddress.ip_address(dhcp["end"])
    except Exception:  # noqa: BLE001
        return False


def classify(mac, ip, dhcp):
    """Retourne (type d'attribution, alertes, infos Pi-hole)."""
    alerts, info = [], {"pihole_name": None, "reserved_ip": None, "lease_expires": None}
    if dhcp is None:
        return "Inconnu (Pi-hole injoignable)", alerts, info

    res = dhcp["reservations"].get(mac) if mac else None
    lease = dhcp["leases"].get(mac) if mac else None
    if lease:
        info["pihole_name"] = lease["name"]
        exp = lease["expires"]
        info["lease_expires"] = ("permanent" if not exp
                                 else datetime.fromtimestamp(exp).isoformat(timespec="minutes"))

    if res:
        info["reserved_ip"] = res["ip"]
        info["pihole_name"] = res["name"] or info["pihole_name"]
        if res["ip"] and res["ip"] != ip:
            alerts.append(f"Réservé en {res['ip']} mais vu en {ip}")
        return "DHCP réservé", alerts, info

    if lease and lease["ip"] == ip:
        return "DHCP dynamique", alerts, info

    if lease:
        alerts.append(f"Bail Pi-hole en {lease['ip']} inutilisé")
    if in_dhcp_range(ip, dhcp):
        alerts.append("IP fixe dans la plage DHCP (risque de conflit)")
    return "IP fixe", alerts, info


# --------------------------------------------------------------------- nmap
def run_nmap(args, timeout=3600):
    out = subprocess.run(["nmap", "-oX", "-"] + args, capture_output=True,
                         text=True, timeout=timeout, check=False)
    if out.returncode != 0 or not out.stdout.strip():
        raise RuntimeError(out.stderr.strip() or f"nmap code {out.returncode}")
    return ET.fromstring(out.stdout)


def host_addresses(h):
    ip = mac = vendor = None
    for a in h.findall("address"):
        if a.get("addrtype") == "ipv4":
            ip = a.get("addr")
        elif a.get("addrtype") == "mac":
            mac, vendor = norm_mac(a.get("addr")), a.get("vendor")
    return ip, mac, vendor


def discover():
    args = ["-sn", "-PR", "-T4"]
    if OPT.get("dns_server"):
        args += ["--dns-servers", OPT["dns_server"]]
    root = run_nmap(args + [OPT["network"]])
    hosts = {}
    for h in root.findall("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        ip, mac, vendor = host_addresses(h)
        if not ip:
            continue
        hn = h.find("hostnames/hostname")
        hosts[ip] = {"mac": mac, "vendor": vendor,
                     "dns": hn.get("name") if hn is not None else None}
    return hosts


def local_interfaces():
    """IP -> MAC des interfaces de l'hôte (nmap ne voit pas sa propre MAC)."""
    res = {}
    out = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True,
                         text=True, check=False).stdout
    for line in out.splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        iface, ip = p[1].split("@")[0], p[3].split("/")[0]
        try:
            with open(f"/sys/class/net/{iface}/address", encoding="utf-8") as f:
                res[ip] = norm_mac(f.read().strip())
        except OSError:
            pass
    return res


def deep_scan(ips):
    args = ["-sS", "-O", "--osscan-limit", "-T4", "-n",
            "--top-ports", str(OPT.get("top_ports", 100))] + ips
    root = run_nmap(args, timeout=7200)
    res = {}
    for h in root.findall("host"):
        ip, _, _ = host_addresses(h)
        ports = []
        for p in h.findall("ports/port"):
            pst = p.find("state")
            if pst is None or pst.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append(f"{p.get('portid')}/{svc.get('name') if svc is not None else '?'}")
        osm = h.find("os/osmatch")
        res[ip] = {"ports": ports,
                   "os": f"{osm.get('name')} ({osm.get('accuracy')}%)" if osm is not None else None}
    return res


# --------------------------------------------------------------------- scan
def ip_key(d):
    try:
        return int(ipaddress.ip_address(d.get("ip") or "0.0.0.0"))
    except ValueError:
        return 0


def scan():
    if not lock.acquire(blocking=False):
        log("Scan déjà en cours")
        return False
    state["scanning"] = True
    t0, now = time.time(), datetime.now().isoformat(timespec="seconds")
    first_run = not state["devices"]
    try:
        log(f"Scan de {OPT['network']}…")
        hosts = discover()
        for ip, mac in local_interfaces().items():
            if ip in hosts and not hosts[ip]["mac"]:
                hosts[ip]["mac"], hosts[ip]["vendor"] = mac, "Hôte Home Assistant"
        log(f"{len(hosts)} équipements en ligne")

        dhcp = None
        try:
            dhcp = pihole_dhcp()
            state["dhcp"] = {k: dhcp[k] for k in ("active", "start", "end")}
            log(f"Pi-hole : {len(dhcp['leases'])} baux, {len(dhcp['reservations'])} réservations")
        except Exception as e:  # noqa: BLE001
            log(f"Pi-hole injoignable : {e}")

        deep = {}
        if OPT.get("deep_scan") and hosts:
            log("Scan approfondi (ports + OS)…")
            try:
                deep = deep_scan(sorted(hosts))
            except Exception as e:  # noqa: BLE001
                log(f"Scan approfondi en échec : {e}")

        devices, new = state["devices"], []
        for d in devices.values():
            d["online"] = False
        for ip, h in hosts.items():
            key = h["mac"] or f"ip:{ip}"
            d = devices.get(key)
            if d is None:
                d = devices[key] = {"first_seen": now, "ports": [], "os": None}
                new.append(key)
            dtype, alerts, info = classify(h["mac"], ip, dhcp)
            dns = h["dns"]
            d.update({
                "ip": ip, "mac": h["mac"], "vendor": h["vendor"] or d.get("vendor"),
                "dns": dns,
                "name": info["pihole_name"] or (dns.split(".")[0] if dns else None),
                "dhcp_type": dtype, "reserved_ip": info["reserved_ip"],
                "lease_expires": info["lease_expires"], "alerts": alerts,
                "online": True, "last_seen": now,
            })
            if ip in deep:
                d["ports"], d["os"] = deep[ip]["ports"], deep[ip]["os"] or d.get("os")

        limit = datetime.now() - timedelta(days=OPT.get("forget_after_days", 60))
        for k in [k for k, d in devices.items()
                  if datetime.fromisoformat(d["last_seen"]) < limit]:
            log(f"Oubli de {devices[k].get('ip')} ({k})")
            del devices[k]

        state["last_scan"], state["last_error"] = now, None
        state["last_duration"] = round(time.time() - t0)
        save_db()
        log(f"Scan terminé en {state['last_duration']} s ({len(new)} nouveaux)")
        push_sensor()
        if new and not first_run and OPT.get("notify_new_devices"):
            notify_new([devices[k] for k in new])
        return True
    except Exception as e:  # noqa: BLE001
        state["last_error"] = str(e)
        log(f"ERREUR scan : {e}")
        return False
    finally:
        state["scanning"] = False
        lock.release()


# ------------------------------------------------------------ Home Assistant
def push_sensor():
    devs = sorted(state["devices"].values(), key=ip_key)
    attrs = {
        "friendly_name": "Appareils réseau", "icon": "mdi:lan",
        "unit_of_measurement": "appareils",
        "last_scan": state["last_scan"], "total": len(devs),
        "dhcp_dynamique": sum(d["dhcp_type"] == "DHCP dynamique" for d in devs),
        "dhcp_reserve": sum(d["dhcp_type"] == "DHCP réservé" for d in devs),
        "ip_fixe": sum(d["dhcp_type"] == "IP fixe" for d in devs),
        "alertes": sum(bool(d.get("alerts")) for d in devs),
        "devices": [{"ip": d["ip"], "mac": d["mac"], "name": d.get("name") or "",
                     "vendor": d.get("vendor") or "", "dhcp": d["dhcp_type"],
                     "online": "🟢" if d["online"] else "⚪",
                     "last_seen": d["last_seen"][:16].replace("T", " ")} for d in devs],
    }
    try:
        ha_api("POST", f"/states/{SENSOR}",
               {"state": sum(d["online"] for d in devs), "attributes": attrs})
    except Exception as e:  # noqa: BLE001
        log(f"Mise à jour du capteur HA impossible : {e}")


def notify_new(devs):
    lines = [f"- **{d.get('name') or '?'}** — {d['ip']} — {d.get('mac') or '?'} "
             f"({d.get('vendor') or 'fabricant inconnu'}) — {d['dhcp_type']}" for d in devs]
    try:
        ha_api("POST", "/services/persistent_notification/create", {
            "title": f"{len(devs)} nouvel(s) appareil(s) sur le réseau",
            "message": "\n".join(lines),
            "notification_id": "network_scanner_new"})
    except Exception as e:  # noqa: BLE001
        log(f"Notification impossible : {e}")


# ---------------------------------------------------------------- planning
def scheduler():
    hh, mm = map(int, OPT.get("scan_time", "03:00").split(":"))
    while True:
        now = datetime.now()
        nxt = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if nxt <= now:
            nxt += timedelta(days=1)
        log(f"Prochain scan planifié : {nxt:%d/%m/%Y %H:%M}")
        while datetime.now() < nxt:  # pas de 60 s : robuste au changement d'heure
            time.sleep(min(60, max(1, (nxt - datetime.now()).total_seconds())))
        scan()


# -------------------------------------------------------------- serveur web
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _forbidden(self):
        if self.client_address[0] not in ALLOWED_CLIENTS:
            self.send_error(403)
            return True
        return False

    def _send(self, code, body, ctype):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self._forbidden():
            return
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            with open(os.path.join(WEB_DIR, "index.html"), "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
        elif path == "/api/devices":
            payload = dict(state)
            payload["devices"] = sorted(state["devices"].values(), key=ip_key)
            payload["options"] = {"network": OPT["network"], "scan_time": OPT["scan_time"]}
            self._send(200, json.dumps(payload, ensure_ascii=False),
                       "application/json; charset=utf-8")
        else:
            self.send_error(404)

    def do_POST(self):
        if self._forbidden():
            return
        if self.path.split("?")[0] == "/api/scan":
            started = not lock.locked()
            if started:
                threading.Thread(target=scan, daemon=True).start()
            self._send(202, json.dumps({"started": started}), "application/json")
        else:
            self.send_error(404)


def main():
    load_db()
    log(f"Network Scanner démarré — réseau {OPT['network']}, scan quotidien à {OPT['scan_time']}")
    if state["devices"]:
        push_sensor()
    else:
        threading.Thread(target=scan, daemon=True).start()  # premier inventaire
    threading.Thread(target=scheduler, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
