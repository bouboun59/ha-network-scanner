"""Identification des équipements à partir de Home Assistant et du Matter Server.

Sources, par ordre de priorité :
  1. appareils HA ayant une MAC/IP connue (Shelly, Tapo, ESPHome, WLED, Reolink…)
  2. nœuds Matter Wi-Fi (MAC + IPv4 lues dans le Matter Server, nom pris dans HA)
  3. traqueurs réseau (Livebox, device_tracker) et application mobile, en dernier recours
"""
import base64
import ipaddress
import json
import os
import re
import socket
import struct
import urllib.parse

# Domaines dont le nom est un simple « nom de secours » (moins fiable)
LOW_PRIORITY = {"livebox", "device_tracker", "upnp", "dlna_dmr", "wake_on_lan", "nmap_tracker", "ping"}

HA_TEMPLATE = r"""
{%- set ns = namespace(o=[]) -%}
{%- for dev in states | map(attribute='entity_id') | map('device_id') | reject('none') | unique -%}
  {%- set doms = (device_attr(dev,'config_entries') or []) | map('config_entry_attr','domain') | reject('none') | list -%}
  {%- set m = namespace(macs=(device_attr(dev,'connections') or []) | selectattr(0,'eq','mac') | map(attribute=1) | map('lower') | list, ips=[]) -%}
  {%- for e in device_entities(dev) -%}
    {%- for k in ['ip','ip_address','host','ipv4','local_ip'] -%}
      {%- set a = state_attr(e,k) -%}
      {%- if a is string and a | regex_match('^\d+\.\d+\.\d+\.\d+$') -%}{%- set m.ips = m.ips + [a] -%}{%- endif -%}
    {%- endfor -%}
    {%- for k in ['mac','mac_address'] -%}
      {%- set a = state_attr(e,k) -%}
      {%- if a is string and a | regex_match('^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$') -%}{%- set m.macs = m.macs + [a | lower | replace('-',':')] -%}{%- endif -%}
    {%- endfor -%}
    {%- set st = states(e) -%}
    {%- if st | regex_match('^\d+\.\d+\.\d+\.\d+$') -%}{%- set m.ips = m.ips + [st] -%}{%- endif -%}
  {%- endfor -%}
  {%- set ids = (device_attr(dev,'identifiers') or []) | map(attribute=1) | map('string') | select('search','MatterNodeDevice') | list -%}
  {%- if m.macs or m.ips or ids -%}
    {%- set ns.o = ns.o + [{'n': device_attr(dev,'name_by_user') or device_attr(dev,'name'), 'd': doms[0] if doms else '',
        'mf': device_attr(dev,'manufacturer'), 'mo': device_attr(dev,'model'),
        'macs': m.macs | unique | list, 'ips': m.ips | unique | list, 'ids': ids}] -%}
  {%- endif -%}
{%- endfor -%}
{%- for s in states.device_tracker -%}
  {%- if device_id(s.entity_id) is none and (s.attributes.ip is defined or s.attributes.mac is defined) -%}
    {%- set ns.o = ns.o + [{'n': s.name, 'd': 'device_tracker', 'mf': none, 'mo': none,
        'macs': [s.attributes.mac | lower] if s.attributes.mac is string else [],
        'ips': [s.attributes.ip] if s.attributes.ip is string else [], 'ids': []}] -%}
  {%- endif -%}
{%- endfor -%}
{{ ns.o | tojson }}
"""


# ----------------------------------------------------------- client WebSocket
class _WS:
    """Client WebSocket minimal (texte, sans extension) — suffisant pour le Matter Server."""

    def __init__(self, url, timeout=20):
        u = urllib.parse.urlparse(url)
        self.sock = socket.create_connection((u.hostname, u.port or 80), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f"GET {u.path or '/'} HTTP/1.1\r\nHost: {u.hostname}:{u.port or 80}\r\n"
                           f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("handshake WebSocket interrompu")
            self.buf += chunk
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise ConnectionError(head.split(b"\r\n", 1)[0].decode(errors="replace"))

    def _read(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("connexion WebSocket fermée")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _send(self, opcode, data):
        hdr = bytes([0x80 | opcode])
        n = len(data)
        if n < 126:
            hdr += bytes([0x80 | n])
        elif n < 65536:
            hdr += bytes([0x80 | 126]) + struct.pack("!H", n)
        else:
            hdr += bytes([0x80 | 127]) + struct.pack("!Q", n)
        mask = os.urandom(4)
        self.sock.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def send_json(self, obj):
        self._send(0x1, json.dumps(obj).encode())

    def recv_json(self):
        parts = []
        while True:
            b1, b2 = self._read(2)
            fin, opcode, n = b1 & 0x80, b1 & 0x0F, b2 & 0x7F
            if n == 126:
                n = struct.unpack("!H", self._read(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", self._read(8))[0]
            mask = self._read(4) if b2 & 0x80 else None
            data = self._read(n)
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if opcode == 0x8:
                raise ConnectionError("WebSocket fermé par le serveur")
            if opcode == 0x9:
                self._send(0xA, data)
                continue
            if opcode in (0x1, 0x2, 0x0):
                parts.append(data)
                if fin:
                    return json.loads(b"".join(parts))

    def close(self):
        try:
            self._send(0x8, b"")
        except OSError:
            pass
        self.sock.close()


def matter_nodes(url, timeout=20):
    """Nœuds Matter en Wi-Fi/Ethernet : [{node_id, mac, ips, vendor, product, label}]."""
    ws = _WS(url, timeout)
    try:
        ws.send_json({"message_id": "netscan", "command": "get_nodes"})
        for _ in range(200):
            msg = ws.recv_json()
            if isinstance(msg, dict) and msg.get("message_id") == "netscan":
                nodes = msg.get("result") or []
                break
        else:
            return []
    finally:
        ws.close()
    out = []
    for n in nodes:
        attrs = n.get("attributes") or {}
        for itf in attrs.get("0/51/0") or []:
            if itf.get("7") not in (1, 2):  # 1 = Wi-Fi, 2 = Ethernet (4 = Thread : pas d'IPv4)
                continue
            try:
                raw = base64.b64decode(itf.get("4") or "")
                mac = ":".join(f"{b:02x}" for b in raw) if len(raw) == 6 else None
                ips = [str(ipaddress.IPv4Address(base64.b64decode(x))) for x in itf.get("5") or []]
            except (ValueError, TypeError):
                continue
            out.append({"node_id": n.get("node_id"), "mac": mac, "ips": ips,
                        "vendor": attrs.get("0/40/1"), "product": attrs.get("0/40/3"),
                        "label": attrs.get("0/40/5") or None})
    return out


# ------------------------------------------------------------------- index
GENERIC = re.compile(r"^(device-\d+|none(-\d+)?|unknown|linux|localhost|lwip\d*|esp[-_]?[0-9a-f]*|android-[0-9a-f]+)$", re.I)


def clean(name):
    """Décode les échappements mDNS (\\032 = espace) ; None si nom générique."""
    if not name:
        return None
    name = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), str(name)).strip()
    return None if GENERIC.match(name) else name


def build_index(ha_devices, mnodes):
    """Retourne (par_mac, par_ip) : clé -> {name, domain, model, manufacturer}."""
    by_mac, by_ip = {}, {}

    def put(table, key, info):
        if not key:
            return
        cur = table.get(key)
        # un nom « fiable » (intégration dédiée) remplace un nom de secours, pas l'inverse
        if cur is None or (cur["domain"] in LOW_PRIORITY and info["domain"] not in LOW_PRIORITY):
            table[key] = info

    matter_ha = {}
    for d in ha_devices:
        info = {"name": clean(d.get("n")), "domain": d.get("d") or "",
                "manufacturer": d.get("mf"), "model": d.get("mo")}
        for i in d.get("ids") or []:
            parts = str(i).split("-")
            if len(parts) >= 3:
                try:
                    matter_ha[int(parts[1], 16)] = info
                except ValueError:
                    pass
        if not info["name"]:
            continue
        for m in d.get("macs") or []:
            put(by_mac, m.lower(), info)
        for ip in d.get("ips") or []:
            put(by_ip, ip, info)

    for n in mnodes:
        ha = matter_ha.get(n["node_id"])
        name = (ha or {}).get("name") or n["label"] or " ".join(x for x in (n["vendor"], n["product"]) if x)
        info = {"name": name, "domain": "matter",
                "manufacturer": n["vendor"], "model": n["product"]}
        put(by_mac, n["mac"], info)
        for ip in n["ips"]:
            put(by_ip, ip, info)
    return by_mac, by_ip


def apply(devices, by_mac, by_ip):
    """Ajoute ha_name / ha_domain / ha_model à chaque équipement ; retourne le nombre identifié."""
    found = 0
    for d in devices.values():
        cands = [c for c in (by_mac.get((d.get("mac") or "").lower()) if d.get("mac") else None,
                             by_ip.get(d.get("ip"))) if c]
        cands.sort(key=lambda c: c["domain"] in LOW_PRIORITY)  # nom d'intégration dédiée d'abord
        info = cands[0] if cands else None
        if info:
            found += 1
            d["ha_name"], d["ha_domain"] = info["name"], info["domain"]
            mf, mo = info.get("manufacturer") or "", info.get("model") or ""
            d["ha_model"] = (mo if mf and mo.lower().startswith(mf.lower()) else f"{mf} {mo}").strip() or None
        else:
            d.pop("ha_name", None), d.pop("ha_domain", None), d.pop("ha_model", None)
        # libellé affiché : intégration dédiée > nom Pi-hole/DNS > nom de secours (Livebox…)
        if info and info["domain"] not in LOW_PRIORITY:
            d["label"] = info["name"]
        else:
            d["label"] = d.get("name") or (info or {}).get("name")
    return found
