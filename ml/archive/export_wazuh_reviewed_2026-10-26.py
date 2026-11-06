#!/usr/bin/env python3
r"""
export_wazuh.py - Exporta eventos de wazuh-archives-* a un archivo Parquet
para alimentar el pipeline de ML del Home SOC.

Corre en el HOST (que alcanza el indexador en WAZUH_MANAGER_IP:9200),
o en el propio Ubuntu usando WAZUH_HOST=https://localhost:9200.

Uso (PowerShell en el host):
    $env:WAZUH_PASS="TU_CLAVE"
    python export_wazuh.py --start 2026-10-26T18:30:00Z --end 2026-10-27T06:00:00Z --out ..\..\data\raw_T0.parquet

- Las horas van en UTC (ISO 8601, con Z).
- Excluye fuentes de ruido (sca, syscollector, etc.) que no sirven como features.
- NO guarda credenciales: la clave se lee de la variable de entorno WAZUH_PASS.
"""
import os
import sys
import json
import argparse
import warnings

import requests
import pandas as pd

warnings.filterwarnings("ignore")  # certificado self-signed del lab

HOST = os.environ.get("WAZUH_HOST", "https://WAZUH_MANAGER_IP:9200")
USER = os.environ.get("WAZUH_USER", "admin")
PASS = os.environ.get("WAZUH_PASS")
INDEX = "wazuh-archives-*"

# Fuentes (campo "location") que NO entran al dataset: escaneos periodicos
# e inventario/automonitoreo de Wazuh, no son comportamiento del host.
NOISE = {
    "sca", "syscollector", "rootcheck", "df -P", "last -n 20",
    "netstat listening ports", "journald", "/var/log/dpkg.log", "wazuh-agent",
}


def g(d, *path, default=None):
    """Getter seguro para campos anidados."""
    for k in path:
        if isinstance(d, dict) and k in d:
            d = d[k]
        else:
            return default
    return d


def source_of(location):
    if location == "EventChannel":
        return "windows"
    if location and "eve.json" in location:
        return "suricata"
    return "other"


def event_time(src, s):
    """Hora del EVENTO (no la de ingesta de Wazuh). Clave: los flow de
    Suricata llegan ~5 min tarde, asi que para las ventanas usamos la
    hora real del evento."""
    if src == "suricata":
        return g(s, "data", "flow", "start") or g(s, "data", "timestamp") or s.get("timestamp")
    if src == "windows":
        return g(s, "data", "win", "system", "systemTime") or s.get("timestamp")
    return s.get("timestamp")


def flatten(s):
    loc = s.get("location")
    src = source_of(loc)
    sbt = g(s, "data", "win", "eventdata", "scriptBlockText")
    return {
        "ts_ingest": s.get("timestamp"),
        "event_time": event_time(src, s),
        "source": src,
        "agent": g(s, "agent", "name"),
        "rule_id": g(s, "rule", "id"),
        "rule_level": g(s, "rule", "level"),
        "rule_groups": ",".join(g(s, "rule", "groups", default=[]) or []),
        # --- host (Windows / Sysmon / Security / PowerShell) ---
        "win_eventid": g(s, "data", "win", "system", "eventID"),
        "win_channel": g(s, "data", "win", "system", "channel"),
        "win_image": g(s, "data", "win", "eventdata", "image"),
        "win_parent": g(s, "data", "win", "eventdata", "parentImage"),
        "win_logontype": g(s, "data", "win", "eventdata", "logonType"),
        "win_ip": g(s, "data", "win", "eventdata", "ipAddress"),
        "ps_len": len(sbt) if sbt else 0,
        # --- red (Suricata) ---
        "suri_type": g(s, "data", "event_type"),
        "suri_src": g(s, "data", "src_ip"),
        "suri_dst": g(s, "data", "dest_ip"),
        "suri_dport": g(s, "data", "dest_port"),
        "suri_proto": g(s, "data", "proto"),
        "dns_q": g(s, "data", "dns", "rrname"),
        "tls_sni": g(s, "data", "tls", "sni"),
        "http_host": g(s, "data", "http", "hostname"),
        "flow_toserver": g(s, "data", "flow", "bytes_toserver"),
        "flow_toclient": g(s, "data", "flow", "bytes_toclient"),
        "alert_sig": g(s, "data", "alert", "signature"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", required=True, help="UTC ISO, p.ej. 2026-10-26T18:30:00Z")
    ap.add_argument("--end", required=True, help="UTC ISO (exclusivo)")
    ap.add_argument("--out", required=True, help="ruta del Parquet de salida")
    a = ap.parse_args()

    if not PASS:
        sys.exit("ERROR: falta la variable de entorno WAZUH_PASS")

    body = {"size": 2000, "query": {"range": {"timestamp": {"gte": a.start, "lt": a.end}}}}
    hdr = {"Content-Type": "application/json"}

    r = requests.get(f"{HOST}/{INDEX}/_search?scroll=2m", auth=(USER, PASS),
                     verify=False, headers=hdr, data=json.dumps(body))
    r.raise_for_status()
    j = r.json()
    sid = j.get("_scroll_id")

    rows, kept, dropped = [], 0, 0
    while True:
        hits = j.get("hits", {}).get("hits", [])
        if not hits:
            break
        for h in hits:
            s = h["_source"]
            if s.get("location") in NOISE:
                dropped += 1
                continue
            rows.append(flatten(s))
            kept += 1
        r = requests.get(f"{HOST}/_search/scroll", auth=(USER, PASS), verify=False,
                         headers=hdr, data=json.dumps({"scroll": "2m", "scroll_id": sid}))
        j = r.json()
        sid = j.get("_scroll_id")

    df = pd.DataFrame(rows)
    out_dir = os.path.dirname(a.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    df.to_parquet(a.out, index=False)

    print(f"Exportados {kept} eventos (descartados {dropped} de ruido) -> {a.out}")
    if len(df):
        print("Rango event_time:", df.event_time.min(), "->", df.event_time.max())
        print("Por fuente:")
        print(df.source.value_counts().to_string())


if __name__ == "__main__":
    main()
