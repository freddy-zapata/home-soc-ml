#!/usr/bin/env python3
r"""
export_wazuh.py - Exporta eventos de wazuh-archives-* a un Parquet para el
pipeline de ML del Home SOC.

Correcciones de la auditoria 2026-10-26 (protocolo v0.2):
- Valida el scroll en CADA peticion: ante un error intermedio aborta SIN exito
  y SIN escribir el Parquet final (nada de exportaciones a medias).
- Guarda `available_at` (hora de ingesta) ademas de `event_time` (hora del
  evento), para la causalidad temporal del protocolo.
- Guarda `agent_id` y `flow_id`.
- DNS: extrae rrname de v2 (dns.rrname) y v3 (dns.queries[].rrname).
- Bytes de red SOLO desde eventos `flow` (no desde `alert`, que embebe un flow
  y duplicaria los bytes).
- Conserva el canal de Windows (`win_channel`) para distinguir EventIDs por
  canal en las features.

Corre en el HOST (que alcanza el indexador). La clave se lee de WAZUH_PASS.

Uso (PowerShell en el host):
    $env:WAZUH_PASS="TU_CLAVE"
    python export_wazuh.py --start 2026-10-26T18:30:00Z --end 2026-10-27T06:00:00Z --out ..\..\data\raw_T0.parquet
"""
import os
import sys
import json
import argparse
import warnings

import requests
import pandas as pd

warnings.filterwarnings("ignore")  # certificado self-signed del lab

HOST = os.environ.get("WAZUH_HOST", "https://192.168.119.153:9200")
USER = os.environ.get("WAZUH_USER", "admin")
PASS = os.environ.get("WAZUH_PASS")
INDEX = "wazuh-archives-*"

NOISE = {
    "sca", "syscollector", "rootcheck", "df -P", "last -n 20",
    "netstat listening ports", "journald", "/var/log/dpkg.log", "wazuh-agent",
}


def g(d, *path, default=None):
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
    """Hora del EVENTO (no la de ingesta). Los flow de Suricata llegan ~5 min
    tarde, por eso las ventanas usan esta hora, no la de ingesta."""
    if src == "suricata":
        return g(s, "data", "flow", "start") or g(s, "data", "timestamp") or s.get("timestamp")
    if src == "windows":
        return g(s, "data", "win", "system", "systemTime") or s.get("timestamp")
    return s.get("timestamp")


def dns_query(s):
    """rrname de la consulta DNS, soportando eve v2 y v3."""
    dns = g(s, "data", "dns")
    if not isinstance(dns, dict):
        return None
    if dns.get("rrname"):
        return dns["rrname"]
    qs = dns.get("queries")
    if isinstance(qs, list) and qs and isinstance(qs[0], dict):
        return qs[0].get("rrname")
    return None


def flatten(s):
    loc = s.get("location")
    src = source_of(loc)
    sbt = g(s, "data", "win", "eventdata", "scriptBlockText")
    etype = g(s, "data", "event_type")
    is_flow = etype in ("flow", "netflow")  # solo aqui hay bytes "reales"
    return {
        "available_at": s.get("timestamp"),       # hora de ingesta en Wazuh
        "event_time": event_time(src, s),         # hora del evento
        "source": src,
        "agent_name": g(s, "agent", "name"),
        "agent_id": g(s, "agent", "id"),
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
        "suri_type": etype,
        "flow_id": g(s, "data", "flow_id"),
        "suri_src": g(s, "data", "src_ip"),
        "suri_dst": g(s, "data", "dest_ip"),
        "suri_dport": g(s, "data", "dest_port"),
        "suri_proto": g(s, "data", "proto"),
        "dns_q": dns_query(s),
        "tls_sni": g(s, "data", "tls", "sni"),
        "http_host": g(s, "data", "http", "hostname"),
        "flow_toserver": g(s, "data", "flow", "bytes_toserver") if is_flow else None,
        "flow_toclient": g(s, "data", "flow", "bytes_toclient") if is_flow else None,
        "alert_sig": g(s, "data", "alert", "signature"),
        "alert_sid": g(s, "data", "alert", "signature_id"),
    }


def _check(resp, ctx):
    """Valida una respuesta del indexador; lanza si hay cualquier problema."""
    resp.raise_for_status()
    j = resp.json()
    sh = j.get("_shards", {})
    if sh.get("failed"):
        raise RuntimeError(f"{ctx}: {sh.get('failed')} shards fallaron")
    if j.get("timed_out"):
        raise RuntimeError(f"{ctx}: la consulta expiro (timed_out)")
    return j


def run_export(start, end):
    """Devuelve un DataFrame con el tramo [start, end). Lanza si algo falla
    a mitad del scroll (no deja datos parciales)."""
    if not PASS:
        raise SystemExit("ERROR: falta la variable de entorno WAZUH_PASS")
    hdr = {"Content-Type": "application/json"}
    body = {"size": 2000, "query": {"range": {"timestamp": {"gte": start, "lt": end}}}}

    j = _check(requests.get(f"{HOST}/{INDEX}/_search?scroll=2m", auth=(USER, PASS),
                            verify=False, headers=hdr, data=json.dumps(body)),
               "busqueda inicial")
    sid = j.get("_scroll_id")
    rows, kept, dropped = [], 0, 0
    try:
        while True:
            hits = j.get("hits", {}).get("hits", [])
            if not hits:
                break
            for h in hits:
                s = h.get("_source", {})
                if s.get("location") in NOISE:
                    dropped += 1
                    continue
                rows.append(flatten(s))
                kept += 1
            if not sid:
                raise RuntimeError("scroll sin _scroll_id a mitad del recorrido")
            j = _check(requests.get(f"{HOST}/_search/scroll", auth=(USER, PASS),
                                    verify=False, headers=hdr,
                                    data=json.dumps({"scroll": "2m", "scroll_id": sid})),
                       "scroll")
            sid = j.get("_scroll_id")
    finally:
        if sid:
            try:
                requests.delete(f"{HOST}/_search/scroll", auth=(USER, PASS), verify=False,
                                headers=hdr, data=json.dumps({"scroll_id": [sid]}))
            except Exception:
                pass
    return pd.DataFrame(rows), kept, dropped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", required=True, help="UTC ISO, p.ej. 2026-10-26T18:30:00Z")
    ap.add_argument("--end", required=True, help="UTC ISO (exclusivo)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    df, kept, dropped = run_export(a.start, a.end)   # si falla, no se escribe nada

    out_dir = os.path.dirname(a.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    df.to_parquet(a.out, index=False)

    print(f"OK: {kept} eventos exportados (descartados {dropped} de ruido) -> {a.out}")
    if len(df):
        print("Rango event_time:", df.event_time.min(), "->", df.event_time.max())
        print("Por fuente:")
        print(df.source.value_counts().to_string())
    else:
        print("ADVERTENCIA: 0 eventos en el rango. Revisa --start/--end (UTC).")


if __name__ == "__main__":
    main()
