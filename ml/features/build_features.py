#!/usr/bin/env python3
r"""
build_features.py - Convierte el Parquet crudo (export_wazuh.py) en features
por (entidad, ventana de 5 min) e imprime un INFORME DE PREPARACION.

Correcciones de la auditoria 2026-10-26 (protocolo v0.2):
- Agrupa por (entidad = agent_id, ventana), NO solo por ventana (antes mezclaba
  equipos).
- EventIDs sensibles al CANAL (Sysmon 1, Security 4624/4625, PowerShell 4104),
  no solo por numero.
- Etiquetas con limites SEMIABIERTOS [inicio, fin) (antes incluia una ventana de
  mas con `<= fin`).
- Si se pide --labels y el archivo no existe -> ERROR (antes lo ignoraba).
- La "cobertura" NO se infiere del tiempo entre el primer y el ultimo evento;
  se reporta el numero de ventanas con datos (la cobertura real viene del
  manifiesto de sesiones, protocolo v0.2 §5).
- Columnas derivadas de reglas van con prefijo `diag_` y NO son features del
  modelo (protocolo §7). `label` se guarda aparte.

Uso:
    python build_features.py --in ..\..\data\raw_T0.parquet --out ..\..\data\features_T0.parquet [--labels ..\..\data\attack_windows.csv]
"""
import argparse
import os
import sys

import pandas as pd

# Features del MODELO (sin columnas de reglas, sin label, sin claves).
# Esta lista es la fuente de verdad; FEATURES.md la documenta.
MODEL_FEATURES = [
    "n_events", "n_win_events", "n_suri_events",
    "proc_creates", "img_unique", "logon_fail", "logon_ok",
    "ps_blocks", "ps_len_max",
    "dst_ip_unique", "dport_unique", "dns_unique", "tls_unique",
    "http_reqs", "flow_out", "flow_in",
]
DIAG_COLS = ["diag_suri_alerts", "diag_wazuh_alerts_lvl8plus"]  # NO entran al modelo


def to_utc(series):
    return pd.to_datetime(series, utc=True, errors="coerce")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--labels", default=None, help="attack_windows.csv (opcional)")
    ap.add_argument("--window", default="5min")
    a = ap.parse_args()

    # --- etiquetas: si se piden y no existen, es ERROR (no seguir en silencio) ---
    attacks = None
    if a.labels is not None:
        if not os.path.exists(a.labels):
            sys.exit(f"ERROR: se pidio --labels pero no existe el archivo: {a.labels}")
        attacks = pd.read_csv(a.labels, comment="#")
        for col in ("start_utc", "end_utc"):
            if col not in attacks.columns:
                sys.exit(f"ERROR: el CSV de etiquetas no tiene la columna '{col}'")
        attacks["start_utc"] = to_utc(attacks["start_utc"])
        attacks["end_utc"] = to_utc(attacks["end_utc"])
        bad = attacks[attacks.start_utc.isna() | attacks.end_utc.isna()]
        if len(bad):
            sys.exit(f"ERROR: {len(bad)} fila(s) de etiquetas con fechas invalidas")

    df = pd.read_parquet(a.inp)
    df["event_time"] = to_utc(df["event_time"])
    df = df.dropna(subset=["event_time"]).sort_values("event_time")
    if df.empty:
        sys.exit("ERROR: el Parquet no tiene eventos con event_time valido.")

    # entidad = agent_id (fallback a nombre); ventana por hora del evento
    df["entity"] = df.get("agent_id")
    df["entity"] = df["entity"].fillna(df.get("agent_name")).fillna("unknown")
    df["win"] = df["event_time"].dt.floor(a.window)

    chan = df["win_channel"].fillna("") if "win_channel" in df else ""
    eid = df["win_eventid"]
    df["is_win"] = df["source"] == "windows"
    df["is_suri"] = df["source"] == "suricata"
    df["is_proc"] = (eid == "1") & chan.str.contains("Sysmon", case=False)
    df["is_4625"] = (eid == "4625") & chan.str.contains("Security", case=False)
    df["is_4624"] = (eid == "4624") & chan.str.contains("Security", case=False)
    df["is_4104"] = (eid == "4104")  # solo el canal PowerShell emite 4104
    df["has_http"] = df["http_host"].notna()
    df["has_alert"] = df["alert_sig"].notna()
    df["lvl"] = pd.to_numeric(df["rule_level"], errors="coerce")
    df["is_lvl8"] = df["lvl"] >= 8

    grp = df.groupby(["entity", "win"])
    feats = grp.agg(
        n_events=("source", "size"),
        n_win_events=("is_win", "sum"),
        n_suri_events=("is_suri", "sum"),
        proc_creates=("is_proc", "sum"),
        img_unique=("win_image", "nunique"),
        logon_fail=("is_4625", "sum"),
        logon_ok=("is_4624", "sum"),
        ps_blocks=("is_4104", "sum"),
        ps_len_max=("ps_len", "max"),
        dst_ip_unique=("suri_dst", "nunique"),
        dport_unique=("suri_dport", "nunique"),
        dns_unique=("dns_q", "nunique"),
        tls_unique=("tls_sni", "nunique"),
        http_reqs=("has_http", "sum"),
        flow_out=("flow_toserver", "sum"),
        flow_in=("flow_toclient", "sum"),
        diag_suri_alerts=("has_alert", "sum"),
        diag_wazuh_alerts_lvl8plus=("is_lvl8", "sum"),
    ).fillna(0).reset_index()

    # --- etiqueta por solapamiento SEMIABIERTO [inicio, fin) ---
    feats["label"] = 0
    if attacks is not None:
        wlen = pd.Timedelta(a.window)
        win = feats["win"]
        for _, row in attacks.iterrows():
            # una ventana [w, w+wlen) solapa el ataque [s, e)  <=>  w < e  y  w+wlen > s
            hit = (win < row.end_utc) & (win + wlen > row.start_utc)
            feats.loc[hit, "label"] = 1

    out_dir = os.path.dirname(a.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    feats.to_parquet(a.out, index=False)

    # ------------------- INFORME DE PREPARACION -------------------
    line = "=" * 56
    print(line)
    print("INFORME DE PREPARACION DEL DATASET")
    print(line)
    print(f"Ventanas (entidad x {a.window}): {len(feats)}")
    print(f"Entidades: {feats.entity.nunique()}  -> {sorted(feats.entity.unique())}")
    print(f"Rango event_time observado (NO es cobertura): "
          f"{df.event_time.min()} -> {df.event_time.max()}")
    print("  (la cobertura real sale del manifiesto de sesiones, no de este rango)")
    print(f"Ventanas con eventos de host:     {(feats.n_win_events > 0).sum()}")
    print(f"Ventanas con eventos de Suricata: {(feats.n_suri_events > 0).sum()}")
    print(f"Ventanas etiquetadas como ataque: {int(feats.label.sum())}")

    present = [c for c in MODEL_FEATURES if c in feats]
    const = [c for c in present if feats[c].nunique() <= 1]
    print("\nFeatures del modelo constantes (revisar, no aportan):")
    print("  ", const if const else "ninguna")

    print("\nMedia por feature del modelo:")
    print(feats[present].mean().round(2).to_string())

    local = feats["win"].dt.tz_convert("America/Guayaquil")
    is_day = (local.dt.hour >= 8) & (local.dt.hour < 18)
    print(f"\nVentanas de dia (08-18 local): {int(is_day.sum())}  |  noche: {int((~is_day).sum())}")
    print("Red presente -> "
          f"DNS: {'si' if feats.dns_unique.sum() > 0 else 'NO'} | "
          f"TLS: {'si' if feats.tls_unique.sum() > 0 else 'NO'} | "
          f"HTTP: {'si' if feats.http_reqs.sum() > 0 else 'NO'}")
    print(f"PowerShell 4104 presente: {'si' if feats.ps_blocks.sum() > 0 else 'NO (datos pre-4104 / piloto)'}")
    print(f"\nColumnas diagnostico (NO son features del modelo): {DIAG_COLS}")
    print(line)
    print(f"OK -> features guardadas en: {a.out}")


if __name__ == "__main__":
    main()
