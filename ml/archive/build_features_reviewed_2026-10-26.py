#!/usr/bin/env python3
r"""
build_features.py - Convierte el Parquet crudo (export_wazuh.py) en una tabla
de features por ventana de tiempo e imprime un INFORME DE PREPARACION.

Una fila = una ventana de 5 min. Las columnas describen el comportamiento de
esa ventana (procesos, logons, puertos, DNS, etc.). Eso es lo que entrena el
modelo.

Uso:
    python build_features.py --in ..\..\data\raw_T0.parquet --out ..\..\data\features_T0.parquet --labels ..\..\data\attack_windows.csv

--labels es opcional; si no hay ataques (piloto) todas las ventanas quedan label=0.
"""
import argparse
import os

import numpy as np
import pandas as pd


def to_utc(series):
    return pd.to_datetime(series, utc=True, errors="coerce")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--labels", default=None, help="attack_windows.csv (opcional)")
    ap.add_argument("--window", default="5min")
    a = ap.parse_args()

    df = pd.read_parquet(a.inp)
    df["event_time"] = to_utc(df["event_time"])
    df = df.dropna(subset=["event_time"]).sort_values("event_time")
    if df.empty:
        print("El Parquet no tiene eventos con event_time valido. Nada que hacer.")
        return
    df["win"] = df["event_time"].dt.floor(a.window)

    # Columnas booleanas/numericas auxiliares (mas rapido que apply)
    df["is_win"] = df.source == "windows"
    df["is_suri"] = df.source == "suricata"
    df["is_proc"] = df.win_eventid == "1"      # Sysmon: creacion de proceso
    df["is_4625"] = df.win_eventid == "4625"   # logon fallido
    df["is_4624"] = df.win_eventid == "4624"   # logon exitoso
    df["is_4104"] = df.win_eventid == "4104"   # PowerShell script block
    df["has_http"] = df.http_host.notna()
    df["has_alert"] = df.alert_sig.notna()
    df["lvl"] = pd.to_numeric(df.rule_level, errors="coerce")
    df["is_lvl8"] = df["lvl"] >= 8

    grp = df.groupby("win")
    feats = grp.agg(
        ev_total=("source", "size"),
        ev_windows=("is_win", "sum"),
        ev_suricata=("is_suri", "sum"),
        # --- host ---
        proc_creates=("is_proc", "sum"),
        img_unique=("win_image", "nunique"),
        logon_fail=("is_4625", "sum"),
        logon_ok=("is_4624", "sum"),
        ps_blocks=("is_4104", "sum"),
        ps_len_max=("ps_len", "max"),
        # --- red ---
        dst_ip_unique=("suri_dst", "nunique"),
        dport_unique=("suri_dport", "nunique"),
        dns_unique=("dns_q", "nunique"),
        tls_unique=("tls_sni", "nunique"),
        http_reqs=("has_http", "sum"),
        flow_out=("flow_toserver", "sum"),
        flow_in=("flow_toclient", "sum"),
        suri_alerts=("has_alert", "sum"),
        # --- linea base de reglas (para comparar con el ML) ---
        wazuh_alerts_lvl8plus=("is_lvl8", "sum"),
    ).fillna(0)

    # Etiqueta por solapamiento con ventanas de ataque
    feats["label"] = 0
    if a.labels and os.path.exists(a.labels):
        aw = pd.read_csv(a.labels, comment="#")
        aw["start_utc"] = to_utc(aw["start_utc"])
        aw["end_utc"] = to_utc(aw["end_utc"])
        idx = feats.index
        for _, row in aw.dropna(subset=["start_utc", "end_utc"]).iterrows():
            hit = (idx >= row.start_utc.floor(a.window)) & (idx <= row.end_utc)
            feats.loc[hit, "label"] = 1

    out_dir = os.path.dirname(a.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    feats.to_parquet(a.out)

    # ---------------- INFORME DE PREPARACION ----------------
    line = "=" * 52
    print(line)
    print("INFORME DE PREPARACION DEL DATASET")
    print(line)
    print(f"Ventanas ({a.window}): {len(feats)}")
    print(f"Rango UTC: {feats.index.min()}  ->  {feats.index.max()}")
    span_h = (feats.index.max() - feats.index.min()).total_seconds() / 3600
    print(f"Horas cubiertas (aprox): {span_h:.1f}")
    print(f"Ventanas de ataque (label=1): {int(feats.label.sum())}")

    const = [c for c in feats.columns if c != "label" and feats[c].nunique() <= 1]
    print("\nColumnas constantes (no aportan, revisar):")
    print("  ", const if const else "ninguna")

    print("\nMedia por feature:")
    print(feats.drop(columns=["label"]).mean().round(2).to_string())

    # dia/noche en hora local (Guayaquil, UTC-5)
    local = feats.index.tz_convert("America/Guayaquil")
    is_day = (local.hour >= 8) & (local.hour < 18)
    print(f"\nVentanas de dia (08-18 local): {int(is_day.sum())}  |  noche: {int((~is_day).sum())}")
    print("Red presente -> "
          f"DNS: {'si' if feats.dns_unique.sum() > 0 else 'NO'} | "
          f"TLS: {'si' if feats.tls_unique.sum() > 0 else 'NO'} | "
          f"HTTP: {'si' if feats.http_reqs.sum() > 0 else 'NO'}")
    print(f"PowerShell 4104 presente: {'si' if feats.ps_blocks.sum() > 0 else 'NO (datos pre-4104 / piloto)'}")
    print(line)
    print(f"Features guardadas en: {a.out}")


if __name__ == "__main__":
    main()
