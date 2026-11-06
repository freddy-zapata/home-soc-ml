#!/usr/bin/env python3
r"""
build_features.py - Turn the raw Parquet (from export_wazuh.py) into a
per-(entity, 5-min window) feature table and print a READINESS REPORT.

Audit fixes (2026-10-27, protocol v0.2):
- Group by (entity = agent_id, window); never mix hosts.
- Channel-aware EventIDs (Sysmon 1, Security 4624/4625, PowerShell 4104).
- EventID NORMALIZED (string, stripped) before any comparison.
- Labels apply ONLY to the TARGET entity of each attack (target_host), not to
  every entity at that time.
- Attack registry `status` is honoured: only status == "executed" produces
  label=1. attempted/failed windows are EXCLUDED (not treated as benign).
- Exclusion ranges (cleanup_end_utc / excluded_until_utc) mark windows as
  EXCLUDED so prep/cleanup are not counted as normal.
- INVERTED or zero-length intervals (start >= end) are rejected with an error.
- Half-open labelling [start, end).
- `available_at` is APPLIED as a causal cutoff: an event feeds a window only if
  it was available by (window_close + grace); later events are counted apart
  and never leak into that window's features.
- Rule-derived columns are `diag_` and excluded from the model (protocol §7).

Usage:
    python build_features.py --in raw.parquet --out features.parquet \
        [--labels attack_windows.csv] [--window 5min] [--grace 10min]
"""
import argparse
import os
import sys

import pandas as pd

# Model features (no rule columns, no label, no keys). FEATURES.md documents them.
# Volume is captured PER SOURCE (n_win_events, n_suri_events), never as a single
# total: FIM/other coverage changed mid-dataset (27-oct), so a total event count
# would not be comparable across that boundary. "other" (FIM/syscheck) events are
# tracked as a diagnostic only, never as a model feature.
MODEL_FEATURES = [
    "n_win_events", "n_suri_events",
    "proc_creates", "img_unique", "logon_fail", "logon_ok",
    "ps_blocks", "ps_len_max",
    "dst_ip_unique", "dport_unique", "dns_unique", "tls_unique",
    "http_reqs", "flow_out", "flow_in",
]
DIAG_COLS = ["diag_total_events", "diag_other_events",
             "diag_suri_alerts", "diag_wazuh_alerts_lvl8plus"]


def to_utc(s):
    return pd.to_datetime(s, utc=True, errors="coerce")


def load_attacks(path):
    """Load and validate the attack registry. Rejects inverted intervals."""
    aw = pd.read_csv(path, comment="#")
    for col in ("start_utc", "end_utc"):
        if col not in aw.columns:
            sys.exit(f"ERROR: labels CSV missing required column '{col}'")
    aw["start_utc"] = to_utc(aw["start_utc"])
    aw["end_utc"] = to_utc(aw["end_utc"])
    bad = aw[aw.start_utc.isna() | aw.end_utc.isna()]
    if len(bad):
        sys.exit(f"ERROR: {len(bad)} label row(s) with invalid dates")
    inv = aw[aw.start_utc >= aw.end_utc]
    if len(inv):
        ids = inv.get("attack_id", pd.Series(inv.index)).tolist()
        sys.exit(f"ERROR: inverted/zero-length interval(s) (start >= end): {ids}")
    # optional columns with safe defaults
    if "status" not in aw.columns:
        aw["status"] = "executed"
    aw["status"] = aw["status"].fillna("executed").astype(str).str.strip().str.lower()
    if "target_host" not in aw.columns:
        aw["target_host"] = None
    for c in ("cleanup_end_utc", "excluded_until_utc"):
        if c not in aw.columns:
            aw[c] = pd.NaT
        aw[c] = to_utc(aw[c])   # tz-aware (NaT stays tz-aware) so comparisons are safe
    # cleanup/exclusion end, when present, must not precede the attack end
    for c in ("cleanup_end_utc", "excluded_until_utc"):
        bad_c = aw[aw[c].notna() & (aw[c] < aw.end_utc)]
        if len(bad_c):
            ids = bad_c.get("attack_id", pd.Series(bad_c.index)).tolist()
            sys.exit(f"ERROR: {c} precedes end_utc in: {ids}")
    return aw


def label_and_exclude(feats, entmap, attacks, wlen):
    """label=1 only for executed attacks on the target entity, half-open;
    prep/cleanup and attempted/failed ranges -> excluded=True."""
    feats["label"] = 0
    feats["excluded"] = False
    win = feats["win"]

    def overlap(a, b):
        return (win < b) & (win + wlen > a)

    def target_entities(th):
        if th is None or (isinstance(th, float) and pd.isna(th)):
            return set(feats.entity.unique())            # unknown target -> all
        th = str(th).strip().lower()
        ents = set()
        for e, names in entmap.items():
            cand = {str(e).lower()} | {str(n).lower() for n in names}
            if th in cand:
                ents.add(e)
        return ents

    for _, r in attacks.iterrows():
        ents = target_entities(r.get("target_host"))
        mask_ent = feats.entity.isin(ents)
        if not mask_ent.any():
            continue
        if r["status"] == "executed":
            feats.loc[mask_ent & overlap(r.start_utc, r.end_utc), "label"] = 1
            excl_end = r["cleanup_end_utc"] if pd.notna(r["cleanup_end_utc"]) else r["excluded_until_utc"]
            if pd.notna(excl_end) and excl_end > r.end_utc:
                m = mask_ent & overlap(r.end_utc, excl_end) & (feats.label == 0)
                feats.loc[m, "excluded"] = True
        else:  # attempted / failed -> ambiguous, exclude (never benign, never attack)
            end2 = r["cleanup_end_utc"] if pd.notna(r["cleanup_end_utc"]) else \
                   (r["excluded_until_utc"] if pd.notna(r["excluded_until_utc"]) else r.end_utc)
            m = mask_ent & overlap(r.start_utc, end2) & (feats.label == 0)
            feats.loc[m, "excluded"] = True
    return feats


def build(df, window, grace):
    """Aggregate causally: an event feeds its window only if available by
    (window_close + grace). Returns (feats, entity->agent_names, n_late)."""
    wlen = pd.Timedelta(window)
    grace = pd.Timedelta(grace)

    df = df.copy()
    if df.empty or "event_time" not in df.columns:
        sys.exit("ERROR: the input Parquet has no events (empty export). "
                 "Check that the --start/--end range has data in wazuh-archives "
                 "(see the readiness checks).")
    df["event_time"] = to_utc(df["event_time"])
    df = df.dropna(subset=["event_time"]).sort_values("event_time")
    if df.empty:
        sys.exit("ERROR: no events with a valid event_time.")

    # entity = agent_id (fallback to name)
    df["entity"] = df.get("agent_id")
    df["entity"] = df["entity"].fillna(df.get("agent_name")).fillna("unknown")
    # agent 000 is the Wazuh manager, NOT an instrumented endpoint -> out of model scope (protocol §7)
    df = df[df["entity"].astype("string").str.strip() != "000"]
    if df.empty:
        sys.exit("ERROR: no endpoint events after excluding the manager (agent 000).")
    df["win"] = df["event_time"].dt.floor(window)

    # numeric coercion: Wazuh may send byte counts / lengths as strings
    for c in ("flow_toserver", "flow_toclient", "ps_len"):
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")

    # --- causal cutoff: apply available_at ---
    avail = to_utc(df.get("available_at")).fillna(df["event_time"])
    cutoff = df["win"] + wlen + grace
    included = avail <= cutoff
    n_late = int((~included).sum())
    df = df[included]
    if df.empty:
        sys.exit("ERROR: every event fell outside its causal window (check available_at/grace).")

    # --- EventID NORMALIZED (string, stripped) ---
    eid = df["win_eventid"].astype("string").str.strip()
    chan = df["win_channel"].astype("string").str.strip() if "win_channel" in df else pd.Series("", index=df.index)
    chan = chan.fillna("")

    def flag(cond):
        return cond.fillna(False)

    df["is_win"] = df["source"] == "windows"
    df["is_suri"] = df["source"] == "suricata"
    df["is_other"] = ~(df["is_win"] | df["is_suri"])   # FIM/syscheck and any non-modelled source
    df["is_proc"] = flag(eid.eq("1") & chan.str.contains("Sysmon", case=False))
    df["is_4625"] = flag(eid.eq("4625") & chan.str.contains("Security", case=False))
    df["is_4624"] = flag(eid.eq("4624") & chan.str.contains("Security", case=False))
    df["is_4104"] = flag(eid.eq("4104"))
    df["has_http"] = df["http_host"].notna()
    df["has_alert"] = df["alert_sig"].notna()
    df["lvl"] = pd.to_numeric(df["rule_level"], errors="coerce")
    df["is_lvl8"] = (df["lvl"] >= 8).fillna(False)

    feats = df.groupby(["entity", "win"]).agg(
        n_win_events=("is_win", "sum"),
        n_suri_events=("is_suri", "sum"),
        diag_total_events=("source", "size"),
        diag_other_events=("is_other", "sum"),
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

    # guarantee model/diagnostic columns are numeric (defensive, for report + modelling)
    for c in MODEL_FEATURES + DIAG_COLS:
        if c in feats.columns:
            feats[c] = pd.to_numeric(feats[c], errors="coerce").fillna(0)

    entmap = df.groupby("entity")["agent_name"].agg(lambda s: set(x for x in s.dropna())).to_dict()
    return feats, entmap, n_late


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--labels", default=None, help="attack registry CSV (optional)")
    ap.add_argument("--window", default="5min")
    ap.add_argument("--grace", default="10min", help="late-event grace after window close")
    a = ap.parse_args()

    attacks = None
    if a.labels is not None:
        if not os.path.exists(a.labels):
            sys.exit(f"ERROR: --labels given but file does not exist: {a.labels}")
        attacks = load_attacks(a.labels)

    df = pd.read_parquet(a.inp)
    feats, entmap, n_late = build(df, a.window, a.grace)

    if attacks is not None:
        feats = label_and_exclude(feats, entmap, attacks, pd.Timedelta(a.window))
    else:
        feats["label"] = 0
        feats["excluded"] = False

    out_dir = os.path.dirname(a.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    feats.to_parquet(a.out, index=False)

    # ----------------------- READINESS REPORT -----------------------
    line = "=" * 56
    print(line)
    print("DATASET READINESS REPORT")
    print(line)
    print(f"Windows (entity x {a.window}): {len(feats)}")
    print(f"Entities: {feats.entity.nunique()} -> {sorted(feats.entity.unique())}")
    print(f"Observed event_time range (NOT coverage): "
          f"{to_utc(df['event_time']).min()} -> {to_utc(df['event_time']).max()}")
    print("  (real coverage comes from the session manifest, not this range)")
    print(f"Windows with host events:     {(feats.n_win_events > 0).sum()}")
    print(f"Windows with Suricata events: {(feats.n_suri_events > 0).sum()}")
    print(f"Non-modelled 'other' events (e.g. FIM): {int(feats.diag_other_events.sum())} "
          f"(diagnostic only, NOT a model feature)")
    print(f"Attack windows (label=1):     {int(feats.label.sum())}")
    print(f"Excluded windows (prep/cleanup/failed): {int(feats.excluded.sum())}")
    print(f"Events dropped by causal cutoff (available_at > close+{a.grace}): {n_late}")

    present = [c for c in MODEL_FEATURES if c in feats]
    const = [c for c in present if feats[c].nunique() <= 1]
    print("\nConstant model features (review, no signal):")
    print("  ", const if const else "none")
    print("\nModel-feature means:")
    print(feats[present].mean().round(2).to_string())

    local = feats["win"].dt.tz_convert("America/Guayaquil")
    is_day = (local.dt.hour >= 8) & (local.dt.hour < 18)
    print(f"\nDay windows (08-18 local): {int(is_day.sum())} | night: {int((~is_day).sum())}")
    print("Network present -> "
          f"DNS:{'yes' if feats.dns_unique.sum() > 0 else 'NO'} "
          f"TLS:{'yes' if feats.tls_unique.sum() > 0 else 'NO'} "
          f"HTTP:{'yes' if feats.http_reqs.sum() > 0 else 'NO'}")
    print(f"PowerShell 4104 present: {'yes' if feats.ps_blocks.sum() > 0 else 'NO (pre-4104 / pilot)'}")
    print(f"\nDiagnostic (NOT model features): {DIAG_COLS}")
    print(line)
    print(f"OK -> features written to: {a.out}")


if __name__ == "__main__":
    main()
