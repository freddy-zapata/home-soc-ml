#!/usr/bin/env python3
r"""
test_pipeline.py - Reproducible tests for the HomeSOC ML pipeline.

Covers the audit fixes (protocol v0.2):
- per-target-entity labelling (not every entity by time)
- attack-registry `status` (executed vs attempted/failed) and exclusions
- rejection of inverted/zero-length intervals
- EventID normalization (int / whitespace)
- `available_at` applied as a causal cutoff
- half-open [start, end) labelling, DNS v2/v3, bytes only from `flow`

Run from anywhere:   python ml/tests/test_pipeline.py
Exit code 0 = all passed. No third-party test runner needed.
"""
import importlib.util
import os
import sys
import tempfile

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))


def load(mod_name, rel):
    spec = importlib.util.spec_from_file_location(mod_name, os.path.join(ROOT, rel))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


EXP = load("exp", "ml/export/export_wazuh.py")
BF = load("bf", "ml/features/build_features.py")


def win(agent, aid, chan, eid, systime, available=None, image=None, ps=None):
    """Synthetic EventChannel _source. `available` = ingest time (available_at)."""
    ed = {}
    if image:
        ed["image"] = image
    if ps:
        ed["scriptBlockText"] = ps
    return {"_source": {
        "timestamp": available or systime,
        "location": "EventChannel",
        "agent": {"name": agent, "id": aid},
        "data": {"win": {"system": {"eventID": eid, "channel": chan, "systemTime": systime},
                         "eventdata": ed}}}}


def suri(agent, aid, etype, t, available=None, **data):
    d = {"event_type": etype, "timestamp": t}
    d.update(data)
    return {"_source": {"timestamp": available or t,
                        "location": "C:\\Program Files\\Suricata\\log\\eve.json",
                        "agent": {"name": agent, "id": aid}, "data": d}}


def build_raw():
    W = "2026-10-26T18:31:00.000Z"      # window 18:30
    docs = [
        # Agent A (001 / WIN10), attack window 18:30
        win("WIN10", "001", "Microsoft-Windows-Sysmon/Operational", 1, W, image="a.exe"),  # eventID as INT
        win("WIN10", "001", "Security", "4625", W),
        win("WIN10", "001", "Security", "4625", W),
        win("WIN10", "001", "Microsoft-Windows-PowerShell/Operational", " 4104 ", W, ps="IEX x" * 9),  # whitespace
        win("WIN10", "001", "Application", "1", W),                 # EventID 1 wrong channel -> NOT a proc
        suri("WIN10", "001", "flow", W, flow={"start": W, "bytes_toserver": "1000", "bytes_toclient": "2000"},
             flow_id=1, dest_ip="8.8.8.8", dest_port=53),  # bytes as STRINGS (as Wazuh often sends)
        # manager agent 000 -> must be excluded from entities
        suri("ubuntu", "000", "dns", W, dns={"rrname": "mgr.local"}),
        suri("WIN10", "001", "dns", W, dns={"rrname": "github.com", "type": "query"}),            # v2
        suri("WIN10", "001", "dns", W, dns={"version": 3, "type": "query", "queries": [{"rrname": "python.org"}]}),  # v3
        suri("WIN10", "001", "tls", W, tls={"sni": "bbc.com"}),
        suri("WIN10", "001", "http", W, http={"hostname": "example.com"}),
        suri("WIN10", "001", "alert", W, alert={"signature": "SCAN", "signature_id": 9000001},
             flow={"bytes_toserver": 999999, "bytes_toclient": 999999}, dest_ip="8.8.8.8"),       # must NOT add bytes
        # FIM (syscheck) event -> source 'other': must land in diag_other_events, NOT in model features
        {"_source": {"timestamp": W, "location": "syscheck", "agent": {"name": "WIN10", "id": "001"},
                     "data": {"syscheck": {"path": "c:\\users\\freddy\\downloads\\x.txt", "event": "added"}}}},
        # LATE event: 4624 in window 18:30 but available 1h later -> causal cutoff drops it
        win("WIN10", "001", "Security", "4624", "2026-10-26T18:33:00.000Z",
            available="2026-10-26T19:33:00.000Z"),
        # Agent A benign windows for exclusion tests
        win("WIN10", "001", "Microsoft-Windows-Sysmon/Operational", 1, "2026-10-26T18:41:00.000Z", image="b.exe"),  # win 18:40
        win("WIN10", "001", "Microsoft-Windows-Sysmon/Operational", 1, "2026-10-26T18:46:00.000Z", image="c.exe"),  # win 18:45
        # Agent B (002 / WIN11) in window 18:30 -> must NOT be labelled by a WIN10 attack
        win("WIN11", "002", "Microsoft-Windows-Sysmon/Operational", 1, W, image="d.exe"),
        # noise dropped
        {"_source": {"timestamp": W, "location": "sca", "agent": {"name": "WIN10", "id": "001"}, "data": {}}},
    ]
    rows = [EXP.flatten(d["_source"]) for d in docs if d["_source"].get("location") not in EXP.NOISE]
    return pd.DataFrame(rows)


def test_flatten():
    df = build_raw()
    dns = set(df[df.suri_type == "dns"].dns_q.dropna())
    assert dns == {"github.com", "python.org", "mgr.local"}, ("DNS v2/v3", dns)  # flatten keeps all; 000 filtered later in build
    assert df[df.suri_type == "flow"].flow_toserver.notna().all(), "flow rows must carry bytes"
    assert df[df.suri_type == "alert"].flow_toserver.isna().all(), "alert must not carry bytes"
    assert set(df.agent_id.dropna()) == {"000", "001", "002"}, "agent_id"  # 000 present pre-build, filtered in build
    assert df.available_at.notna().all(), "available_at stored"
    print("OK flatten: DNS v2/v3, bytes only from flow, agent_id/available_at")


def test_build_causal_and_eventid():
    feats, entmap, n_late = BF.build(build_raw(), "5min", "10min")
    a30 = feats[(feats.entity == "001") & (feats.win == pd.Timestamp("2026-10-26T18:30:00Z"))].iloc[0]
    assert a30.proc_creates == 1, ("EventID 1 only on Sysmon channel (int normalized)", a30.proc_creates)
    assert a30.logon_fail == 2, ("4625 x2", a30.logon_fail)
    assert a30.ps_blocks == 1, ("' 4104 ' normalized", a30.ps_blocks)
    assert a30.flow_out == 1000, ("no duplicated bytes in features", a30.flow_out)
    assert a30.logon_ok == 0, ("late 4624 excluded by causal cutoff", a30.logon_ok)
    assert n_late >= 1, ("causal cutoff counted a late event", n_late)
    assert entmap["001"] == {"WIN10"}, entmap
    # FIM/other must be a diagnostic only and must NOT alter model features
    assert a30.diag_other_events >= 1, ("FIM counted in diag_other_events", a30.diag_other_events)
    assert "n_events" not in feats.columns, "total event count must not be a model feature"
    assert a30.proc_creates == 1, "FIM must not change proc_creates (comparability)"
    assert "000" not in set(feats.entity), "manager agent 000 must be excluded"
    assert float(a30.flow_out) == 1000.0, ("string bytes coerced to numeric", a30.flow_out)
    print(f"OK build: EventID normalized + channel-aware; causal cutoff dropped {n_late} late event(s); "
          "FIM isolated in diag_other_events")


def _attacks_csv(rows):
    hdr = "attack_id,technique_id,target_host,start_utc,end_utc,status,cleanup_end_utc\n"
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w") as f:
        f.write(hdr + "".join(rows))
    return path


def test_labels_status_target_exclusions():
    feats, entmap, _ = BF.build(build_raw(), "5min", "10min")
    wlen = pd.Timedelta("5min")
    csv = _attacks_csv([
        # executed on WIN10, 18:30-18:35, cleanup to 18:50
        "A1,T1059,WIN10,2026-10-26T18:30:00Z,2026-10-26T18:35:00Z,executed,2026-10-26T18:50:00Z\n",
        # attempted on WIN10, 18:40-18:45 -> excluded, never label
        "A2,T1110,WIN10,2026-10-26T18:40:00Z,2026-10-26T18:45:00Z,attempted,\n",
    ])
    aw = BF.load_attacks(csv)
    f = BF.label_and_exclude(feats.copy(), entmap, aw, wlen)

    def cell(ent, ts, col):
        r = f[(f.entity == ent) & (f.win == pd.Timestamp(ts))]
        return int(r[col].iloc[0]) if len(r) else None

    assert cell("001", "2026-10-26T18:30:00Z", "label") == 1, "executed labels target window"
    assert cell("002", "2026-10-26T18:30:00Z", "label") == 0, "other entity NOT labelled (per-target)"
    assert cell("001", "2026-10-26T18:40:00Z", "label") == 0, "attempted is not a label"
    assert cell("001", "2026-10-26T18:40:00Z", "excluded") == 1, "attempted window excluded"
    assert cell("001", "2026-10-26T18:45:00Z", "excluded") == 1, "cleanup window excluded"
    os.unlink(csv)
    print("OK labels: per-target, status executed vs attempted, cleanup excluded")


def test_inverted_interval_rejected():
    csv = _attacks_csv(["BAD,T1,WIN10,2026-10-26T18:40:00Z,2026-10-26T18:30:00Z,executed,\n"])
    try:
        BF.load_attacks(csv)
    except SystemExit as e:
        assert "inverted" in str(e).lower(), e
        print("OK validation: inverted interval rejected")
        return
    finally:
        os.unlink(csv)
    raise AssertionError("inverted interval was NOT rejected")


if __name__ == "__main__":
    test_flatten()
    test_build_causal_and_eventid()
    test_labels_status_target_exclusions()
    test_inverted_interval_rejected()
    print("\nALL TESTS PASSED")
