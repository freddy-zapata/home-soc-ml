# FEATURES — HomeSOC ML (v2, 2026-10-27)

Versioned feature list. Source of truth for the **main model**: the
`MODEL_FEATURES` constant in `build_features.py` must match this table.

## Unit
- **Entity** = `agent_id` (one instrumented Windows host). Hosts are never mixed.
- **Window** = 5 min, clock-aligned (00,05,10…), by **event time** (`event_time`),
  not ingest time.
- `available_at` (ingest time) is kept in the raw data and **applied as a causal
  cutoff**: an event feeds a window only if available by `window_close + grace`
  (default 10 min). It is not a feature itself.

## Model features (fed to IF / autoencoder)

| Column | Meaning | Source |
|---|---|---|
| `n_win_events` | host events (EventChannel) in the window | Windows |
| `n_suri_events` | network events in the window | Suricata |
| `proc_creates` | process creations (EventID 1 **on the Sysmon channel**) | Sysmon |
| `img_unique` | distinct process images | Sysmon |
| `logon_fail` | failed logons (4625 **on the Security channel**) | Security |
| `logon_ok` | successful logons (4624 **on the Security channel**) | Security |
| `ps_blocks` | PowerShell script blocks (4104) | PowerShell |
| `ps_len_max` | max scriptBlockText length | PowerShell |
| `dst_ip_unique` | distinct destination IPs | Suricata |
| `dport_unique` | distinct destination ports | Suricata |
| `dns_unique` | distinct queried domains (v2+v3) | Suricata |
| `tls_unique` | distinct TLS servers (SNI, else cert subject/SAN) | Suricata |
| `http_reqs` | HTTP requests | Suricata |
| `flow_out` | bytes to server (**flow events only**) | Suricata |
| `flow_in` | bytes to client (**flow events only**) | Suricata |

## Comparability with FIM (why there is no single total count)
Volume is captured **per source** (`n_win_events`, `n_suri_events`), never as one
total. On 27-oct FIM was extended (Documents/Downloads), so FIM/`syscheck` event
volume changed mid-dataset. A single total-event feature would therefore be
**incomparable across that boundary**. FIM and any other non-modelled source land
in `diag_other_events` (diagnostic), outside the model. To compare periods: use
per-source counts and the coverage manifest, not a total. Do not use
`config_version` as a feature.

## NOT model features (protocol §7)
- `entity`, `win` → grouping keys.
- `label` → evaluation label (from the attack registry, never from alerts).
- `excluded` → window dropped from training (prep/cleanup/attempted/failed).
- `diag_total_events` → all events in the window (incl. FIM) — diagnostic.
- `diag_other_events` → FIM/syscheck and any non-modelled source — diagnostic.
- `diag_suri_alerts`, `diag_wazuh_alerts_lvl8plus` → rule-derived — diagnostic.
- `profile`, `session_id`, scenario names from benign sessions → **never** inputs.

## Pending (when data + manifest exist)
- Per-source **coverage indicator** per window (sensor absent ≠ 0).
- DNS entropy and inter-flow regularity (beaconing) — added only if they help in
  calibration; any feature added re-versions this file.
