# ml/

Machine learning pipeline for the Home SOC: export events from the Wazuh indexer, build
per-window features, train an anomaly detector and score new windows.

> **Status: incomplete prototype — do not use for results.**
> This is the first version of the export and feature scripts, committed as-is so the history
> shows how the pipeline evolved. An independent code review found the defects listed below;
> each fix will land in its own commit.

## Contents

| Path | What it does | Status |
|---|---|---|
| `export/export_wazuh.py` | Exports `wazuh-archives-*` events for a UTC time range to a Parquet file | Prototype, known defects |
| `features/build_features.py` | Turns the raw Parquet into a table of features per 5-minute window and prints a readiness report | Prototype, known defects |
| `requirements.txt` | Python dependencies (not pinned yet) | Prototype |

Training, scoring (FastAPI) and notifications are not written yet.

## Known defects (to be fixed in separate commits)

`build_features.py`
- Groups only by time window, so events from different hosts are mixed in the same row.
- If a labels file is requested but does not exist, it silently labels everything as benign.
- Labelling uses `<= end`, which marks one extra window after each attack (should be `[start, end)`).
- "Hours covered" is the time between the first and last window, not the time actually covered by data.
- Includes rule-derived columns (`suri_alerts`, `wazuh_alerts_lvl8plus`) that must not be model inputs.

`export_wazuh.py`
- Does not check the response of each scroll request, so a failed page can end the export early
  and still write an output file.
- Does not extract Suricata DNS v3 fields.
- Sums bytes from both `alert` and `flow` records, double-counting traffic.
- Does not store `available_at` (when the event became available to the SIEM) or the `agent.id` /
  `flow_id` identifiers.

## Data and secrets

- No data, models or credentials are stored in the repository (see the root `.gitignore`).
- The indexer password is read from the `WAZUH_PASS` environment variable; the host from `WAZUH_HOST`.
- `WAZUH_MANAGER_IP` is a placeholder: replace it with the address of your Wazuh indexer.
- All times are UTC (ISO 8601). Features use the **event time**, not the Wazuh ingestion time.
- Labels always come from the attack execution log, never from Wazuh alerts.
