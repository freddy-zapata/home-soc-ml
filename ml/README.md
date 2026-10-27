# ml/

Machine learning pipeline for the Home SOC: export events from the Wazuh indexer, build
per-host, per-window features, train an anomaly detector and score new windows.

> **Status: prototype under correction — do not use for results.**
> The first round of fixes from an independent code review is applied in the code, but it has not
> yet been validated end to end on a real slice of lab data. Each further fix lands in its own commit.
>
> History note: the version that was originally reviewed was never committed. Commit `7908980`
> already contains the first round of fixes, even though its message describes it as the
> prototype with known defects.

## Contents

| Path | What it does | Status |
|---|---|---|
| `export/export_wazuh.py` | Exports `wazuh-archives-*` events for a UTC range `[start, end)` to a Parquet file | Review fixes applied, pending validation |
| `features/build_features.py` | Builds features per (host, 5-minute window) and prints a readiness report | Review fixes applied, pending validation |
| `features/FEATURES.md` | Versioned list of model features (must match `MODEL_FEATURES` in the code) | v1 |
| `requirements.txt` | Python dependencies (not pinned yet) | Prototype |

Training, scoring (FastAPI) and notifications are not written yet. Code comments and messages are
still in Spanish; they will be translated to English in a separate commit.

## Review findings and status

| Finding | Status |
|---|---|
| Features grouped only by time window, mixing hosts | Fixed in code: grouped by `agent_id` and window |
| Missing labels file silently ignored | Fixed in code: error if `--labels` is given and the file does not exist |
| Labelling with `<= end` marked one extra window | Fixed in code: half-open overlap `[start, end)` |
| "Hours covered" computed as time between first and last window | Fixed in code: report shows windows with data; real coverage comes from the session manifest |
| Rule-derived columns used as model inputs | Fixed in code: renamed with `diag_` prefix and excluded from `MODEL_FEATURES` |
| Event IDs not tied to their Windows channel | Fixed in code: Sysmon 1 and Security 4624/4625 matched by channel (4104 by event ID only) |
| Scroll responses not checked; partial exports possible | Fixed in code: every response is validated and no output file is written on error |
| Suricata DNS v3 fields not extracted | Fixed in code: v2 and v3 query names |
| Bytes summed from both `alert` and `flow` records | Fixed in code: bytes only from `flow` events |
| `available_at`, `agent.id` and `flow_id` not stored | Fixed in code |

## Data and secrets

- No data, models or credentials are stored in the repository (see the root `.gitignore`).
- The indexer password is read from the `WAZUH_PASS` environment variable; the host from `WAZUH_HOST`.
- `WAZUH_MANAGER_IP` is a placeholder: set `WAZUH_HOST` to the address of your Wazuh indexer.
- All times are UTC (ISO 8601). Features use the **event time**, not the Wazuh ingestion time.
- Labels always come from the attack execution log, never from Wazuh alerts.
