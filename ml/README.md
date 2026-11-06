# ml/

Machine learning pipeline for the Home SOC: export events from the Wazuh indexer, build
per-host, per-window features, train an anomaly detector and score new windows.

> **Status: prototype — not used for results yet.**
> The fixes from an independent code review are applied, the export and feature pipeline has run end
> to end on a real slice of lab data, and a reproducible test script covers the fixes. Training,
> scoring and notifications are still missing. Each further fix lands in its own commit.
>
> History note: the version that was originally reviewed was never committed. Commit `7908980`
> already contains the first round of fixes, even though its message describes it as the
> prototype with known defects.

## Contents

| Path | What it does | Status |
|---|---|---|
| `export/export_wazuh.py` | Exports `wazuh-archives-*` events for a UTC range `[start, end)` to a Parquet file | Validated on real lab data |
| `features/build_features.py` | Builds features per (host, 5-minute window) and prints a readiness report | Validated on real lab data |
| `features/FEATURES.md` | Versioned list of model features (must match `MODEL_FEATURES` in the code) | v2 |
| `tests/test_pipeline.py` | Reproducible tests for the review fixes (synthetic events, no lab access needed) | Passing |
| `archive/` | Versions exactly as reviewed on 2026-10-26 (do not run) | Frozen |
| `requirements.txt` | Python dependencies (not pinned yet) | Prototype |

Training, scoring (FastAPI) and notifications are not written yet. Some code comments and messages
are still in Spanish; they will be translated to English in a separate commit.

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

## Running

The indexer is not exposed to the network: reach it through an SSH tunnel to the Wazuh VM.

```powershell
# Host Windows, terminal 1: keep the tunnel open
ssh -L 9200:localhost:9200 <user>@WAZUH_MANAGER_IP

# Host Windows, terminal 2
$env:WAZUH_HOST = "https://localhost:9200"
$env:WAZUH_PASS = "<indexer password>"
python ml/export/export_wazuh.py --start 2026-10-26T18:30:00Z --end 2026-10-27T00:00:00Z --out data/raw.parquet
python ml/features/build_features.py --in data/raw.parquet --out data/features.parquet --labels data/attack_windows.csv
```

Tests (only need `pandas`, `pyarrow` and `requests`):

```powershell
python ml/tests/test_pipeline.py
```

Exit code 0 means all tests passed.

## Attack registry

`data/attack_windows_template.csv` follows the v0.2 schema: one row per attack execution with its
Atomic test GUID, target host, `status` (`attempted`, `executed`, `failed`) and cleanup/exclusion
times. Only `executed` rows produce `label = 1`, and only for the target host. Preparation, cleanup,
attempted and failed periods are excluded from both classes.

## Data and secrets

- No data, models or credentials are stored in the repository (see the root `.gitignore`).
- The indexer password is read from the `WAZUH_PASS` environment variable; the host from `WAZUH_HOST`.
- `WAZUH_MANAGER_IP` is a placeholder: set `WAZUH_HOST` to the address of your Wazuh indexer.
- All times are UTC (ISO 8601). Features use the **event time**, not the Wazuh ingestion time.
- Labels always come from the attack execution log, never from Wazuh alerts.
