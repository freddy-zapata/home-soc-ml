# ml/archive/

Versions of the ML scripts exactly as they were submitted to the independent code review on
2026-10-26. They are kept to document how the pipeline evolved (iterative design process). **Do not
run them** — they contain the defects listed in [`../README.md`](../README.md#review-findings-and-status).
The current code is in `../export/` and `../features/`.

| File | Reviewed version of |
|---|---|
| `export_wazuh_reviewed_2026-10-26.py` | `ml/export/export_wazuh.py` |
| `build_features_reviewed_2026-10-26.py` | `ml/features/build_features.py` |

Notes:
- Contents and line numbers are identical to the reviewed files, so the line references in the review
  match. The only change is the lab IP address, replaced with the `WAZUH_MANAGER_IP` placeholder
  (lines 6 and 28 of the export script).
- These files were never committed before: commit `7908980` already contained the first round of fixes.
- Comments and messages are in Spanish, as in the reviewed version.
