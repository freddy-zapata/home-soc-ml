# wazuh/

Wazuh configuration used in the lab to collect the official dataset (T0 = `2026-10-26T18:30:00Z`).
It is frozen until data collection is closed, with one documented exception: real-time FIM was
extended to the user's Documents and Downloads folders on `2026-10-27T17:54:51Z` (see
[Change history](#change-history)).

| File | Goes to | Machine |
|---|---|---|
| `manager/local_rules.xml` | `/var/ossec/etc/rules/local_rules.xml` | Ubuntu (Wazuh manager) |
| `agent-windows/ossec.conf` | `C:\Program Files (x86)\ossec-agent\ossec.conf` | Windows victim (agent) |

Both files are exact copies of the lab configuration, except for the IP placeholders below. The two
Documents/Downloads lines were added to the repository copy from the documented change procedure,
not copied back from the agent. Rule
descriptions are kept in Spanish because that is the text deployed in the lab and shown in the alerts.

## Placeholders

Real IP addresses were replaced with UPPERCASE placeholders. Before using a file, replace each
placeholder with the value for your network:

| Placeholder | Meaning |
|---|---|
| `WAZUH_MANAGER_IP` | IP address of the Wazuh manager the agent connects to |

On the victim (PowerShell as administrator), for example:

```powershell
(Get-Content .\ossec.conf) -replace 'WAZUH_MANAGER_IP','10.0.0.10' | Set-Content .\ossec.conf
```

## Changes from the default configuration

**Manager — `local_rules.xml`**
- Rule **100050** (level 10, MITRE **T1059.001**): alerts when an event **4104** (PowerShell Script
  Block Logging) contains `Invoke-RestMethod`, `Invoke-WebRequest`, `Compress-Archive`,
  `Net.WebClient`, `DownloadString`, `EncodedCommand` or `-enc`.
- Rule 100001 is the example shipped with Wazuh; it is kept so the file is identical to the lab's.

**Windows agent — `ossec.conf`**
- `<client_buffer>`: `queue_size` 50000 (the default value overflowed with Suricata).
- `<localfile>` for the Suricata `eve.json` (`C:\Program Files\Suricata\log\eve.json`, json format).
- `<localfile>` for the **Sysmon** channel (`Microsoft-Windows-Sysmon/Operational`).
- `<localfile>` for the **PowerShell** channel (`Microsoft-Windows-PowerShell/Operational`, event 4104).
  Requires Script Block Logging to be enabled on the victim.
- `<syscheck>`: **real-time** FIM (`check_all`) on `C:\Users\Public`, `C:\Windows\Temp`,
  `C:\Users\Freddy\Documents` and `C:\Users\Freddy\Downloads`. The default global exclusions
  (`.log`, `.htm`, `.jpg`, `.png`, `.chm`, `.pnf`, `.evtx`) also apply to these folders, so FIM does not
  cover every file type. Real-time mode reports what changed, not which user or process changed it.
- `<active-response>`: left as installed, `<disabled>no</disabled>` (see below).

**Active Response.** The agent keeps the Active Response capability enabled (`disabled=no`, the value
deployed in the lab). The manager's `ossec.conf` was checked on 2026-11-06 and has no active
`<active-response>` blocks, so no automatic responses are configured. The system only raises alerts.

## Change history

| Date (UTC) | Change | Notes |
|---|---|---|
| 2026-10-26T18:30:00Z | Baseline configuration (T0): rule 100050, PowerShell 4104 channel, real-time FIM on Public and Temp | Commit `b879020` |
| 2026-10-27T17:54:51Z | Real-time FIM extended to Documents and Downloads; agent restarted | Agent reloaded at 17:55:05Z. Create, modify and delete events were confirmed in Wazuh for both folders. Data before this time does not cover these folders |

## Applying the changes

Ubuntu (manager):
```bash
sudo cp local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-logtest      # optional: test with a 4104 event
sudo systemctl restart wazuh-manager
```

Windows victim (PowerShell as administrator):
```powershell
Copy-Item .\ossec.conf "C:\Program Files (x86)\ossec-agent\ossec.conf"
Restart-Service WazuhSvc
```

## Known limitations (rule-based baseline)

- Rule 100050 also fires on the **benign** traffic of `generate_varied_traffic.ps1`
  (it uses `Invoke-WebRequest` and `Compress-Archive`): an expected false positive of the baseline.
- The `-enc` pattern also matches `-Encoding` (e.g. `Out-File -Encoding utf8`).

This is intentional: the baseline is the set of static rules as they would be used in practice, and
the ML layer is evaluated by how much it reduces these false positives. Dataset labels come from the
attack execution log, never from Wazuh alerts.
