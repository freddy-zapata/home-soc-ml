# scripts/windows/

Benign traffic generators that run on the Windows victim. They produce the "normal" activity the
anomaly model learns from.

| Script | How it runs | What it generates | Wazuh alerts |
|---|---|---|---|
| `generate_clean_normal_traffic.ps1` | Scheduled task `TraficoNormalLimpio`, SYSTEM, every 10 min | Web requests, native system queries, opens/closes notepad, calc and mspaint, file copy | Designed not to trigger alerts. Since PowerShell 4104 logging was enabled, its `Invoke-WebRequest` call can also match rule 100050 |
| `generate_varied_traffic.ps1` | Scheduled task `TraficoNormalVariado`, SYSTEM, every 5 min | Day/night rhythm (90 % of runs 08–18 h, 50 % 18–23 h, 15 % at night), web, DNS, small download, files + zip, ping to the gateway, system queries, apps, public API | Rule 100050 (`Invoke-WebRequest`, `Invoke-RestMethod`, `Compress-Archive`), about once per run |
| `simulate_normal_usage.ps1` | Open PowerShell window (infinite loop, user session) | cmd, explorer, Edge, files in `C:\Users\Public\Documents` | False positives by design (suspicious explorer.exe process, PowerShell -> cmd, etc.); its `Invoke-WebRequest` call can also match rule 100050 |

Logs are written to `C:\ProgramData\TrafficLab\` (local time).

**Language note:** the scripts are kept byte-identical to the versions running in the lab, so their
comments, log messages and scheduled task names are in Spanish. Changing them would break the
comparison between the repository and the deployed scripts.

Start the noisy generator:

```powershell
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -NoExit -File C:\simulate_normal_usage.ps1"
```
