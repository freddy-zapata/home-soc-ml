# Home SOC + Anomaly Detection with Machine Learning

A home SOC lab built with **Wazuh (HIDS/SIEM)**, **Suricata (NIDS)** and **Sysmon**, extended with a
**machine learning anomaly detection layer** to reduce the false positives produced by static rules.

> Status: in development. Telemetry collection and benign traffic generation are working;
> the ML pipeline and the evaluation with labelled attacks are in progress.

## Architecture

| Component | Role |
|---|---|
| Ubuntu Server | Wazuh manager + indexer + dashboard (all-in-one) |
| Windows (victim) | Wazuh agent, Sysmon and Suricata (Npcap) |
| Kali Linux | Attack generation (Nmap, brute force, Atomic Red Team) |

Flow: Sysmon/Windows + Suricata `eve.json` -> Wazuh agent -> manager -> `wazuh-alerts-*` and
`wazuh-archives-*` indices -> features -> anomaly model -> alert.

## Contents

- `docs/SOC-ML-Lab-Guide.md`: step-by-step guide to reproduce the lab.
- `scripts/windows/`: three benign traffic generators (clean, varied with a day/night rhythm, and noisy,
  which triggers false positives in the static rules).
- `suricata/custom.rules`: custom port scan rule (MITRE T1046).
- `data/attack_windows_template.csv`: template for recording attack windows (labelling).
- `ml/`: ML pipeline (incomplete prototype, see `ml/README.md`).
- `wazuh/`: manager configuration (custom rule 100050) and Windows agent configuration used in the lab.

## Labelling methodology

Labels do **not** come from what Wazuh flags as an alert. They come from a manual log of attack
executions (UTC start and end time). Everything outside those executions is treated as benign activity.
Network events use the event time (`flow.start`), not the ingestion time, because flows are written
with a delay.

## Roadmap

- [x] Wazuh + Suricata + Sysmon lab working end to end
- [x] Benign traffic generators (clean, varied, noisy)
- [x] Custom scan rule (sid 9000001, T1046)
- [x] Lab configuration under version control (PowerShell 4104 rule, real-time FIM)
- [ ] Dataset: benign activity + labelled attacks (MITRE ATT&CK)
- [ ] Models: Isolation Forest and autoencoder, evaluated against the rule-based baseline
- [ ] Scoring service (FastAPI) + Telegram notifications
- [ ] Docker Compose package + installation test on a clean VM
- [ ] OpenCanary honeypot on a Raspberry Pi

## Disclaimer

Educational project. Attacks are run only against machines owned by the author inside an isolated lab.
Do not use these techniques against any system without explicit authorization.

## License

MIT
