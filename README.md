# 🛡️ Home SOC + Anomaly Detection with Machine Learning

![Status](https://img.shields.io/badge/status-in%20development-yellow)
![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-0969da)
![Suricata](https://img.shields.io/badge/NIDS-Suricata-cf222e)
![Sysmon](https://img.shields.io/badge/telemetry-Sysmon-1a7f37)
![MITRE ATT&CK](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-6e7781)
![License](https://img.shields.io/badge/license-MIT-blue)

A home SOC lab built with **Wazuh (HIDS/SIEM)**, **Suricata (NIDS)** and **Sysmon**, being extended with a
**machine learning anomaly detection layer** to reduce the false positives produced by static rules.

> **Status: in development.** Telemetry collection and benign traffic generation are working.
> No attacks have been run in the lab yet. The ML pipeline is an unvalidated prototype, so this project has
> **no detection metrics yet**.

---

## ⚙️ System Description

The lab runs on a Windows host with VMware Workstation, in a NAT network isolated from the home network.

![Home SOC lab architecture](docs/images/architecture.svg)

| Component | Role | Status |
|---|---|---|
| **Ubuntu Server** | Wazuh manager, indexer and dashboard (all-in-one) | ✅ Working |
| **Windows (victim)** | Wazuh agent, Sysmon, Suricata (Npcap) and benign traffic generators | ✅ Working |
| **Atomic Red Team** | Adversary techniques executed on the Windows victim | 🕓 Planned |
| **Kali Linux** | Network attacks (Nmap, brute force) | 🕓 Planned |
| **ML layer** | Runs on the host, outside the VMs | 🚧 Prototype |

### Data flow

```mermaid
flowchart TB
  subgraph C["1. Telemetry: working"]
    direction LR
    A["Sysmon + Windows channels"] --> X["Wazuh agent"]
    B["Suricata eve.json"] --> X
    X --> D["Wazuh manager"]
    D --> E[("wazuh-alerts-*<br/>wazuh-archives-*")]
  end
  subgraph P["2. ML pipeline: in progress"]
    direction LR
    F["export_wazuh.py<br/>Parquet"] --> G["build_features.py<br/>per host, 5 min"]
    G --> H["Isolation Forest<br/>Autoencoder"]
    H --> I["FastAPI scoring<br/>Telegram alert"]
  end
  C --> P
  classDef ok fill:#d1f2dc,stroke:#1a7f37,color:#0b3d1c
  classDef proto fill:#fff1c7,stroke:#bf8700,color:#4d3700
  classDef plan fill:#eceff3,stroke:#6e7781,color:#30363d,stroke-dasharray:5 4
  class A,B,X,D,E ok
  class F,G proto
  class H,I plan
  style C fill:transparent,stroke:#6e7781
  style P fill:transparent,stroke:#6e7781
```

Green: working. Amber: prototype pending validation. Grey: planned.

---

## 📁 Repository Structure

```
home-soc-ml/
├── data/
│   └── attack_windows_template.csv   # Template to log attack windows (labelling)
├── docs/
│   ├── images/architecture.svg       # Architecture diagram
│   └── SOC-ML-Lab-Guide.md           # Step-by-step guide to reproduce the lab
├── ml/                               # ML pipeline (incomplete prototype)
│   ├── export/export_wazuh.py        # Exports Wazuh events to Parquet
│   ├── features/build_features.py    # Builds features per host and 5-minute window
│   ├── features/FEATURES.md          # Versioned list of model features
│   ├── requirements.txt
│   └── README.md                     # Prototype status and review findings
├── scripts/windows/                  # Benign traffic generators
├── suricata/custom.rules             # Custom port scan rule
├── wazuh/
│   ├── agent-windows/ossec.conf      # Windows agent configuration
│   ├── manager/local_rules.xml       # Custom Wazuh rules
│   └── README.md                     # Lab configuration and known limitations
├── LICENSE
└── README.md
```

---

## 🔧 Requirements

| VM | OS | vCPU | RAM | Disk |
|---|---|---|---|---|
| Wazuh | Ubuntu Server 24.04 LTS | 4 | 8 GB | 50 GB |
| Victim | Windows 10/11 (evaluation) | 2 | 4 GB | 60 GB |
| Attacker | Kali Linux | 2 | 4 GB | 40 GB |

- **Virtualization:** VMware Workstation Pro, using the NAT network (VMnet8).
- **ML prototype:** Python with `requests`, `pandas`, `pyarrow` and `numpy`.

The full setup is in the [lab guide](docs/SOC-ML-Lab-Guide.md).

---

## 🧩 Main Components

### Detection rules

These rules are the baseline the ML layer will be compared against. They have not been evaluated against labelled attacks yet.

| Rule | Engine | Detects | MITRE ATT&CK |
|---|---|---|---|
| `sid 9000001` | Suricata | Possible port scan | T1046 |
| `100050` | Wazuh | Suspicious PowerShell commands in event 4104 | T1059.001 |

Rule `100050` also fires on benign traffic. This is intentional and documented in [`wazuh/README.md`](wazuh/README.md), because reducing these false positives is the goal of the ML layer.

### Benign traffic generators

| Script | Purpose |
|---|---|
| `generate_clean_normal_traffic.ps1` | Clean baseline activity, designed not to trigger alerts |
| `generate_varied_traffic.ps1` | Varied activity with a day/night rhythm |
| `simulate_normal_usage.ps1` | Noisy activity that triggers false positives by design |

### ML pipeline

| Stage | Status |
|---|---|
| Export events from the Wazuh indexer | 🚧 Review fixes applied, pending validation |
| Features per host and 5-minute window | 🚧 Review fixes applied, pending validation |
| Isolation Forest and autoencoder | 🕓 Not written yet |
| FastAPI scoring and Telegram notifications | 🕓 Not written yet |

See [`ml/README.md`](ml/README.md) for the review findings.

---

## 🏷️ Labelling Methodology

Labels do **not** come from what Wazuh flags as an alert. They will come from a manual log of attack
executions (UTC start and end time). Everything outside those executions is treated as benign activity.
Network events use the event time (`flow.start`), not the ingestion time, because flows are written
with a delay.

```mermaid
flowchart LR
  A["Manual attack log<br/>UTC start and end"] --> C{"5-min window overlaps<br/>an attack?"}
  B["Features per host<br/>by event time"] --> C
  C -- yes --> D["Label: attack"]
  C -- no --> Z["Label: benign"]
  D --> F["Evaluate against<br/>the rule baseline"]
  Z --> F
  W["Wazuh alerts"] -. "never used as labels" .-x C
  classDef ok fill:#d1f2dc,stroke:#1a7f37,color:#0b3d1c
  classDef plan fill:#eceff3,stroke:#6e7781,color:#30363d,stroke-dasharray:5 4
  classDef atk fill:#ffe1de,stroke:#cf222e,color:#5c0b12
  classDef vic fill:#dbeafe,stroke:#0969da,color:#0a2f5c
  class A,B,C,F vic
  class D atk
  class Z ok
  class W plan
```

---

## 🗺️ Roadmap

- [x] Wazuh + Suricata + Sysmon telemetry working end to end
- [x] Benign traffic generators (clean, varied, noisy)
- [x] Custom scan rule (sid 9000001, T1046)
- [x] Lab configuration under version control (PowerShell 4104 rule, real-time FIM)
- [ ] Run attacks in the lab: Nmap, brute force and Atomic Red Team
- [ ] Dataset: benign activity + labelled attacks (MITRE ATT&CK)
- [ ] Models: Isolation Forest and autoencoder, evaluated against the rule-based baseline
- [ ] Scoring service (FastAPI) + Telegram notifications
- [ ] Docker Compose package + installation test on a clean VM
- [ ] OpenCanary honeypot on a Raspberry Pi

---

## ⚠️ Disclaimer

Educational project. Attacks are to be run only against machines owned by the author inside an isolated lab.
Do not use these techniques against any system without explicit authorization.

---

## 🧠 Credits

Developed by **Freddy Alejandro Zapata Armas** as a personal portfolio project.
Quito, Ecuador – 2026

## 📄 License

MIT
