# Lab: Home SOC + Anomaly Detection with ML
Complete step-by-step guide — Host: Windows + VMware Workstation Pro

> **Placeholders:** real lab IP addresses were replaced with UPPERCASE placeholders. Replace them with
> the values of your own network:
>
> | Placeholder | Meaning |
> |---|---|
> | `WAZUH_MANAGER_IP` | Ubuntu VM running the Wazuh manager, indexer and dashboard |
> | `VICTIM_IP` | Windows victim VM |
> | `GATEWAY_IP` | Default gateway of the VMware NAT network (usually `.2`) |
>
> **Partly outdated sections** (they will be updated in a separate commit):
> - Part 5, Suricata step 3: the lab now logs `alert`, `anomaly`, `flow`, `dns`, `http` and `tls`
>   events (not only `alert`), because the ML features need network flows. The agent buffer was
>   raised to cope with the volume.
> - The current Wazuh configuration (PowerShell 4104 channel, rule 100050, real-time FIM) is in
>   [`wazuh/`](../wazuh/README.md) and is not described here yet.
> - Parts 6–9 describe the original plan for the ML pipeline. The current code is in
>   [`ml/`](../ml/README.md).

## Quick note on costs

- **VMware Workstation Pro**: free for personal use since November 2024 (Broadcom). You need a free Broadcom account to download it, but no credit card or paid license. [Source](https://blogs.vmware.com/cloud-foundation/2024/11/11/vmware-fusion-and-workstation-are-now-free-for-all-users/)
- **Ansible**: always 100% free and open source. You can use it to configure your VMs (install packages, deploy configs) over SSH at no cost.
- **Watch out with Vagrant + VMware**: if you later want Vagrant to *create* the VMs in VMware automatically (not just configure them), HashiCorp's official `vagrant-vmware-desktop` plugin **is paid** (with a free trial). You do not need it for this lab — you will create the VMs by hand in VMware Workstation, and if you want to automate later, use Ansible only for configuration (that is free) over SSH to the VMs you already created.
- **Wazuh, Kali, Ubuntu, Atomic Red Team, Sysmon, scikit-learn, PyTorch, FastAPI**: all free and open source.

---

## Lab architecture

| VM | OS | Role | vCPU | RAM | Disk |
|---|---|---|---|---|---|
| VM1 | Ubuntu Server 24.04 LTS | Wazuh Manager + Indexer + Dashboard (SIEM) | 4 | 8 GB | 50 GB |
| VM2 | Windows 10/11 (evaluation) | Victim (with Sysmon + Wazuh agent) | 2 | 4 GB | 60 GB |
| VM3 | Kali Linux | Attacker | 2 | 4 GB | 40 GB |

Total assigned: 16 GB of RAM (out of 32 GB), leaving room for the host and for training the model.

**ML training is NOT done inside a VM** — it runs on the Windows host (or WSL2), so the RTX 4060 can be used directly without fighting GPU passthrough. The VMs only generate and store the data; the host processes it.

Network: all VMs use VMware's **NAT** network (VMnet8 by default). They can reach each other and the internet to update packages, but stay isolated from your real home network.

---

## Part 0 — Prepare the host

1. Check that virtualization is enabled in the BIOS/UEFI (Intel VT-x). In Windows: Task Manager → Performance tab → CPU → it should say "Virtualization: Enabled".
2. Make sure you have at least 200 GB of free disk space.
3. Create a free Broadcom account: https://support.broadcom.com (sign up, no payment required).
4. Download VMware Workstation Pro from the Broadcom portal (search for "VMware Workstation Pro" in the Support Portal, version 17.5.2 or later / 26H1). Install it and, when it asks for a license, choose the personal use option without entering a key.
5. Download the images you will need:
   - Ubuntu Server 24.04 LTS ISO: https://ubuntu.com/download/server
   - Windows 10 or 11 evaluation ISO (90 days, free): Microsoft Evaluation Center
   - Kali Linux, prebuilt VMware image (not an ISO, ready to import): https://www.kali.org/get-kali/#kali-virtual-machines

---

## Part 1 — Configure the virtual network

1. In VMware Workstation: Edit → Virtual Network Editor.
2. Check that VMnet8 exists with type NAT (it does by default). Note the subnet it shows (usually 192.168.x.0/24).
3. You do not need to create anything new: when you create each VM, select "NAT" as the network type.

---

## Part 2 — VM1: Wazuh Manager (SIEM)

### Create the VM
1. File → New Virtual Machine → Typical → select the Ubuntu Server ISO.
2. Name: `soc-wazuh`. Assign a 50 GB disk (single file).
3. Before finishing the wizard, click "Customize Hardware": set 4 vCPU and 8 GB RAM. Network: NAT.

### Install Ubuntu Server
4. Boot the VM and install Ubuntu Server with the installer (language, keyboard; DHCP networking is fine).
5. For disk partitioning, use "use entire disk".
6. Create your user and password.
7. When it asks about "Featured Server Snaps", **select OpenSSH server** (so you can manage it over SSH from your host).
8. Finish the installation and reboot.

### Set a static IP (recommended)
9. Once logged in, check the interface: `ip a`. Edit netplan:
   ```
   sudo nano /etc/netplan/50-cloud-init.yaml
   ```
   Change it to something like this (adjust the interface name and subnet to what you see with `ip a`):
   ```yaml
   network:
     version: 2
     ethernets:
       ens33:
         dhcp4: no
         addresses: [WAZUH_MANAGER_IP/24]
         routes:
           - to: default
             via: GATEWAY_IP
         nameservers:
           addresses: [8.8.8.8]
   ```
10. Apply it: `sudo netplan apply`

### Install Wazuh (all-in-one)
11. Update the system:
    ```
    sudo apt update && sudo apt upgrade -y
    ```
12. Download and install Wazuh with the assisted installer (installs indexer + manager + dashboard together):
    ```
    curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
    sudo bash ./wazuh-install.sh -a
    ```
13. **Save the admin password** shown at the end of the script (you need it to log in to the dashboard).
14. Firewall (if you use ufw): open the required ports:
    ```
    sudo ufw allow 22/tcp
    sudo ufw allow 443/tcp
    sudo ufw allow 1514/tcp
    sudo ufw allow 1515/tcp
    sudo ufw allow 55000/tcp
    sudo ufw enable
    ```
15. From the browser on the Windows host, open `https://WAZUH_MANAGER_IP` (accept the self-signed certificate) and log in with `admin` and the saved password. Your SIEM is up and running.

### Log ALL events (not only alerts)
This is key for the ML: by default Wazuh only stores alerts (when a rule fires), but to train an anomaly model you also need the "normal" traffic.

16. Edit `/var/ossec/etc/ossec.conf` on the manager and enable full logging:
    ```
    sudo nano /var/ossec/etc/ossec.conf
    ```
    Find the `<global>` section and make sure it contains:
    ```xml
    <global>
      <jsonout_output>yes</jsonout_output>
      <alerts_log>yes</alerts_log>
      <logall>yes</logall>
      <logall_json>yes</logall_json>
    </global>
    ```
17. Restart the manager: `sudo systemctl restart wazuh-manager`
18. This writes `/var/ossec/logs/archives/archives.json` with **all** events, not only the ones that fired a rule. That is the raw material for the dataset.

---

## Part 3 — VM2: Victim (Windows)

1. New VM → Windows ISO → name `victima-win`. 2 vCPU, 4 GB RAM, 60 GB disk, NAT network.
2. Install Windows normally with a local account (not a Microsoft account), skip the app setup.
3. Install VMware Tools (VM menu → Install VMware Tools).
4. Note the IP address: `ipconfig` in PowerShell.

### Install Sysmon (detailed telemetry)
5. Download Sysmon: https://learn.microsoft.com/sysinternals/downloads/sysmon
6. Download a proven config (SwiftOnSecurity's, widely used in the community): https://github.com/SwiftOnSecurity/sysmon-config → save `sysmonconfig-export.xml`
7. In PowerShell as administrator, inside the folder where you downloaded everything:
   ```powershell
   .\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
   ```

### Install the Wazuh agent
8. Download the Windows agent MSI installer from `https://WAZUH_MANAGER_IP` (the Wazuh dashboard has a wizard under Agents → Add agent that gives you the right command/MSI) or directly from https://documentation.wazuh.com (Windows agent section).
9. Install it from PowerShell (as administrator), pointing to the manager:
   ```powershell
   msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER='WAZUH_MANAGER_IP' WAZUH_AGENT_NAME='victima-win'
   ```
10. Start the service:
    ```powershell
    NET START WazuhSvc
    ```
11. Check in the Wazuh dashboard (Agents) that `victima-win` shows as **Active**.

---

## Part 4 — VM3: Kali (attacker)

1. Import the prebuilt Kali image (File → Open → select the `.vmx` included in the downloaded ZIP).
2. Change its network to NAT (same VMnet8).
3. Default user/password: `kali` / `kali`.
4. Update it:
   ```
   sudo apt update && sudo apt full-upgrade -y
   ```
5. Note its IP address: `ip a`

---

## Part 5 — Generate attacks (build the dataset)

The idea is to simulate attacks mapped to MITRE ATT&CK and record **when** you run them, so the dataset can be labelled later (window = attack vs. window = normal). The more tactics you cover (not only brute force), the better the model will generalize.

Lab addresses: Ubuntu/Wazuh manager `WAZUH_MANAGER_IP`, Windows victim `VICTIM_IP`.

### 0. Prerequisite: install Suricata on the victim (otherwise Wazuh does not see network scans)

**Why it is needed:** Wazuh is a HIDS — it only analyzes logs generated inside a host (Windows Event Log, Sysmon, file integrity). An `nmap` scan does not create anything in those logs by itself, and the traffic between Kali and the victim never goes through the manager VM (it goes directly through VMware's virtual switch). The solution is to install Suricata (NIDS) directly on `victima-win`, so the endpoint itself inspects the network traffic it receives and reports it to Wazuh through the agent you already installed.

**Everything below is done on `victima-win` (`VICTIM_IP`), except the final test step, which runs from Kali.**

1. Install Npcap (packet capture on Windows): download it from https://npcap.com/#download and run the installer. Select the option **"Install Npcap in WinPcap API-compatible Mode"**.

2. Install Suricata for Windows: download the installer from https://www.suricata.io/download/ and run it (by default it installs to `C:\Program Files\Suricata`).

3. Review the configuration in `C:\Program Files\Suricata\suricata.yaml`:
   - **Important about `HOME_NET`:** the default value (`192.168.0.0/16,10.0.0.0/8,172.16.0.0/12`) is so broad that it includes both the victim and Kali. Most Emerging Threats scan/recon rules are written to fire when traffic goes from `$EXTERNAL_NET` (`!$HOME_NET`) to `$HOME_NET` — if Kali is also inside `HOME_NET`, those rules never match and you will not see alerts for the scans (although you will see others that do not depend on direction, such as P2P traffic rules). So **narrow `HOME_NET` down to just your victim**, which automatically makes Kali "external":
     ```yaml
     vars:
       address-groups:
         HOME_NET: "[VICTIM_IP/32]"
     ```
   - Confirm that eve logging is enabled (it is by default):
     ```yaml
     outputs:
       - eve-log:
           enabled: yes
           filetype: regular
           filename: eve.json
     ```
   - **Important to avoid overloading the Wazuh agent:** by default Suricata logs to `eve.json` not only alerts but every flow, DNS, TLS, HTTP record, etc. for all traffic — that produces a huge volume that overflows the Windows agent buffer (you will see "Agent event queue is full. Events may be lost." in the dashboard, and you risk losing exactly the alerts you care about). Inside `types:` in that same section, keep **only** `alert`:
     ```yaml
     outputs:
       - eve-log:
           enabled: yes
           filetype: regular
           filename: eve.json
           types:
             - alert:
                 payload: no
                 metadata: yes
                 packet: no
                 http: no
                 tls: no
     ```
     Delete or comment out the other default entries in that list (`http:`, `dns:`, `tls:`, `files:`, `flow:`, `smtp:`, `ssh:`, `stats:`, etc.).
   - Complementary: increase the Wazuh agent buffer just in case. In `C:\Program Files (x86)\ossec-agent\ossec.conf`, add before `</ossec_config>`:
     ```xml
     <client_buffer>
       <disabled>no</disabled>
       <queue_size>50000</queue_size>
       <events_per_second>1000</events_per_second>
     </client_buffer>
     ```
     Restart the agent (`NET STOP WazuhSvc` / `NET START WazuhSvc`) after this change.
   - Note the `default-log-dir` (usually `C:\Program Files\Suricata\log`); that is where `eve.json` will be written.

4. Download the ruleset (Emerging Threats Open, free, includes scan/recon signatures). On Windows `suricata-update.exe` is not always bundled with the installer (unlike Linux), so the reliable way is manual:
   - Check your version: `.\suricata.exe -V` (in PowerShell, inside `C:\Program Files\Suricata`).
   - Go to https://rules.emergingthreats.net/open/ and open the folder matching your version. **Note:** for now Emerging Threats only publishes folders for `suricata-5.0` and `suricata-7.0.3` (nothing for the 8.x series yet) — the rule syntax is forward compatible, so if you run Suricata 8.x use `suricata-7.0.3`, the most recent one available.
   - Download the zip directly (lighter): `https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules.zip` and unzip it. It is the full set and includes scan/recon signatures.
   - Save it as `C:\Program Files\Suricata\rules\emerging-all.rules` (create the `rules` folder if it does not exist).
   - In `suricata.yaml`, find the `rule-files:` section and **replace the whole block** (do not just add a line — the default yaml includes a long list of files such as `botcc.rules`, `ciarmy.rules`, `compromised.rules`, `tor.rules`, etc. that do not exist on disk because they were meant to be generated by `suricata-update`; if you leave them, Suricata fails because it cannot find them). Leave it like this, with a single file:
     ```yaml
     default-rule-path: C:\Program Files\Suricata\rules
     rule-files:
       - emerging-all.rules
     ```
     Delete or comment out with `#` all other lines in that list.
   - Validate the configuration before running it live:
     ```powershell
     .\suricata.exe -T -c suricata.yaml
     ```
     It should end with `Configuration provided was successfully loaded`.
   - **Possible error: `unknown rule keyword 'file.magic'`.** The official Suricata build for Windows is not compiled with `libmagic` support, so that keyword does not exist there (it only affects a handful of "Zip Slip" detection rules and a 7-Zip exploit, nothing critical for the lab). Filter those lines out instead of fighting the library:
     ```powershell
     cd "C:\Program Files\Suricata\rules"
     Get-Content emerging-all.rules | Where-Object { $_ -notmatch "file\.magic" } | Set-Content emerging-all-clean.rules
     ```
     And in `suricata.yaml` point to `emerging-all-clean.rules` instead of `emerging-all.rules`. If another `unknown rule keyword` appears with a different name (e.g. `lua`), it is the same pattern: add it to the filter (`-notmatch "file\.magic|lua"`) and regenerate.
   - (Alternative if you have Python: `pip install suricata-update` and run it from there — on Windows it tends to cause more dependency problems; the manual download is more reliable for the lab.)

5. Identify the name of your network interface:
   ```powershell
   ipconfig
   ```
   Look for the adapter with the IP `VICTIM_IP` (usually something like `Ethernet0`).

6. Start Suricata on that interface (leave it running in its own PowerShell window while you work in the lab — for a homelab you do not need to install it as a service). **Important: open PowerShell/CMD as Administrator** (right click → "Run as administrator") before this — otherwise you will see `Permission denied` when it tries to write to `C:\Program Files\Suricata\log`, and Npcap needs administrator rights to capture packets anyway:
   ```powershell
   cd "C:\Program Files\Suricata"
   .\suricata.exe -c suricata.yaml -i Ethernet0
   ```
   Alternative if you want to avoid depending on permissions over `Program Files`: set `default-log-dir: C:\suricata-logs` in `suricata.yaml` (create the folder first with `mkdir C:\suricata-logs`) and adjust the `eve.json` path in step 7 accordingly.

   **Known bug in Suricata 8.0.x for Windows:** using the "friendly" interface name (`Ethernet0`) with `-i` makes the process crash (`msvcrt.dll`, error `0xc0000005`, shown as "Application Error" in Event Viewer). This is confirmed on the official Suricata forum for the same version. The fix is to use the **interface IP** instead of the name:
   ```powershell
   .\suricata.exe -c suricata.yaml -i VICTIM_IP
   ```
   If it still crashes, the alternative is to use the internal Npcap device ID (format `\Device\NPF_{GUID}`) instead of the name or the IP.

   **Optional — start Suricata automatically with Windows (instead of keeping the console open):** use NSSM (free, wraps any `.exe` as a Windows service):
   1. Download NSSM: https://nssm.cc/download (64-bit zip).
   2. Unzip it, e.g. to `C:\nssm`.
   3. In PowerShell as administrator:
      ```powershell
      C:\nssm\win64\nssm.exe install Suricata
      ```
   4. In the window that opens, fill in:
      - Path: `C:\Program Files\Suricata\suricata.exe`
      - Startup directory: `C:\Program Files\Suricata`
      - Arguments: `-c suricata.yaml -i VICTIM_IP`
   5. Click "Install service".
   6. Start it: `nssm start Suricata` (or from `services.msc`).
   7. Check in `services.msc` that the startup type is "Automatic". You can also force it from PowerShell: `Set-Service -Name Suricata -StartupType Automatic`.

   **While you are at it, confirm that the Wazuh agent also starts automatically** (it normally does by default with the MSI installer):
   ```powershell
   Get-Service WazuhSvc | Select-Object Name, Status, StartType
   ```
   If `StartType` is not `Automatic`: `Set-Service -Name WazuhSvc -StartupType Automatic`.

   **Recommended:** if you rely on Suricata starting automatically on a fixed IP (`-i VICTIM_IP`), set that IP as static on `victima-win` (Network settings → adapter → manual IPv4: IP `VICTIM_IP`, mask `255.255.255.0`, gateway `GATEWAY_IP`, DNS `8.8.8.8`) — this prevents a DHCP change from breaking the service after a reboot.

   Test it by rebooting the whole VM once to confirm that both services (`Suricata` and `WazuhSvc`) start on their own without manual intervention.
   If you want it to start as a Windows service later, you can wrap it with NSSM (`https://nssm.cc`), but for now keeping the console open is enough.

7. Configure the Wazuh agent to read the Suricata log. Edit `C:\Program Files (x86)\ossec-agent\ossec.conf` and add this block before `</ossec_config>`:
   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>C:\Program Files\Suricata\log\eve.json</location>
   </localfile>
   ```

8. Restart the agent service:
   ```powershell
   NET STOP WazuhSvc
   NET START WazuhSvc
   ```

9. You do not need to change anything on the manager (VM1): Wazuh already ships default rules to decode Suricata (`0475-suricata_rules.xml`).

   **If you still see no alerts when running `nmap` after fixing `HOME_NET`:** the Emerging Threats Open ruleset has almost no generic "this is a port scan" signatures (its rules target malware/C2/exploits with known content, not the behavioral pattern of a scan). The solution is to write your own custom rule (a good point for the README: you identified the gap and solved it yourself):
   1. Create `C:\Program Files\Suricata\rules\custom.rules`:
      ```
      alert tcp any any -> $HOME_NET any (msg:"CUSTOM SCAN Posible escaneo de puertos (Nmap)"; flags:S; threshold:type both, track by_src, count 20, seconds 10; classtype:attempted-recon; sid:9000001; rev:1; metadata:mitre_tactic_id TA0007, mitre_tactic_name Discovery, mitre_technique_id T1046, mitre_technique_name Network_Service_Scanning;)
      ```
      (it fires when a single source sends 20+ SYN packets to the victim within 10 seconds — the typical pattern of an `nmap` scan of the top 1000 ports. The `msg` text is kept in Spanish because it is the exact rule deployed in the lab.)
   2. Add it to `suricata.yaml`:
      ```yaml
      rule-files:
        - emerging-all-clean.rules
        - custom.rules
      ```
   3. Validate (`-T`) and restart the process/service.
   4. Repeat the `nmap` scan from Kali and check the Dashboard.

10. Test it, this time from **Kali**:
    ```
    nmap -sV -sC VICTIM_IP
    ```
    And check the Wazuh Dashboard — you should see new Suricata alerts almost immediately. If you want to confirm it directly on the manager before going to the dashboard:
    ```bash
    # on VM1 (Ubuntu, manager)
    sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -i suricata
    ```

With this, the lab goes from being purely HIDS to also having a NIDS layer — worth stating explicitly in the README as an architecture decision you identified and solved; it is not a minor detail.

### 1. Reconnaissance and scanning (from Kali)
```
nmap -sV -sC VICTIM_IP                    # standard service scan
nmap -sS -p- VICTIM_IP                    # all ports, SYN scan
nmap -A --script vuln VICTIM_IP           # known vulnerability detection
enum4linux -a VICTIM_IP                   # SMB enumeration (users, shares, policies)
smbclient -L //VICTIM_IP/ -N              # list SMB shares without authentication
crackmapexec smb VICTIM_IP                # quick SMB fingerprint
```

### 2. Brute force / credential access (enable RDP and/or SMB on the victim first)
```
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://VICTIM_IP
hydra -l administrator -P /usr/share/wordlists/rockyou.txt smb://VICTIM_IP
crackmapexec smb VICTIM_IP -u users.txt -p passwords.txt   # password spraying
```
Optional (more advanced, requires being on the same simulated local network): `sudo responder -I eth0` for LLMNR/NBT-NS poisoning to capture the NTLM hashes the victim sends when resolving mistyped names.

### 3. Lateral movement (with credentials already obtained or test credentials)
```
xfreerdp /v:VICTIM_IP /u:administrator /p:YOUR_PASSWORD          # real RDP login, generates event 4624/4625
crackmapexec smb VICTIM_IP -u administrator -p YOUR_PASSWORD -x "whoami"   # remote execution over SMB
```
(`crackmapexec` and the impacket tools such as `psexec.py` are installed with `pipx install crackmapexec` / `sudo apt install impacket-scripts` on Kali if they are not already there.)

### 4. Atomic Red Team — covers more MITRE tactics (run on `victima-win`)
Installation:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```
Widen the set of techniques so the dataset contains a variety of "malicious behaviors", not just one:

```powershell
# Execution
Invoke-AtomicTest T1059.001   # Malicious PowerShell
Invoke-AtomicTest T1059.003   # Windows Command Shell (abused cmd.exe)

# Credential access
Invoke-AtomicTest T1003       # Credential dumping (LSASS)
Invoke-AtomicTest T1003.001   # LSASS memory dump specifically

# Persistence
Invoke-AtomicTest T1547.001   # Registry Run keys
Invoke-AtomicTest T1053.005   # Malicious scheduled task

# Privilege escalation / defense evasion
Invoke-AtomicTest T1112       # Registry modification
Invoke-AtomicTest T1070.001   # Clearing Windows event logs
Invoke-AtomicTest T1562.001   # Disabling security tools

# Discovery (internal reconnaissance, already compromised)
Invoke-AtomicTest T1082       # System information discovery
Invoke-AtomicTest T1016       # Network configuration discovery
Invoke-AtomicTest T1018       # Remote system discovery
Invoke-AtomicTest T1087       # Account discovery

# Collection and exfiltration
Invoke-AtomicTest T1560       # Archive collected data (compression before exfiltration)
Invoke-AtomicTest T1041       # Exfiltration over C2 channel

# Command and control (beaconing simulation)
Invoke-AtomicTest T1071.001   # C2 traffic disguised as normal HTTP/HTTPS

# Impact (use with care, check what the test does before running it)
Invoke-AtomicTest T1486 -ShowDetailsBrief   # ransomware simulation (review the test; some only touch/rename test files in a sandbox folder)
```

Before running one you do not know, check what it does with `Invoke-AtomicTest <ID> -ShowDetailsBrief` (it runs nothing, it only describes the test) and clean up afterwards with `Invoke-AtomicTest <ID> -Cleanup` when available.

### 5. Varied "normal" traffic (as important as the attacks)
If all your benign traffic is "the victim doing nothing", the model will learn to detect "any activity" instead of "malicious activity". Generate realistic normal activity:
- Open and close Office applications, the browser, File Explorer.
- Copy files between folders and to a test network share.
- Run Windows updates or install/uninstall a legitimate program.
- Run your own script that simulates a user (opening random apps every X minutes) to get hours of benign traffic without having to be there manually.

### Window log (ground truth)
Keep a simple `.csv` with the columns: `mitre_technique, tactic, start_time, end_time, tool`. This is what you use in Part 7 to label each time window as `1` (malicious) or `0` (normal) when building the dataset.

---

## Part 6 — Export the dataset from Wazuh to your host

The data lives in the Wazuh Indexer (based on OpenSearch), port 9200 on VM1.

1. On your host (Windows/WSL2), install the Python client:
   ```
   pip install opensearch-py pandas
   ```
2. Example script to extract events (`extract_data.py`):
   ```python
   from opensearchpy import OpenSearch
   import pandas as pd

   client = OpenSearch(
       hosts=[{"host": "WAZUH_MANAGER_IP", "port": 9200}],
       http_auth=("admin", "YOUR_PASSWORD"),
       use_ssl=True,
       verify_certs=False,
   )

   query = {
       "query": {"range": {"@timestamp": {"gte": "2026-08-10T00:00:00", "lte": "2026-08-11T00:00:00"}}},
       "size": 10000,
   }

   res = client.search(index="wazuh-archives-*", body=query)
   rows = [hit["_source"] for hit in res["hits"]["hits"]]
   df = pd.json_normalize(rows)
   df.to_csv("dataset_raw.csv", index=False)
   ```
   (Note: the full-events index is called `wazuh-archives-*` once you enable the archives module in Filebeat on the manager — if you only see `wazuh-alerts-*`, check the Wazuh documentation on the "archives module" in `/var/ossec/etc/filebeat/module` to enable it.)

---

## Part 7 — Train the model (on the host, with the RTX 4060)

1. On Windows, install Python 3.11+ (or use WSL2 with Ubuntu if you prefer a more Linux-like environment — recommended).
2. Create a virtual environment:
   ```
   python -m venv venv
   venv\Scripts\activate
   pip install pandas scikit-learn matplotlib jupyter torch --index-url https://download.pytorch.org/whl/cu121
   ```
   (Check pytorch.org first for the exact command for your CUDA/driver version; you need an up-to-date NVIDIA driver, but you do not need to install the full CUDA Toolkit separately.)
3. Feature engineering: group events into time windows (e.g. 1 minute) per host, and compute columns such as:
   - total number of events
   - number of failed logon attempts (event id 4625)
   - number of processes created (Sysmon event id 1)
   - number of network connections (Sysmon event id 3)
   - diversity of uncommon parent-child processes
4. Label each window as `1` (malicious) if it falls inside a range you recorded in Part 5, otherwise `0`.
5. Unsupervised baseline model (Isolation Forest):
   ```python
   from sklearn.ensemble import IsolationForest
   model = IsolationForest(contamination=0.1, random_state=42)
   model.fit(X_train)
   ```
6. Supervised comparison model (Random Forest) or an autoencoder in PyTorch (uses the GPU) to compare precision/recall/F1/ROC-AUC metrics against Wazuh's native rules.
7. Save the model: `joblib.dump(model, "anomaly_model.pkl")` (or `torch.save(...)` for the autoencoder).

---

## Part 8 — Real-time scoring service (closing the loop)

1. Build a small API with FastAPI on the host:
   ```
   pip install fastapi uvicorn
   ```
2. Every N minutes, the API:
   - Queries the Wazuh Indexer for the latest events (same `opensearch-py` client).
   - Applies the same feature engineering as in Part 7.
   - Scores them with the trained model.
   - If the score exceeds a threshold, writes a JSON line to a local log file, e.g. `C:\ml-alerts\anomalies.log`.
3. On VM1 (Wazuh manager), configure a local log source so Wazuh reads that file (you will need to copy it or expose it through a shared folder/rsync), and define a decoder + custom rule in `/var/ossec/etc/rules/local_rules.xml` so those lines become native Wazuh alerts with their own group (e.g. `ml_anomaly`).
4. Result: in the Wazuh dashboard you will see traditional rule alerts and the alerts generated by your model side by side.

---

## Part 9 — Dashboard and results

1. In the Wazuh Dashboard, create a visualization (Discover / Dashboards) filtered by `rule.groups: ml_anomaly` to see only your model's detections.
2. Compare them against the standard rule alerts during the same attack windows you ran in Part 5.
3. Optional: set up Grafana on the same OpenSearch for a more visual panel of "model score over time" vs. "real attack windows" — it makes a very strong image for the README.

---

## Part 10 — Document and publish on GitHub

Suggested repository structure:
```
/docs        → architecture diagram, table of MITRE techniques tested
/ml          → notebooks, training script, saved model
/api         → FastAPI scoring service code
/wazuh       → custom rules and decoders (no passwords or sensitive data)
README.md    → problem, architecture, how to reproduce it, results (metrics + screenshots)
```

The README should include: the problem it solves, the architecture diagram, which attacks you tested (with MITRE IDs), model metrics (precision/recall/F1 compared with native rules), dashboard screenshots, and what you learned / next steps.

**Do not upload** the full dataset with real lab data or credentials — upload a small sample or a synthetic example dataset, and keep `.env`/passwords out with `.gitignore`.

---

## Next level (optional, once the MVP works)

- Add a second Linux victim to diversify the dataset.
- Add a Domain Controller (Windows Server + AD) for more realistic post-exploitation scenarios.
- Use Ansible (free) to automate the *configuration* of the VMs you already created (install Wazuh, Sysmon, etc.) over SSH — not to create the VMs themselves; doing that through Vagrant + VMware requires a paid plugin.
