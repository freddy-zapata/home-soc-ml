# wazuh/

Configuracion de Wazuh usada en el laboratorio. Es la configuracion **congelada** con la que se
genera el dataset oficial (T0 = `2026-10-26T18:30:00Z`): no se modifica hasta cerrar la recoleccion.

| Archivo | Va en | Maquina |
|---|---|---|
| `manager/local_rules.xml` | `/var/ossec/etc/rules/local_rules.xml` | Ubuntu (Wazuh manager) |
| `agent-windows/ossec.conf` | `C:\Program Files (x86)\ossec-agent\ossec.conf` | Windows victima (agente) |

## Marcadores

Las IPs reales se reemplazaron por marcadores en MAYUSCULAS. Antes de usar un archivo, cambia cada
marcador por el valor de tu red:

| Marcador | Que es |
|---|---|
| `WAZUH_MANAGER_IP` | IP del Wazuh manager al que se conecta el agente |

En la victima (PowerShell como administrador), por ejemplo:

```powershell
(Get-Content .\ossec.conf) -replace 'WAZUH_MANAGER_IP','10.0.0.10' | Set-Content .\ossec.conf
```

## Que se cambio respecto a la config por defecto

**Manager — `local_rules.xml`**
- Regla **100050** (nivel 10, MITRE **T1059.001**): alerta cuando un evento **4104** (PowerShell Script
  Block Logging) contiene `Invoke-RestMethod`, `Invoke-WebRequest`, `Compress-Archive`,
  `Net.WebClient`, `DownloadString`, `EncodedCommand` o `-enc`.
- La regla 100001 es el ejemplo que trae Wazuh de fabrica; se deja para que el archivo sea identico al del lab.

**Agente Windows — `ossec.conf`**
- `<client_buffer>`: `queue_size` 50000 (el valor por defecto se saturaba con Suricata).
- `<localfile>` del `eve.json` de Suricata (`C:\Program Files\Suricata\log\eve.json`, formato json).
- `<localfile>` del canal **Sysmon** (`Microsoft-Windows-Sysmon/Operational`).
- `<localfile>` del canal **PowerShell** (`Microsoft-Windows-PowerShell/Operational`, evento 4104).
  Requiere activar *Script Block Logging* en la victima.
- `<syscheck>`: FIM en **tiempo real** sobre `C:\Users\Public` y `C:\Windows\Temp` (`check_all`).

## Aplicar los cambios

Ubuntu (manager):
```bash
sudo cp local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-logtest      # opcional: probar con un evento 4104
sudo systemctl restart wazuh-manager
```

Windows victima (PowerShell como administrador):
```powershell
Copy-Item .\ossec.conf "C:\Program Files (x86)\ossec-agent\ossec.conf"
Restart-Service WazuhSvc
```

## Limitaciones conocidas (linea base de reglas)

- La 100050 tambien dispara con el trafico **benigno** del generador `generate_varied_traffic.ps1`
  (usa `Invoke-WebRequest` y `Compress-Archive`): es un falso positivo esperado de la linea base.
- El patron `-enc` tambien coincide con `-Encoding` (p. ej. `Out-File -Encoding utf8`).

Esto es intencional para el proyecto: la linea base son las reglas estaticas tal como se usarian en
la practica, y la capa de ML se evalua por cuanto reduce estos falsos positivos. Las etiquetas del
dataset salen de `data/attack_windows.csv`, nunca de las alertas de Wazuh.
