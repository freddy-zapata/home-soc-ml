# Lab: Home SOC + Detección de Anomalías con ML
Guía completa paso a paso — Host: Windows + VMware Workstation Pro

## Nota rápida sobre costos

- **VMware Workstation Pro**: gratis para uso personal desde noviembre 2024 (Broadcom). Necesitas una cuenta Broadcom gratuita para descargarlo, pero no piden tarjeta ni licencia paga. [Fuente](https://blogs.vmware.com/cloud-foundation/2024/11/11/vmware-fusion-and-workstation-are-now-free-for-all-users/)
- **Ansible**: 100% gratis y open source siempre. Lo puedes usar para configurar tus VMs (instalar paquetes, desplegar configs) conectándote por SSH, sin costo alguno.
- **Ojo con Vagrant + VMware**: si más adelante quieres que Vagrant *cree* automáticamente las VMs en VMware (no solo configurarlas), el plugin oficial `vagrant-vmware-desktop` de HashiCorp **sí es de pago** (con trial gratis). Para este lab no lo necesitas — vas a crear las VMs a mano en VMware Workstation, y si luego quieres automatizar, usas Ansible solo para configuración (eso sí es gratis) conectándote por SSH a las VMs ya creadas.
- **Wazuh, Kali, Ubuntu, Atomic Red Team, Sysmon, scikit-learn, PyTorch, FastAPI**: todo gratis y open source.

---

## Arquitectura del lab

| VM | SO | Rol | vCPU | RAM | Disco |
|---|---|---|---|---|---|
| VM1 | Ubuntu Server 24.04 LTS | Wazuh Manager + Indexer + Dashboard (SIEM) | 4 | 8 GB | 50 GB |
| VM2 | Windows 10/11 (evaluación) | Víctima (con Sysmon + agente Wazuh) | 2 | 4 GB | 60 GB |
| VM3 | Kali Linux | Atacante | 2 | 4 GB | 40 GB |

Total asignado: 16 GB de RAM (de tus 32 GB), dejando margen para el host y para entrenar el modelo.

**El entrenamiento de ML NO se hace dentro de una VM** — se hace en tu Windows host (o WSL2), para poder usar la RTX 4060 directamente sin pelear con passthrough de GPU. Las VMs solo generan y almacenan los datos; el host los procesa.

Red: todas las VMs van en la red **NAT** de VMware (VMnet8 por defecto). Se ven entre sí y tienen salida a internet para actualizar paquetes, pero quedan aisladas de tu red doméstica real.

---

## Parte 0 — Preparar el host

1. Verifica que la virtualización esté activa en el BIOS/UEFI (Intel VT-x). En Windows: Administrador de tareas → pestaña Rendimiento → CPU → debe decir "Virtualización: Habilitada".
2. Asegúrate de tener al menos 200 GB libres en disco.
3. Crea una cuenta gratuita en Broadcom: https://support.broadcom.com (regístrate, no pide pago).
4. Descarga VMware Workstation Pro desde el portal de Broadcom (busca "VMware Workstation Pro" en el Support Portal, versión 17.5.2 o superior / 26H1). Instálalo y, cuando pida licencia, elige la opción de uso personal sin ingresar clave.
5. Descarga las imágenes que vas a necesitar:
   - Ubuntu Server 24.04 LTS ISO: https://ubuntu.com/download/server
   - Windows 10 o 11 ISO de evaluación (90 días, gratis): Microsoft Evaluation Center
   - Kali Linux, imagen prearmada para VMware (no ISO, ya viene lista para importar): https://www.kali.org/get-kali/#kali-virtual-machines

---

## Parte 1 — Configurar la red virtual

1. En VMware Workstation: Edit → Virtual Network Editor.
2. Verifica que exista VMnet8 tipo NAT (viene por defecto). Anota el rango de subred que muestra (normalmente 192.168.x.0/24).
3. No necesitas crear nada nuevo: cuando crees cada VM, seleccionas "NAT" como tipo de red.

---

## Parte 2 — VM1: Wazuh Manager (SIEM)

### Crear la VM
1. File → New Virtual Machine → Typical → selecciona el ISO de Ubuntu Server.
2. Nombre: `soc-wazuh`. Asigna 50 GB de disco (archivo único).
3. Antes de terminar el wizard, click "Customize Hardware": pon 4 vCPU y 8 GB RAM. Red: NAT.

### Instalar Ubuntu Server
4. Arranca la VM e instala Ubuntu Server con el instalador (idioma, teclado, red por DHCP está bien).
5. En la partición de disco, usa "use entire disk".
6. Crea tu usuario y contraseña.
7. Cuando pregunte por "Featured Server Snaps", **marca OpenSSH server** (para poder administrarla por SSH desde tu host).
8. Termina la instalación y reinicia.

### Fijar IP estática (recomendado)
9. Ya logueado, revisa la interfaz: `ip a`. Edita el netplan:
   ```
   sudo nano /etc/netplan/50-cloud-init.yaml
   ```
   Cambia a algo así (ajusta el nombre de interfaz y subred a lo que veas con `ip a`):
   ```yaml
   network:
     version: 2
     ethernets:
       ens33:
         dhcp4: no
         addresses: [192.168.x.10/24]
         routes:
           - to: default
             via: 192.168.x.2
         nameservers:
           addresses: [8.8.8.8]
   ```
10. Aplica: `sudo netplan apply`

### Instalar Wazuh (todo en uno)
11. Actualiza el sistema:
    ```
    sudo apt update && sudo apt upgrade -y
    ```
12. Descarga e instala Wazuh usando el instalador asistido (instala indexer + manager + dashboard juntos):
    ```
    curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
    sudo bash ./wazuh-install.sh -a
    ```
13. **Guarda la contraseña de admin** que muestra al final del script (la necesitas para entrar al dashboard).
14. Firewall (si usas ufw): abre los puertos necesarios:
    ```
    sudo ufw allow 22/tcp
    sudo ufw allow 443/tcp
    sudo ufw allow 1514/tcp
    sudo ufw allow 1515/tcp
    sudo ufw allow 55000/tcp
    sudo ufw enable
    ```
15. Desde tu navegador en el host Windows, entra a `https://192.168.x.10` (acepta el certificado autofirmado) y logueate con `admin` y la contraseña guardada. Ya tienes tu SIEM funcionando.

### Habilitar el log de TODOS los eventos (no solo alertas)
Esto es clave para el ML: por defecto Wazuh solo guarda alertas (cuando una regla dispara), pero para entrenar un modelo de anomalías necesitas también el tráfico "normal".

16. Edita `/var/ossec/etc/ossec.conf` en el manager y activa el log completo:
    ```
    sudo nano /var/ossec/etc/ossec.conf
    ```
    Busca la sección `<global>` y asegúrate de tener:
    ```xml
    <global>
      <jsonout_output>yes</jsonout_output>
      <alerts_log>yes</alerts_log>
      <logall>yes</logall>
      <logall_json>yes</logall_json>
    </global>
    ```
17. Reinicia el manager: `sudo systemctl restart wazuh-manager`
18. Esto genera `/var/ossec/logs/archives/archives.json` con **todos** los eventos, no solo los que dispararon una regla. Esa es tu materia prima para el dataset.

---

## Parte 3 — VM2: Víctima (Windows)

1. New VM → ISO de Windows → nombre `victima-win`. 2 vCPU, 4 GB RAM, 60 GB disco, red NAT.
2. Instala Windows normal, cuenta local (no de Microsoft), sáltate el setup de apps.
3. Instala VMware Tools (VM menu → Install VMware Tools).
4. Anota la IP: `ipconfig` en PowerShell.

### Instalar Sysmon (telemetría detallada)
5. Descarga Sysmon: https://learn.microsoft.com/sysinternals/downloads/sysmon
6. Descarga una config probada (la de SwiftOnSecurity, muy usada en la comunidad): https://github.com/SwiftOnSecurity/sysmon-config → guarda `sysmonconfig-export.xml`
7. En PowerShell como administrador, dentro de la carpeta donde descargaste todo:
   ```powershell
   .\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
   ```

### Instalar el agente de Wazuh
8. Descarga el instalador MSI del agente Windows desde `https://192.168.x.10` (el propio dashboard de Wazuh tiene un asistente en Agents → Add agent que te da el comando/MSI correcto) o directo: https://documentation.wazuh.com (sección Windows agent).
9. Instala desde PowerShell (como administrador), apuntando al manager:
   ```powershell
   msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER='192.168.x.10' WAZUH_AGENT_NAME='victima-win'
   ```
10. Inicia el servicio:
    ```powershell
    NET START WazuhSvc
    ```
11. Verifica en el dashboard de Wazuh (Agents) que `victima-win` aparezca como **Active**.

---

## Parte 4 — VM3: Kali (atacante)

1. Importa la imagen prearmada de Kali (File → Open → selecciona el `.vmx` que viene en el ZIP descargado).
2. Cambia su red a NAT (misma VMnet8).
3. Usuario/clave por defecto: `kali` / `kali`.
4. Actualiza:
   ```
   sudo apt update && sudo apt full-upgrade -y
   ```
5. Anota su IP: `ip a`

---

## Parte 5 — Generar ataques (construir el dataset)

La idea es simular ataques mapeados a MITRE ATT&CK, y anotar **cuándo** los ejecutas, para poder etiquetar el dataset después (ventana = ataque vs. ventana = normal). Mientras más variedad de tácticas cubras (no solo fuerza bruta), mejor va a generalizar el modelo.

IPs de tu lab: Ubuntu/Wazuh manager `192.168.119.153`, víctima Windows `192.168.119.152`.

### 0. Requisito previo: instalar Suricata en la víctima (si no, Wazuh no ve los escaneos de red)

**Por qué hace falta:** Wazuh es un HIDS — solo analiza logs generados dentro de un host (Windows Event Log, Sysmon, integridad de archivos). Un `nmap` no genera nada en esos logs por sí solo, y el tráfico entre Kali y la víctima nunca pasa por la VM del manager (van directo por el switch virtual de VMware). La solución es instalar Suricata (NIDS) directamente en `victima-win`, para que el propio endpoint inspeccione el tráfico de red que recibe y se lo reporte a Wazuh vía el agente que ya tienes instalado.

**Todo lo siguiente se hace en `victima-win` (192.168.119.152), salvo el paso final de prueba que es desde Kali.**

1. Instala Npcap (captura de paquetes en Windows): descarga desde https://npcap.com/#download y ejecuta el instalador. Marca la opción **"Install Npcap in WinPcap API-compatible Mode"**.

2. Instala Suricata para Windows: descarga el instalador desde https://www.suricata.io/download/ y ejecútalo (por defecto queda en `C:\Program Files\Suricata`).

3. Revisa la configuración en `C:\Program Files\Suricata\suricata.yaml`:
   - **Importante sobre `HOME_NET`:** el valor por defecto (`192.168.0.0/16,10.0.0.0/8,172.16.0.0/12`) es tan amplio que incluye tanto a la víctima como a Kali. La mayoría de las reglas de escaneo/reconocimiento de Emerging Threats están escritas para disparar cuando el tráfico viene de `$EXTERNAL_NET` (`!$HOME_NET`) hacia `$HOME_NET` — si Kali también cae dentro de `HOME_NET`, esas reglas nunca calzan y no vas a ver alertas de los escaneos (aunque sí verás otras que no dependen de la dirección, como las de tráfico P2P). Por eso, **angosta `HOME_NET` para que sea solo tu víctima**, así Kali queda automáticamente como "externo":
     ```yaml
     vars:
       address-groups:
         HOME_NET: "[192.168.119.152/32]"
     ```
   - Confirma que el log en formato eve esté habilitado (viene así por defecto):
     ```yaml
     outputs:
       - eve-log:
           enabled: yes
           filetype: regular
           filename: eve.json
     ```
   - **Importante para no saturar el agente de Wazuh:** por defecto Suricata registra en `eve.json` no solo alertas, sino cada flujo, DNS, TLS, HTTP, etc. de todo el tráfico — eso genera un volumen enorme que satura el buffer del agente Windows (vas a ver "Agent event queue is full. Events may be lost." en el dashboard, y arriesgas perder justo las alertas que te interesan). Dentro de `types:` en esa misma sección, deja **solo** `alert`:
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
     Borra o comenta las demás entradas (`http:`, `dns:`, `tls:`, `files:`, `flow:`, `smtp:`, `ssh:`, `stats:`, etc.) que vienen por defecto en esa lista.
   - Complementario: agranda el buffer del agente de Wazuh por si acaso. En `C:\Program Files (x86)\ossec-agent\ossec.conf`, agrega antes de `</ossec_config>`:
     ```xml
     <client_buffer>
       <disabled>no</disabled>
       <queue_size>50000</queue_size>
       <events_per_second>1000</events_per_second>
     </client_buffer>
     ```
     Reinicia el agente (`NET STOP WazuhSvc` / `NET START WazuhSvc`) después de este cambio.
   - Anota el `default-log-dir` (normalmente `C:\Program Files\Suricata\log`), ahí va a quedar `eve.json`.

4. Descarga el set de reglas (Emerging Threats Open, gratis, incluye firmas de escaneo/reconocimiento). En Windows `suricata-update.exe` no siempre viene empaquetado con el instalador (a diferencia de Linux), así que la vía confiable es manual:
   - Revisa tu versión: `.\suricata.exe -V` (en PowerShell, dentro de `C:\Program Files\Suricata`).
   - Ve a https://rules.emergingthreats.net/open/ y entra a la carpeta que coincida con tu versión. **Nota:** por ahora Emerging Threats solo publica carpetas para `suricata-5.0` y `suricata-7.0.3` (nada de la serie 8.x todavía) — la sintaxis de las reglas es compatible hacia adelante, así que si tienes Suricata 8.x usa igual `suricata-7.0.3`, la más reciente disponible.
   - Descarga directo el zip (más liviano): `https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules.zip` y descomprímelo. Es el set completo, incluye firmas de escaneo/reconocimiento.
   - Guárdalo en `C:\Program Files\Suricata\rules\emerging-all.rules` (crea la carpeta `rules` si no existe).
   - En `suricata.yaml`, busca la sección `rule-files:` y **reemplaza todo el bloque** (no agregues una línea nada más — el yaml por defecto trae una lista larga de archivos como `botcc.rules`, `ciarmy.rules`, `compromised.rules`, `tor.rules`, etc. que no existen en disco porque estaban pensados para que `suricata-update` los generara; si los dejas, Suricata falla al no encontrarlos). Déjalo así, con un único archivo:
     ```yaml
     default-rule-path: C:\Program Files\Suricata\rules
     rule-files:
       - emerging-all.rules
     ```
     Borra o comenta con `#` todas las demás líneas de esa lista.
   - Valida la configuración antes de correrlo en vivo:
     ```powershell
     .\suricata.exe -T -c suricata.yaml
     ```
     Debe terminar con `Configuration provided was successfully loaded`.
   - **Posible error: `unknown rule keyword 'file.magic'`.** El build oficial de Suricata para Windows no viene compilado con soporte para `libmagic`, así que ese keyword no existe ahí (afecta solo un puñado de reglas de detección de "Zip Slip" y un exploit de 7-Zip, nada crítico para el lab). Filtra esas líneas en vez de pelear con la librería:
     ```powershell
     cd "C:\Program Files\Suricata\rules"
     Get-Content emerging-all.rules | Where-Object { $_ -notmatch "file\.magic" } | Set-Content emerging-all-clean.rules
     ```
     Y en `suricata.yaml` apunta a `emerging-all-clean.rules` en vez de `emerging-all.rules`. Si aparece otro `unknown rule keyword` con un nombre distinto (ej. `lua`), es el mismo patrón: agrégalo al filtro (`-notmatch "file\.magic|lua"`) y regenera.
   - (Alternativa si tienes Python: `pip install suricata-update` y correrlo desde ahí — en Windows suele dar más problemas de dependencias, la descarga manual es más confiable para el lab.)

5. Identifica el nombre de tu interfaz de red:
   ```powershell
   ipconfig
   ```
   Busca el adaptador que tiene la IP `192.168.119.152` (normalmente algo como `Ethernet0`).

6. Arranca Suricata apuntando a esa interfaz (déjalo corriendo en su propia ventana de PowerShell mientras trabajas en el lab — para un homelab no hace falta instalarlo como servicio). **Importante: abre PowerShell/CMD como Administrador** (clic derecho → "Ejecutar como administrador") antes de esto — si no, vas a ver `Permission denied` al intentar escribir en `C:\Program Files\Suricata\log`, y de todas formas Npcap necesita permisos de administrador para capturar paquetes:
   ```powershell
   cd "C:\Program Files\Suricata"
   .\suricata.exe -c suricata.yaml -i Ethernet0
   ```
   Alternativa si quieres evitar depender de permisos sobre `Program Files`: cambia `default-log-dir: C:\suricata-logs` en `suricata.yaml` (crea antes la carpeta con `mkdir C:\suricata-logs`) y ajusta la ruta del `eve.json` en el paso 7 de acuerdo a esto.

   **Bug conocido en Suricata 8.0.x para Windows:** usar el nombre "amigable" de la interfaz (`Ethernet0`) con `-i` hace que el proceso crashee (`msvcrt.dll`, error `0xc0000005`, sale como "Application Error" en el Visor de Eventos). Está confirmado en el foro oficial de Suricata para la misma versión. El fix es usar la **IP de la interfaz** en vez del nombre:
   ```powershell
   .\suricata.exe -c suricata.yaml -i 192.168.119.152
   ```
   Si aun así crashea, la alternativa es usar el ID interno del dispositivo Npcap (formato `\Device\NPF_{GUID}`) en vez del nombre o la IP.

   **Opcional — que Suricata arranque solo con Windows (no depender de dejar la consola abierta):** usa NSSM (gratis, envuelve cualquier `.exe` como servicio de Windows):
   1. Descarga NSSM: https://nssm.cc/download (zip 64-bit).
   2. Descomprime, ej. en `C:\nssm`.
   3. En PowerShell como administrador:
      ```powershell
      C:\nssm\win64\nssm.exe install Suricata
      ```
   4. En la ventana que se abre, llena:
      - Path: `C:\Program Files\Suricata\suricata.exe`
      - Startup directory: `C:\Program Files\Suricata`
      - Arguments: `-c suricata.yaml -i 192.168.119.152`
   5. Click "Install service".
   6. Arráncalo: `nssm start Suricata` (o desde `services.msc`).
   7. Verifica en `services.msc` que el tipo de inicio quede en "Automático". También puedes forzarlo por PowerShell: `Set-Service -Name Suricata -StartupType Automatic`.

   **De paso, confirma que el agente de Wazuh también arranque solo** (normalmente ya viene así por defecto desde el instalador MSI):
   ```powershell
   Get-Service WazuhSvc | Select-Object Name, Status, StartType
   ```
   Si `StartType` no dice `Automatic`: `Set-Service -Name WazuhSvc -StartupType Automatic`.

   **Recomendado:** si vas a depender de que Suricata arranque solo apuntando a una IP fija (`-i 192.168.119.152`), conviene fijar esa IP como estática en `victima-win` (Panel de red → adaptador → IPv4 manual: IP `192.168.119.152`, máscara `255.255.255.0`, gateway `192.168.119.2`, DNS `8.8.8.8`) — así evitas que un cambio de IP por DHCP rompa el servicio tras un reinicio.

   Prueba reiniciando la VM completa una vez para confirmar que ambos servicios (`Suricata` y `WazuhSvc`) arrancan solos sin intervención manual.
   Si quieres que arranque solo como servicio de Windows más adelante, puedes envolverlo con NSSM (`https://nssm.cc`), pero para ahora con la consola abierta es suficiente.

7. Configura el agente de Wazuh para que lea el log de Suricata. Edita `C:\Program Files (x86)\ossec-agent\ossec.conf` y agrega este bloque antes de `</ossec_config>`:
   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>C:\Program Files\Suricata\log\eve.json</location>
   </localfile>
   ```

8. Reinicia el servicio del agente:
   ```powershell
   NET STOP WazuhSvc
   NET START WazuhSvc
   ```

9. No necesitas tocar nada en el manager (VM1): Wazuh ya trae reglas por defecto para decodificar Suricata (`0475-suricata_rules.xml`).

   **Si después de arreglar `HOME_NET` sigues sin ver alertas al correr `nmap`:** el ruleset de Emerging Threats Open casi no trae firmas genéricas de "esto es un escaneo de puertos" (sus reglas apuntan a malware/C2/exploits con contenido conocido, no al patrón de comportamiento de un scan). La solución es escribir tu propia regla custom (buen punto para el README: identificaste el gap y lo resolviste tú):
   1. Crea `C:\Program Files\Suricata\rules\custom.rules`:
      ```
      alert tcp any any -> $HOME_NET any (msg:"CUSTOM SCAN Posible escaneo de puertos (Nmap)"; flags:S; threshold:type both, track by_src, count 20, seconds 10; classtype:attempted-recon; sid:9000001; rev:1; metadata:mitre_tactic_id TA0007, mitre_tactic_name Discovery, mitre_technique_id T1046, mitre_technique_name Network_Service_Scanning;)
      ```
      (dispara si un mismo origen manda 20+ SYN a la víctima en 10 segundos — el patrón típico de un `nmap` con top-1000 puertos.)
   2. Agrégalo en `suricata.yaml`:
      ```yaml
      rule-files:
        - emerging-all-clean.rules
        - custom.rules
      ```
   3. Valida (`-T`) y reinicia el proceso/servicio.
   4. Repite el `nmap` desde Kali y revisa el Dashboard.

10. Prueba, esta vez desde **Kali**:
    ```
    nmap -sV -sC 192.168.119.152
    ```
    Y revisa el Wazuh Dashboard — deberías ver alertas nuevas asociadas a Suricata casi de inmediato. Si quieres confirmarlo directo en el manager antes de ir al dashboard:
    ```bash
    # en VM1 (Ubuntu, manager)
    sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -i suricata
    ```

Con esto tu lab pasa de ser puramente HIDS a tener también una capa NIDS — vale la pena mencionarlo explícitamente en el README como una decisión de arquitectura que identificaste y resolviste, no es un detalle menor.

### 1. Reconocimiento y escaneo (desde Kali)
```
nmap -sV -sC 192.168.119.152                    # escaneo estándar de servicios
nmap -sS -p- 192.168.119.152                     # todos los puertos, SYN scan
nmap -A --script vuln 192.168.119.152            # detección de vulnerabilidades conocidas
enum4linux -a 192.168.119.152                    # enumeración SMB (usuarios, shares, políticas)
smbclient -L //192.168.119.152/ -N               # listar shares SMB sin autenticación
crackmapexec smb 192.168.119.152                 # fingerprint rápido vía SMB
```

### 2. Acceso por fuerza bruta / credenciales (habilita RDP y/o SMB en la víctima primero)
```
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.119.152
hydra -l administrator -P /usr/share/wordlists/rockyou.txt smb://192.168.119.152
crackmapexec smb 192.168.119.152 -u users.txt -p passwords.txt   # password spraying
```
Opcional (más avanzado, requiere estar en la misma red local simulada): `sudo responder -I eth0` para envenenamiento LLMNR/NBT-NS y capturar hashes NTLM que la víctima transmite al resolver nombres mal escritos.

### 3. Movimiento lateral (con credenciales ya obtenidas o de prueba)
```
xfreerdp /v:192.168.119.152 /u:administrator /p:TU_PASSWORD          # login RDP real, genera evento 4624/4625
crackmapexec smb 192.168.119.152 -u administrator -p TU_PASSWORD -x "whoami"   # ejecución remota vía SMB
```
(`crackmapexec` y las herramientas de impacket como `psexec.py` se instalan con `pipx install crackmapexec` / `sudo apt install impacket-scripts` en Kali si no vienen ya.)

### 4. Atomic Red Team — cubre más tácticas MITRE (ejecuta en `victima-win`)
Instalación (igual que antes):
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```
Amplía el set de técnicas para que el dataset tenga variedad de "comportamientos maliciosos", no solo uno:

```powershell
# Ejecución
Invoke-AtomicTest T1059.001   # PowerShell malicioso
Invoke-AtomicTest T1059.003   # Windows Command Shell (cmd.exe abusivo)

# Acceso a credenciales
Invoke-AtomicTest T1003       # Credential dumping (LSASS)
Invoke-AtomicTest T1003.001   # Dump específico de LSASS memory

# Persistencia
Invoke-AtomicTest T1547.001   # Registro Run keys
Invoke-AtomicTest T1053.005   # Scheduled Task malicioso

# Escalación de privilegios / evasión de defensas
Invoke-AtomicTest T1112       # Modificación de registro
Invoke-AtomicTest T1070.001   # Borrado de logs de Windows (event log clearing)
Invoke-AtomicTest T1562.001   # Deshabilitar herramientas de seguridad

# Descubrimiento (reconocimiento interno, ya comprometido)
Invoke-AtomicTest T1082       # System information discovery
Invoke-AtomicTest T1016       # Network configuration discovery
Invoke-AtomicTest T1018       # Remote system discovery
Invoke-AtomicTest T1087       # Account discovery

# Colección y exfiltración
Invoke-AtomicTest T1560       # Archivar datos recolectados (compresión antes de exfiltrar)
Invoke-AtomicTest T1041       # Exfiltración sobre canal C2

# Comando y control (simulación de beaconing)
Invoke-AtomicTest T1071.001   # Tráfico C2 disfrazado de HTTP/HTTPS normal

# Impacto (usa con cuidado, revisa qué hace el test antes de correrlo)
Invoke-AtomicTest T1486 -ShowDetailsBrief   # simulación de ransomware (revisa el test, algunos solo tocan/renombran archivos de prueba en una carpeta sandbox)
```

Antes de correr una que no conozcas, revisa qué hace con `Invoke-AtomicTest <ID> -ShowDetailsBrief` (no ejecuta nada, solo describe el test) y limpia después con `Invoke-AtomicTest <ID> -Cleanup` cuando esté disponible.

### 5. Tráfico "normal" variado (igual de importante que los ataques)
Si todo tu tráfico benigno es "la víctima sin hacer nada", el modelo va a aprender a detectar "cualquier actividad" en vez de "actividad maliciosa". Genera normalidad realista:
- Abre y cierra aplicaciones de Office, navegador, explorador de archivos.
- Copia archivos entre carpetas y hacia un share de red de prueba.
- Ejecuta actualizaciones de Windows o instala/desinstala un programa legítimo.
- Corre un script propio que simule un usuario (abrir apps random cada X minutos) para tener horas de tráfico benigno sin que tengas que estar ahí manualmente.

### Registro de ventanas (ground truth)
Lleva un `.csv` simple con columnas: `tecnica_mitre, tactica, hora_inicio, hora_fin, herramienta`. Esto es lo que usas en la Parte 7 para etiquetar cada ventana de tiempo como `1` (malicioso) o `0` (normal) al construir el dataset.

---

## Parte 6 — Sacar el dataset de Wazuh hacia tu host

Los datos viven en el Wazuh Indexer (basado en OpenSearch), puerto 9200 en VM1.

1. En tu host (Windows/WSL2), instala el cliente Python:
   ```
   pip install opensearch-py pandas
   ```
2. Script de ejemplo para extraer eventos (`extract_data.py`):
   ```python
   from opensearchpy import OpenSearch
   import pandas as pd

   client = OpenSearch(
       hosts=[{"host": "192.168.x.10", "port": 9200}],
       http_auth=("admin", "TU_PASSWORD"),
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
   (Nota: el índice de archivos completos se llama `wazuh-archives-*` una vez que actives el módulo de archives en Filebeat en el manager — si solo ves `wazuh-alerts-*`, revisa la doc de Wazuh sobre "archives module" en `/var/ossec/etc/filebeat/module` para habilitarlo.)

---

## Parte 7 — Entrenar el modelo (en el host, con la RTX 4060)

1. En Windows, instala Python 3.11+ (o usa WSL2 con Ubuntu si prefieres un entorno más parecido a Linux — recomendado).
2. Crea un entorno virtual:
   ```
   python -m venv venv
   venv\Scripts\activate
   pip install pandas scikit-learn matplotlib jupyter torch --index-url https://download.pytorch.org/whl/cu121
   ```
   (Verifica antes en pytorch.org el comando exacto para tu versión de CUDA/driver; necesitas el driver NVIDIA actualizado, no hace falta instalar el CUDA Toolkit completo aparte.)
3. Feature engineering: agrupa eventos en ventanas de tiempo (ej. 1 minuto) por host, y calcula columnas como:
   - cantidad de eventos totales
   - cantidad de intentos de login fallidos (event id 4625)
   - cantidad de procesos creados (Sysmon event id 1)
   - cantidad de conexiones de red (Sysmon event id 3)
   - diversidad de procesos padre-hijo poco comunes
4. Etiqueta cada ventana como `1` (malicioso) si cae dentro de un rango que registraste en la Parte 5, si no `0`.
5. Modelo baseline no supervisado (Isolation Forest):
   ```python
   from sklearn.ensemble import IsolationForest
   model = IsolationForest(contamination=0.1, random_state=42)
   model.fit(X_train)
   ```
6. Modelo supervisado de comparación (Random Forest) o un autoencoder en PyTorch (aprovecha la GPU) para comparar métricas de precisión/recall/F1/ROC-AUC contra las reglas nativas de Wazuh.
7. Guarda el modelo: `joblib.dump(model, "anomaly_model.pkl")` (o `torch.save(...)` si es el autoencoder).

---

## Parte 8 — Servicio de scoring en tiempo real (cerrar el ciclo)

1. Construye una API pequeña con FastAPI en el host:
   ```
   pip install fastapi uvicorn
   ```
2. La API, cada N minutos:
   - Consulta al Wazuh Indexer los eventos más recientes (mismo cliente `opensearch-py`).
   - Aplica el mismo feature engineering de la Parte 7.
   - Puntúa con el modelo entrenado.
   - Si el score supera un umbral, escribe una línea en un archivo de log local, ej. `C:\ml-alerts\anomalies.log`, con formato JSON.
3. En VM1 (manager de Wazuh), configura una fuente de log local para que Wazuh lea ese archivo (tendrás que copiarlo o exponerlo vía una carpeta compartida/rsync) y defines un decoder + regla custom en `/var/ossec/etc/rules/local_rules.xml` para que esas líneas se conviertan en alertas nativas de Wazuh, con su propio grupo (ej. `ml_anomaly`).
4. Resultado: en el dashboard de Wazuh vas a ver, lado a lado, las alertas por reglas tradicionales y las alertas generadas por tu modelo.

---

## Parte 9 — Dashboard y resultados

1. En el Wazuh Dashboard, crea una visualización (Discover / Dashboards) filtrando por `rule.groups: ml_anomaly` para ver solo las detecciones de tu modelo.
2. Compara contra las alertas de reglas estándar durante las mismas ventanas de ataque que ejecutaste en la Parte 5.
3. Opcional: monta Grafana apuntando al mismo OpenSearch para un panel más visual de "score del modelo a lo largo del tiempo" vs. "ventanas reales de ataque" — es una imagen muy fuerte para el README.

---

## Parte 10 — Documentar y subir a GitHub

Estructura sugerida del repo:
```
/docs        → diagrama de arquitectura, tabla de técnicas MITRE probadas
/ml          → notebooks, script de entrenamiento, modelo guardado
/api         → código del servicio FastAPI de scoring
/wazuh       → reglas y decoders custom (sin contraseñas ni datos sensibles)
README.md    → problema, arquitectura, cómo reproducirlo, resultados (métricas + capturas)
```

README debe incluir: qué problema resuelve, diagrama de arquitectura, qué ataques probaste (con IDs MITRE), métricas del modelo (precision/recall/F1 comparado con reglas nativas), capturas del dashboard, y qué aprendiste / próximos pasos.

**No subas** el dataset completo con datos reales del lab ni credenciales — sube una muestra pequeña o un dataset sintético de ejemplo, y deja el `.env`/contraseñas fuera con `.gitignore`.

---

## Siguiente nivel (opcional, cuando el MVP ya funcione)

- Agregar una segunda víctima Linux para diversificar el dataset.
- Meter un Domain Controller (Windows Server + AD) para escenarios más realistas de post-explotación.
- Usar Ansible (gratis) para automatizar la *configuración* de las VMs ya creadas (instalar Wazuh, Sysmon, etc.) conectándote por SSH — no para crear las VMs en sí, eso vía Vagrant+VMware sí tiene costo de plugin.
