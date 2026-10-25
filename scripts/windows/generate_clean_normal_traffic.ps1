# generate_clean_normal_traffic.ps1
# Version "limpia" del generador de trafico normal: evita patrones que las reglas
# de Sysmon/Wazuh marcan como sospechosos (PowerShell->cmd.exe, drops en Public\Documents,
# relanzar explorer.exe con argumentos). Pensado para correr como TAREA PROGRAMADA
# de Windows (no como consola abierta manualmente), asi el proceso padre es el
# Programador de Tareas y no una sesion interactiva de PowerShell.
#
# El script corre UNA VEZ y termina; Task Scheduler lo vuelve a invocar cada N
# minutos (ver el comando de registro mas abajo).

$urls = @(
    "https://www.wikipedia.org",
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.github.com",
    "https://www.python.org"
)

$docsFolder = "C:\ProgramData\TrafficLab"
New-Item -ItemType Directory $docsFolder -Force | Out-Null
$testFile = Join-Path $docsFolder "nota_normal.txt"
if (-not (Test-Path $testFile)) {
    "Nota de prueba para trafico normal del sistema." | Out-File $testFile
}

function Log($msg) {
    Add-Content -Path (Join-Path $docsFolder "clean_traffic_log.txt") -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $msg"
}

# 1. Peticion web (legitima, sin abrir navegador ni disparar procesos hijos)
try {
    $url = Get-Random -InputObject $urls
    Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10 | Out-Null
    Log "Peticion web a $url"
} catch {
    Log "Fallo de red al pedir $url (normal, seguimos)"
}

# 2. Comandos de sistema NATIVOS de PowerShell (sin spawnear cmd.exe)
try {
    Get-Process | Out-Null
    Get-Service | Out-Null
    Get-ChildItem "C:\Windows\System32" -ErrorAction SilentlyContinue | Select-Object -First 20 | Out-Null
    Log "Consultas nativas de sistema (Get-Process/Get-Service/Get-ChildItem)"
} catch {}

# 3. Abrir una aplicacion comun brevemente, sin argumentos raros
try {
    $apps = @("notepad.exe", "calc.exe", "mspaint.exe")
    $app = Get-Random -InputObject $apps
    $proc = Start-Process $app -PassThru
    Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 15)
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Log "Apertura/cierre de $app"
} catch {}

# 4. Operacion de archivo en la carpeta de Documentos del propio usuario (no Public)
try {
    $dst = Join-Path $docsFolder "copia_$(Get-Random -Maximum 99999).txt"
    Copy-Item $testFile $dst -Force
    Start-Sleep -Seconds 2
    Remove-Item $dst -Force -ErrorAction SilentlyContinue
    Log "Copia/borrado de archivo en Documentos"
} catch {}

Log "Ciclo completado"
