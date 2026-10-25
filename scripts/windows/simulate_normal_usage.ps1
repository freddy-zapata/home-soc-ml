# simulate_normal_usage.ps1
# Simula actividad "normal" de usuario en victima-win para generar trafico benigno
# variado, asi el dataset de ML no aprende que "cualquier actividad = malicioso".
#
# Cada ciclo ejecuta 2-3 acciones aleatorias (no siempre las mismas), luego espera
# entre 1 y 4 minutos, y repite indefinidamente.
#
# Uso: correr en victima-win, dejar la ventana abierta (o lanzarlo oculto, ver el
# final de este archivo para el comando). Detener con Ctrl+C.

$urls = @(
    "https://www.wikipedia.org",
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.github.com",
    "https://www.python.org",
    "https://www.wazuh.com"
)

$testFile = "C:\Users\Public\Documents\test_normal.txt"
if (-not (Test-Path $testFile)) {
    "Archivo de prueba para simular actividad normal del usuario." | Out-File $testFile
}

function Simulate-WebRequest {
    try {
        $url = Get-Random -InputObject $urls
        Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10 | Out-Null
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Peticion web (background) a $url"
    } catch {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - (fallo de red al pedir $url, normal, seguimos)"
    }
}

function Simulate-BrowserWindow {
    try {
        $url = Get-Random -InputObject $urls
        # Si msedge no se reconoce por nombre corto, usa la ruta completa comentada abajo
        $proc = Start-Process "msedge.exe" -ArgumentList $url -PassThru -WindowStyle Minimized
        # $proc = Start-Process "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList $url -PassThru -WindowStyle Minimized
        Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 25)
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Navegador (ventana real) abierto/cerrado en $url"
    } catch { Write-Host "$(Get-Date -Format 'HH:mm:ss') - (fallo al abrir navegador)" }
}

function Simulate-Notepad {
    try {
        $proc = Start-Process notepad.exe -PassThru
        Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 15)
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Notepad abierto/cerrado"
    } catch {}
}

function Simulate-Cmd {
    try {
        $commands = @("dir C:\Users", "echo hola", "ipconfig /all", "whoami", "tasklist", "systeminfo")
        $cmd = Get-Random -InputObject $commands
        Start-Process cmd.exe -ArgumentList "/c $cmd" -WindowStyle Hidden -Wait
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - CMD ejecuto: $cmd"
    } catch {}
}

function Simulate-Explorer {
    try {
        Start-Process explorer.exe -ArgumentList "C:\Users\Public\Documents"
        Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 10)
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Explorador de archivos abierto"
    } catch {}
}

function Simulate-FileCopy {
    try {
        $dst = "C:\Users\Public\Documents\copia_$(Get-Random -Maximum 99999).txt"
        Copy-Item $testFile $dst -Force
        Start-Sleep -Seconds 2
        Remove-Item $dst -Force -ErrorAction SilentlyContinue
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Copia/borrado de archivo"
    } catch {}
}

function Simulate-OpenFile {
    try {
        Invoke-Item $testFile
        Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 10)
        Get-Process notepad -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Archivo abierto con su app por defecto"
    } catch {}
}

$actions = @(
    "Simulate-WebRequest",
    "Simulate-BrowserWindow",
    "Simulate-Notepad",
    "Simulate-Cmd",
    "Simulate-Explorer",
    "Simulate-FileCopy",
    "Simulate-OpenFile"
)

Write-Host "Iniciando simulacion de trafico normal. Ctrl+C para detener."

while ($true) {
    $numAcciones = Get-Random -Minimum 2 -Maximum 4   # 2 o 3 acciones por ciclo
    $seleccion = $actions | Get-Random -Count $numAcciones

    foreach ($accion in $seleccion) {
        & $accion
        Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 20)
    }

    $wait = Get-Random -Minimum 60 -Maximum 240
    Write-Host "$(Get-Date -Format 'HH:mm:ss') - Esperando $wait segundos antes del siguiente ciclo..."
    Start-Sleep -Seconds $wait
}
