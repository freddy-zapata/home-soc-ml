# generate_varied_traffic.ps1
# Genera trafico "normal" variado con ritmo diurno (mas actividad de 8 a 18 h, poca de noche).
# Pensado para correr como tarea programada de SYSTEM cada 5 minutos:
#   schtasks /create /tn "TraficoNormalVariado" /tr "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\generate_varied_traffic.ps1" /sc minute /mo 5 /ru "SYSTEM" /f
# Log propio: C:\ProgramData\TrafficLab\varied_traffic_log.txt
$ErrorActionPreference = "SilentlyContinue"
$base = "C:\ProgramData\TrafficLab"
$work = Join-Path $base "work"
New-Item -ItemType Directory $work -Force | Out-Null
function Log($m) { Add-Content (Join-Path $base "varied_traffic_log.txt") "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $m" }

$h = (Get-Date).Hour
if ($h -ge 8 -and $h -lt 18) { $p = 90 } elseif ($h -ge 18 -and $h -lt 23) { $p = 50 } else { $p = 15 }
if ((Get-Random -Maximum 100) -ge $p) { Log "Pausa (baja actividad)"; exit }
Start-Sleep -Seconds (Get-Random -Minimum 0 -Maximum 120)

$sites = @("https://www.wikipedia.org","https://en.wikipedia.org/wiki/Special:Random","https://www.python.org","https://www.github.com","https://www.microsoft.com","https://www.bbc.com","https://www.mozilla.org","https://stackoverflow.com","https://www.apache.org","https://www.debian.org","https://www.cloudflare.com","https://www.ubuntu.com")
$ua = @{ "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36" }

function A-Web { $u = Get-Random -InputObject $sites; Invoke-WebRequest -Uri $u -UseBasicParsing -Headers $ua -TimeoutSec 15 | Out-Null; Log "Web $u" }
function A-Dns { $d = Get-Random -InputObject @("github.com","python.org","microsoft.com","wikipedia.org","cloudflare.com","mozilla.org"); Resolve-DnsName $d | Out-Null; Log "DNS $d" }
function A-Download { $f = Join-Path $work "dl_$(Get-Random -Maximum 99999).png"; Invoke-WebRequest "https://www.python.org/static/img/python-logo.png" -OutFile $f -UseBasicParsing -Headers $ua; Start-Sleep 2; Remove-Item $f -Force; Log "Descarga pequena" }
function A-Files { $f = Join-Path $work "doc_$(Get-Random -Maximum 99999).txt"; 1..(Get-Random -Minimum 50 -Maximum 2000) | ForEach-Object { "linea $_ " + (Get-Random) } | Out-File $f; Get-Content $f | Measure-Object | Out-Null; $z = "$f.zip"; Compress-Archive $f $z -Force; Start-Sleep 2; Remove-Item $f, $z -Force; Log "Archivo creado/leido/comprimido" }
function A-Net { $gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -First 1).NextHop; Test-Connection $gw -Count 2 | Out-Null; Log "Ping gateway" }
function A-Sys { Get-WinEvent -LogName System -MaxEvents 20 | Out-Null; Get-NetTCPConnection | Select-Object -First 20 | Out-Null; Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Out-Null; Log "Consultas de sistema" }
function A-App { $a = Get-Random -InputObject @("notepad.exe","calc.exe","mspaint.exe"); $pr = Start-Process $a -PassThru; Start-Sleep (Get-Random -Minimum 5 -Maximum 20); Stop-Process -Id $pr.Id -Force; Log "App $a" }
function A-Api { Invoke-RestMethod "https://api.github.com/zen" -Headers $ua | Out-Null; Log "API publica" }

$acts = @("A-Web","A-Web","A-Dns","A-Download","A-Files","A-Net","A-Sys","A-App","A-Api")
foreach ($a in ($acts | Get-Random -Count (Get-Random -Minimum 2 -Maximum 5))) { & $a; Start-Sleep (Get-Random -Minimum 3 -Maximum 25) }
Log "Ciclo completado"
