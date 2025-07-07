$datum = Get-Date -Format "yyyy-MM-dd_HH-mm"
$config = Get-Content "C:\Users\Justin\Documents\Projects\Pws-Learning\mailconfig.json" | ConvertFrom-Json

$rapportPad = "C:\Users\Justin\Documents\Projects\Pws-Learning\systeemrapport_$datum.txt"
Add-Content $rapportPad "`n==========  SYSTEEMRAPPORT - $datum ==========`n"

Add-Content $rapportPad "`n Computerinformatie:"
#Get-ComputerInfo -Property Windows* | Out-String | Add-Content $rapportPad
Get-WmiObject -Class Win32_ComputerSystem | Out-String | Add-Content $rapportPad
Get-ComputerInfo -Property DeviceGuard* | Out-String | Add-Content $rapportPad

Add-Content $rapportPad "`n Processor:"
#Get-CimInstance Win32_Processor | Out-String | Add-Content $rapportPad
Get-WmiObject -ClassName Win32_Processor | Out-String | Add-Content $rapportPad
#Get-Counter '\Processor(*)\% Processor Time' | Out-String | Add-Content $rapportPad

Add-Content $rapportPad "`n RAM-modules:"
#Get-CimInstance Win32_PhysicalMemory | Out-String | Add-Content $rapportPad
Get-WmiObject -ClassName Win32_PhysicalMemory | Out-String | Add-Content $rapportPad
#Get-Counter '\Memory\Available MBytes' | Out-String | Add-Content $rapportPad
#Get-Counter '\Memory\% Committed Bytes In Use' | Out-String | Add-Content $rapportPad

Add-Content $rapportPad "`n BIOS:"
#Get-CimInstance Win32_BIOS | Out-String | Add-Content $rapportPad
Get-WmiObject -ClassName Win32_BIOS | Out-String | Add-Content $rapportPad
Get-HotFix | Out-String | Add-Content $rapportPad

Add-Content $rapportPad "`n OS:"
Get-CimInstance Win32_OperatingSystem | Out-String | Add-Content $rapportPad

Add-Content $rapportPad "`n Lokale gebruikers:"
Get-LocalUser | Out-String | Add-Content $rapportPad

Add-Content $rapportPad "`n Lokale groepen:"
Get-LocalGroup | Out-String | Add-Content $rapportPad

Add-Content $rapportPad "`n Grote mappen op C:\Users:"

$groteBestanden = Get-ChildItem -Path "C:\Users" -Recurse -Directory -ErrorAction SilentlyContinue |
    Where-Object { -not $_.PSIsContainer } |
    Sort-Object Length -Descending |
    Select-Object -First 20 FullName, @{Name="SizeMB";Expression={$_.Length / 1MB}} |
    Format-Table | Out-String

Add-Content $rapportPad $groteBestanden

Add-Content $rapportPad "`n Actieve processen:"
#Get-Process | Sort-Object CPU -Descending | Select-Object -First 25 | Out-String | Add-Content $rapportPad
Get-Process | Sort-Object WS -Descending | Select-Object -First 20 Handles,NPM,PM,WS,CPU,Id,SI,ProcessName | Format-Table | Out-String | Add-Content $rapportPad

Add-Content $rapportPad "`n Lopende services:"
Get-Service | Where-Object Status -eq 'Running' | Out-String | Add-Content $rapportPad

Add-Content $rapportPad "`n Opstartprogramma's:"
Get-CimInstance -ClassName Win32_StartupCommand | Out-String | Add-Content $rapportPad


Add-Content $rapportPad "`n IP-adressen:"
Get-NetIPAddress | Out-String | Add-Content $rapportPad

Add-Content $rapportPad "`n Netwerkadapters:"
Get-NetAdapter | Out-String | Add-Content $rapportPad

Add-Content $rapportPad "`n Actieve verbindingen (netstat):"
netstat -an | Out-String | Add-Content $rapportPad

Add-Content $rapportPad "`n Geïnstalleerde programma"
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName |
    Format-Table | Out-String | Add-Content $rapportPad


$gebruiker = (Get-ComputerInfo).CsUserName
$subject = "🖥️ Systeemrapport - $datum - $gebruiker"


$securePass = ConvertTo-SecureString $config.password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($config.username, $securePass)
$body = @"
Beste,

In de bijlage vind je het systeemrapport van $datum.

Groeten,
Justin
"@
Send-MailMessage `
    -From $config.from `
    -To $config.to `
    -Subject $subject `
    -Priority High `
    -Encoding ([System.Text.Encoding]::UTF8) `
    -Body $body `
    -SmtpServer $config.smtpServer `
    -Port $config.port `
    -UseSsl `
    -Credential $cred `
    -Attachments $rapportPad
