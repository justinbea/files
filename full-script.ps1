<#
.SYNOPSIS
  Uitgebreid modulair systeeminformatie script met interactieve keuzes en HTML/TXT rapportage.

.DESCRIPTION
  Dit script verzamelt uitgebreide systeeminformatie verdeeld in secties Hardware, Software, Security,
  Network en Performance. De gebruiker kiest interactief welke secties hij wil verzamelen en
  het outputformaat (HTML of Text) + outputlocatie.
  Het script formatteert bytes en datums netjes en kan optioneel het rapport per e-mail versturen via een
  JSON-configuratiebestand.

.EXAMPLE
  PS> .\SystemInfoPlus.ps1
  (Volg prompts om output te kiezen)
#>

#region Algemene hulpfuncties

function Convert-ToReadableSize {
    param([double]$SizeInBytes)
    if ($SizeInBytes -ge 1TB) { return "{0:N2} TB" -f ($SizeInBytes / 1TB) }
    elseif ($SizeInBytes -ge 1GB) { return "{0:N2} GB" -f ($SizeInBytes / 1GB) }
    elseif ($SizeInBytes -ge 1MB) { return "{0:N2} MB" -f ($SizeInBytes / 1MB) }
    elseif ($SizeInBytes -ge 1KB) { return "{0:N2} KB" -f ($SizeInBytes / 1KB) }
    else { return "$SizeInBytes Bytes" }
}

function Format-Date {
    param([Nullable[datetime]]$Date)
    if (-not $Date -or $Date -eq [datetime]::MinValue) {
        return "N/A"
    }
    try {
        return $Date.ToString("yyyy-MM-dd HH:mm:ss")
    }
    catch {
        return "Onbekend"
    }
}
    

function Prompt-UserSelection {
    param (
        [string]$Message,
        [string[]]$Options
    )
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "Opties: $($Options -join ', ')" -ForegroundColor Yellow
    $selectionRaw = Read-Host "Kies (komma-gescheiden lijst bijv: Hardware,Software)"
    $selection = $selectionRaw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $Options -contains $_ }
    if ($selection.Count -eq 0) {
        Write-Warning "Geen geldige optie gekozen, standaard wordt alles geselecteerd."
        return $Options
    }
    return $selection
}

function Convert-SectionToHtml {
    param (
        [string]$Title,
        [object]$Content
    )

    $html = "<div class='section'>"
    $html += "<h2>$Title</h2>"

    if ($Content -is [System.Collections.IDictionary]) {
        foreach ($key in $Content.Keys) {
            $sectionData = $Content[$key]
            $html += "<h3>$key</h3>"
            # Voor arrays van objecten netjes tabel maken
            if ($sectionData -is [System.Collections.IEnumerable] -and -not ($sectionData -is [string])) {
                $html += $sectionData | ConvertTo-Html -Fragment -PreContent "<p><strong>$key</strong></p>" -As Table
            }
            else {
                $html += "<pre>$sectionData</pre>"
            }
        }
    }
    else {
        # Als string of simpele objecten
        $html += $Content | Out-String | ForEach-Object { "<pre>$_</pre>" }
    }

    $html += "</div>"
    return $html
}

#endregion

#region Data verzamel functies

function Get-HardwareInfo {
    $computerSystem = Get-CimInstance Win32_ComputerSystem
    $processors = Get-CimInstance Win32_Processor
    $videoControllers = Get-CimInstance Win32_VideoController
    $bios = Get-CimInstance Win32_BIOS
    $baseBoard = Get-CimInstance Win32_BaseBoard
    $physicalMemory = Get-CimInstance Win32_PhysicalMemory
    $diskDrives = Get-CimInstance Win32_DiskDrive
    $diskPartitions = Get-CimInstance Win32_DiskPartition
    $logicalDisks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
    $netAdapters = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}

    return [ordered]@{
        ComputerInfo = [PSCustomObject]@{
            Name = $computerSystem.Name
            Manufacturer = $computerSystem.Manufacturer
            Model = $computerSystem.Model
            Domain = $computerSystem.Domain
            TotalPhysicalMemory = Convert-ToReadableSize $computerSystem.TotalPhysicalMemory
        }
        Processor = $processors | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Manufacturer = $_.Manufacturer
                MaxClockSpeedMHz = $_.MaxClockSpeed
                NumberOfCores = $_.NumberOfCores
                NumberOfLogicalProcessors = $_.NumberOfLogicalProcessors
            }
        }
        GPU = $videoControllers | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                AdapterRAM = Convert-ToReadableSize $_.AdapterRAM
                DriverVersion = $_.DriverVersion
                PNPDeviceID = $_.PNPDeviceID
            }
        }
        BIOS = [PSCustomObject]@{
            Name = $bios.Name
            Version = $bios.Version
            SerialNumber = $bios.SerialNumber

            ReleaseDate = try {
    Format-Date ([Management.ManagementDateTimeConverter]::ToDateTime($bios.ReleaseDate))
} catch {
    "Onbekend"
}



        }
        Motherboard = [PSCustomObject]@{
            Manufacturer = $baseBoard.Manufacturer
            Product = $baseBoard.Product
            SerialNumber = $baseBoard.SerialNumber
        }
        MemoryModules = $physicalMemory | ForEach-Object {
            [PSCustomObject]@{
                Manufacturer = $_.Manufacturer
                PartNumber = $_.PartNumber
                SpeedMHz = $_.Speed
                Capacity = Convert-ToReadableSize $_.Capacity
                DeviceLocator = $_.DeviceLocator
                SerialNumber = $_.SerialNumber
            }
        }
        DiskDrives = $diskDrives | ForEach-Object {
            [PSCustomObject]@{
                Model = $_.Model
                InterfaceType = $_.InterfaceType
                Size = Convert-ToReadableSize $_.Size
                SerialNumber = $_.SerialNumber
                MediaType = $_.MediaType
            }
        }
        Partitions = $diskPartitions | ForEach-Object {
            [PSCustomObject]@{
                DeviceID = $_.DeviceID
                Size = Convert-ToReadableSize $_.Size
                BlockSize = Convert-ToReadableSize $_.BlockSize
            }
        }
        LogicalDisks = $logicalDisks | ForEach-Object {
            [PSCustomObject]@{
                DeviceID = $_.DeviceID
                Size = Convert-ToReadableSize $_.Size
                FreeSpace = Convert-ToReadableSize $_.FreeSpace
                FileSystem = $_.FileSystem
            }
        }
        NetworkAdapters = $netAdapters | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Description = $_.InterfaceDescription
                MacAddress = $_.MacAddress
                LinkSpeedMbps = try {
    if ($_.LinkSpeed -is [string]) {
        [int]($_.LinkSpeed -replace '[^\d]', '')
    } else {
        [math]::Round($_.LinkSpeed / 1MB, 2)
    }
} catch {
    "Onbekend"
}

            }
        }
    }
}

function Get-SoftwareInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $hotfixes = Get-HotFix | Where-Object { $_.InstalledOn -ne $null } | Sort-Object InstalledOn -Descending
    $installedApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName } | Sort-Object DisplayName
    $services = Get-Service | Sort-Object Status, DisplayName
    $processes = Get-Process | Sort-Object CPU -Descending | Select-Object -First 25
    $startupCommands = Get-CimInstance Win32_StartupCommand

    return [ordered]@{
        OS = [PSCustomObject]@{
            Caption = $os.Caption
            Version = $os.Version
            BuildNumber = $os.BuildNumber
            InstallDate = if ($os.InstallDate -and $os.InstallDate.Length -ge 8) {
    try {
        Format-Date ([Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate))
    } catch {
        "Onbekend"
    }
} else {
    "N/A"
}

            OSArchitecture = $os.OSArchitecture
        }
        Hotfixes = $hotfixes | ForEach-Object {
            [PSCustomObject]@{
                HotFixID = $_.HotFixID
                InstalledOn = Format-Date $_.InstalledOn
                Description = $_.Description
                InstalledBy = $_.InstalledBy
                Source = $_.Source
            }
        }
        InstalledApps = $installedApps | ForEach-Object {
            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                DisplayVersion = $_.DisplayVersion
                Publisher = $_.Publisher
                InstallDate = if ($_.InstallDate) { Format-Date ([datetime]::ParseExact($_.InstallDate, "yyyyMMdd", $null)) } else { "N/A" }
            }
        }
        Services = $services | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                Status = $_.Status
                StartType = $_.StartType
            }
        }
        Processes = $processes | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                CPU = "{0:N2}" -f $_.CPU
                PM_MB = Convert-ToReadableSize ($_.PM)
                WS_MB = Convert-ToReadableSize ($_.WS)
                Id = $_.Id
                StartTime = try { Format-Date $_.StartTime } catch { "N/A" }
            }
        }
        StartupPrograms = $startupCommands | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Command = $_.Command
                Location = $_.Location
                User = $_.User
            }
        }
    }
}

function Get-SecurityInfo {
    $firewallProfiles = Get-NetFirewallProfile
    $firewallRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true }
    $defenderStatus = Get-MpComputerStatus
    $users = Get-LocalUser
    $groups = Get-LocalGroup
    $uac = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

    return [ordered]@{
        FirewallStatus = $firewallProfiles | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Enabled = $_.Enabled
                DefaultInboundAction = $_.DefaultInboundAction
                DefaultOutboundAction = $_.DefaultOutboundAction
                AllowInboundRules = $_.AllowInboundRules
            }
        }
        FirewallRules = $firewallRules | ForEach-Object {
            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                Direction = $_.Direction
                Action = $_.Action
                Enabled = $_.Enabled
                Profile = $_.Profile
                Group = $_.Group
            }
        }
        DefenderStatus = [PSCustomObject]@{
            RealTimeProtectionEnabled = $defenderStatus.RealTimeProtectionEnabled
            AntivirusEnabled = $defenderStatus.AntivirusEnabled
            AntivirusSignatureLastUpdated = Format-Date $defenderStatus.AntivirusSignatureLastUpdated
            AMServiceEnabled = $defenderStatus.AMServiceEnabled
            BehaviorMonitorEnabled = $defenderStatus.BehaviorMonitorEnabled
            FullScanAge = if ($defenderStatus.FullScanAge -ne $null) { "$($defenderStatus.FullScanAge) days" } else { "N/A" }
        }
        UserAccounts = $users | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Enabled = $_.Enabled
                Description = $_.Description
                LastLogon = Format-Date $_.LastLogon
            }
        }
        UserGroups = $groups | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Description = $_.Description
            }
        }
        UACStatus = [PSCustomObject]@{
            EnableLUA = $uac.EnableLUA
            ConsentPromptBehaviorAdmin = $uac.ConsentPromptBehaviorAdmin
        }
    }
}

function Get-NetworkInfo {
    $interfaces = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    $ipAddresses = Get-NetIPAddress
    $tcpConnections = Get-NetTCPConnection
    $arpTable = Get-NetNeighbor
    $dnsCache = Get-DnsClientCache
    $routes = Get-NetRoute

    return [ordered]@{
        NetworkInterfaces = $interfaces | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Description = $_.InterfaceDescription
                MacAddress = $_.MacAddress
                LinkSpeedMbps = try {
    if ($_.LinkSpeed -is [string]) {
        [int]($_.LinkSpeed -replace '[^\d]', '')
    } else {
        [math]::Round($_.LinkSpeed / 1MB, 2)
    }
} catch {
    "Onbekend"
}

            }
        }
        IPAddresses = $ipAddresses | ForEach-Object {
            [PSCustomObject]@{
                InterfaceAlias = $_.InterfaceAlias
                IPAddress = $_.IPAddress
                AddressFamily = $_.AddressFamily
            }
        }
        TCPConnections = $tcpConnections | ForEach-Object {
            [PSCustomObject]@{
                State = $_.State
                LocalAddress = $_.LocalAddress
                LocalPort = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort = $_.RemotePort
                OwningProcess = $_.OwningProcess
            }
        }
        ARPTable = $arpTable | ForEach-Object {
            [PSCustomObject]@{
                IPAddress = $_.IPAddress
                LinkLayerAddress = $_.LinkLayerAddress
                State = $_.State
            }
        }
        DNSCache = $dnsCache | ForEach-Object {
            [PSCustomObject]@{
                Entry = $_.Entry
                Name = $_.Name
                Data = $_.Data
            }
        }
        Routes = $routes | ForEach-Object {
            [PSCustomObject]@{
                DestinationPrefix = $_.DestinationPrefix
                NextHop = $_.NextHop
                RouteMetric = $_.RouteMetric
            }
        }
    }
}

function Get-PerformanceInfo {
    # CPU Load
    $cpuLoad = Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average | Select-Object -ExpandProperty Average

    # RAM Usage
    $ram = Get-CimInstance Win32_OperatingSystem
    $totalRAM = $ram.TotalVisibleMemorySize
    $freeRAM = $ram.FreePhysicalMemory
    $usedRamPercent = if ($totalRAM -gt 0) { [math]::Round((($totalRAM - $freeRAM) / $totalRAM) * 100, 2) } else { 0 }

    # Disk Usage
    $logicalDisks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
    $totalDiskSize = ($logicalDisks | Measure-Object -Property Size -Sum).Sum
    $totalFreeSpace = ($logicalDisks | Measure-Object -Property FreeSpace -Sum).Sum
    $usedDiskPercent = if ($totalDiskSize -gt 0) { [math]::Round((($totalDiskSize - $totalFreeSpace) / $totalDiskSize) * 100, 2) } else { 0 }

    # Network Traffic
    $netTraffic = Get-NetAdapterStatistics | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            ReceivedBytes = Convert-ToReadableSize $_.ReceivedBytes
            SentBytes = Convert-ToReadableSize $_.SentBytes
        }
    }

    # Event Log Errors afgelopen 7 dagen
    $errors = Get-EventLog -LogName System -EntryType Error -After (Get-Date).AddDays(-7) | Select-Object TimeGenerated, Source, Message -First 100

    return [ordered]@{
        CPUUsagePercent = $cpuLoad
        RAMUsagePercent = $usedRamPercent
        DiskUsagePercent = $usedDiskPercent
        NetworkTraffic = $netTraffic
        RecentSystemErrors = $errors
    }
}

#endregion

#region HTML Rapport Generator

function Generate-HTMLReport {
    param(
        [hashtable]$Data
    )

    $style = @"
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f9f9f9; color: #2c3e50; }
        h1, h2, h3 { color: #34495e; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th { background-color: #2980b9; color: white; padding: 8px; text-align: left; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #ecf0f1; }
        .section { background-color: white; padding: 15px; margin-bottom: 25px; border-radius: 6px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        footer { font-size: 12px; color: #999; text-align: center; margin-top: 40px; }
    "@

    $html = @"
<!DOCTYPE html>
<html lang='nl'>
<head>
    <meta charset='UTF-8'>
    <title>Systeemrapport - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
    <style>$style</style>
</head>
<body>
    <h1>Systeem Informatie Rapport</h1>
    <p>Gegenereerd op: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    <p>Computernaam: $($env:COMPUTERNAME)</p>
"@

    foreach ($section in $Data.Keys) {
        $html += Convert-SectionToHtml -Title $section -Content $Data[$section]
    }

    $html += @"
<footer>
    Rapport gegenereerd door SystemInfoPlus.ps1 – $(Get-Date -Format 'yyyy')
</footer>
</body>
</html>
"@

    return $html
}

#endregion

#region Tekst Rapport Generator

function Generate-TextReport {
    param(
        [hashtable]$Data
    )

    $sb = New-Object System.Text.StringBuilder

    $sb.AppendLine("Systeem Informatie Rapport")
    $sb.AppendLine("Gegenereerd op: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $sb.AppendLine("Computernaam: $($env:COMPUTERNAME)")
    $sb.AppendLine("=" * 60)

    foreach ($section in $Data.Keys) {
        $sb.AppendLine("Sectie: $section")
        $sb.AppendLine("-" * 60)

        $content = $Data[$section]

        if ($content -is [System.Collections.IDictionary]) {
            foreach ($key in $content.Keys) {
               $sb.AppendLine("  ${key}:")
                $val = $content[$key]

                if ($val -is [System.Collections.IEnumerable] -and -not ($val -is [string])) {
                    foreach ($item in $val) {
                        $line = ($item | Out-String).Trim()
                        $sb.AppendLine("    $line")
                    }
                }
                else {
                    $sb.AppendLine("    $val")
                }
                $sb.AppendLine()
            }
        }
        else {
            $sb.AppendLine($content)
        }
        $sb.AppendLine("=" * 60)
    }

    return $sb.ToString()
}

#endregion

#region Hoofdprogramma

Write-Host "=== SystemInfoPlus - Uitgebreid systeeminformatie script ===" -ForegroundColor Cyan

# Opties voor secties
$availableSections = @("Hardware", "Software", "Security", "Network", "Performance")

# Interactieve keuzes
$outputFormat = Read-Host "Kies outputformaat (HTML of Text) [standaard: HTML]"
if (-not $outputFormat) { $outputFormat = "HTML" }
$outputFormat = $outputFormat.ToUpper()
if ($outputFormat -ne "HTML" -and $outputFormat -ne "TEXT") {
    Write-Warning "Ongeldig formaat gekozen, standaard HTML wordt gebruikt."
    $outputFormat = "HTML"
}

$outputPath = Read-Host "Voer het volledige pad in voor de outputmap (bijv. C:\Temp\Reports) [standaard: huidige map]"
if (-not $outputPath) { $outputPath = (Get-Location).Path }
if (-not (Test-Path $outputPath)) {
    Write-Warning "Pad bestaat niet, maak het aan."
    New-Item -ItemType Directory -Path $outputPath | Out-Null
}

$selectedSections = Prompt-UserSelection -Message "Welke secties wil je verzamelen?" -Options $availableSections

# Start verzamelen
$systemData = @{}

if ($selectedSections -contains "Hardware")    { $systemData.Hardware    = Get-HardwareInfo }
if ($selectedSections -contains "Software")    { $systemData.Software    = Get-SoftwareInfo }
if ($selectedSections -contains "Security")    { $systemData.Security    = Get-SecurityInfo }
if ($selectedSections -contains "Network")     { $systemData.Network     = Get-NetworkInfo }
if ($selectedSections -contains "Performance") { $systemData.Performance = Get-PerformanceInfo }

# Bestandsnaam opbouwen
$datum = Get-Date -Format "yyyy-MM-dd_HH-mm"
$extension = if ($outputFormat -eq "HTML") { "html" } else { "txt" }
$rapportBestand = Join-Path -Path $outputPath -ChildPath "systeemrapport_$datum.$extension"

# Rapport genereren
if ($outputFormat -eq "HTML") {
    $htmlContent = Generate-HTMLReport -Data $systemData
    $htmlContent | Out-File -FilePath $rapportBestand -Encoding UTF8
}
else {
    $textContent = Generate-TextReport -Data $systemData
    $textContent | Out-File -FilePath $rapportBestand -Encoding UTF8
}


Write-Host "✅ Rapport gegenereerd: $rapportBestand" -ForegroundColor Green

$scriptPath = $MyInvocation.MyCommand.Path
$configDir = if ($scriptPath) {
    Split-Path -Parent $scriptPath
} else {
    $PWD.Path
}
$configPath = Join-Path -Path $configDir -ChildPath "mailconfig.json"



if (Test-Path $configPath) {
    try {
        $config = Get-Content $configPath | ConvertFrom-Json
        $securePass = ConvertTo-SecureString $config.password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($config.username, $securePass)

        $subject = "🖥️ Uitgebreid Systeemrapport - $datum - $($env:COMPUTERNAME)"
        $body = "Beste,$([Environment]::NewLine)$([Environment]::NewLine)In de bijlage vind je het uitgebreide systeemrapport van $datum.$([Environment]::NewLine)$([Environment]::NewLine)Groeten,$([Environment]::NewLine)SystemInfoPlus Script"

        Send-MailMessage -From $config.from -To $config.to -Subject $subject -Body $body -Attachments $rapportBestand -SmtpServer $config.smtpServer -Port $config.port -UseSsl -Credential $cred -Encoding UTF8

        Write-Host "✅ Rapport per e-mail verzonden naar $($config.to)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Kon rapport niet per e-mail versturen: $_"
    }
}

#endregion
