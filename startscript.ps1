# setup-devops.ps1
# ===============================================
# Uitgebreid script voor DevOps Windows 11 Setup
# Met foutafhandeling, logging en Windows security aanpassingen
# ===============================================

Start-Transcript -Path "$env:USERPROFILE\setup-devops.log" -Append

function Assert-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Warning "Dit script moet als administrator worden uitgevoerd."
        Stop-Transcript
        exit
    }
}

Assert-Admin

Write-Host "🔓 Instellen van Execution Policy op Bypass..." -ForegroundColor Cyan
Set-ExecutionPolicy Bypass -Scope Process -Force

Write-Host "📦 Installeren van Chocolatey indien nodig..." -ForegroundColor Cyan
try {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }
    choco feature enable -n allowGlobalConfirmation
} catch {
    Write-Warning "❌ Fout bij installeren/configureren van Chocolatey: $_"
}

# -----------------------------------------------
# Chocolatey pakketten
# -----------------------------------------------

$packages = @(
    "git", "vscode", "nodejs-lts", "github", "adoptopenjdk",
    "docker-desktop", "python3", "putty", "winscp", "wireshark",
    "googlechrome", "discord", "spotify", "steam", "jenkins",
    "gitlab-runner", "nginx", "terraform", "kubectl", "helm",
    "npcap", "python", "visualstudio2019buildtools", "vcredist-all",
    "postman", "notepadplusplus", "fzf", "openssh", "azure-cli",
    "gh", "warp", "minecraft-launcher", "7zip", "cmder"
)

foreach ($pkg in $packages) {
    try {
        Write-Host "📦 Installing $pkg..." -ForegroundColor Yellow
        choco install $pkg -y
    } catch {
        Write-Warning "❌ Fout bij installeren van $pkg: $_"
    }
}

# -----------------------------------------------
# Winget tools (indien beschikbaar)
# -----------------------------------------------

if (Get-Command winget -ErrorAction SilentlyContinue) {
    $wingetApps = @(
        "Microsoft.WindowsSDK", "Microsoft.Edge", "Microsoft.EdgeWebView2",
        "Microsoft.VisualStudio.2022.BuildTools", "Microsoft.PowerShell"
    )
    foreach ($app in $wingetApps) {
        try {
            Write-Host "🚀 Winget installing: $app" -ForegroundColor Yellow
            winget install --id $app --silent --accept-package-agreements --accept-source-agreements
        } catch {
            Write-Warning "❌ Winget installatie mislukt voor $app: $_"
        }
    }
}

# -----------------------------------------------
# Windows Features
# -----------------------------------------------

Write-Host "⚙️ Activeren van benodigde Windows features..." -ForegroundColor Cyan
try {
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -All -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName OpenSSH.Server -All -NoRestart
} catch {
    Write-Warning "❌ Windows feature activatie mislukt: $_"
}

# -----------------------------------------------
# Installeer WSL2 met Ubuntu
# -----------------------------------------------

Write-Host "🐧 Installeer WSL2 met Ubuntu..." -ForegroundColor Cyan
try {
    wsl --install -d Ubuntu
} catch {
    Write-Warning "❌ WSL installatie mislukt of reeds aanwezig."
}

# -----------------------------------------------
# VS Code Extensies
# -----------------------------------------------

$extensions = @(
    "ms-python.python", "redhat.java", "vscjava.vscode-java-debug",
    "vscjava.vscode-java-dependency", "vscjava.vscode-java-pack",
    "ms-azuretools.vscode-docker", "dbaeumer.vscode-eslint",
    "eamodio.gitlens", "esbenp.prettier-vscode"
)
foreach ($ext in $extensions) {
    try {
        Write-Host "🔌 Installing VS Code extension: $ext" -ForegroundColor Yellow
        code --install-extension $ext
    } catch {
        Write-Warning "❌ Installatie VS Code extensie mislukt: $ext"
    }
}

# -----------------------------------------------
# Python / Java / Node version managers
# -----------------------------------------------

Write-Host "📦 Installeren van pyenv, nvm, sdkman..." -ForegroundColor Cyan
try {
    Invoke-Expression "wsl sudo apt install curl zip unzip git -y"
    Invoke-Expression "wsl curl https://pyenv.run | bash"
    Invoke-Expression "wsl curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.5/install.sh | bash"
    Invoke-Expression "wsl curl -s \"https://get.sdkman.io\" | bash"
} catch {
    Write-Warning "❌ Installatie van versiemanagers in WSL mislukt: $_"
}

# -----------------------------------------------
# Thema en gebruikersvoorkeuren
# -----------------------------------------------

Write-Host "🎨 Instellen van thema en gebruikersvoorkeuren..." -ForegroundColor Cyan
try {
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -Value 0
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'SystemUsesLightTheme' -Value 0
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAlign /t REG_DWORD /d 0 /f
    $desktop = [Environment]::GetFolderPath("Desktop")
    New-Item "$desktop\Dev" -ItemType Directory -Force
    New-Item "$env:USERPROFILE\Projects" -ItemType Directory -Force
} catch {
    Write-Warning "❌ Thema of gebruikersvoorkeuren instellen mislukt: $_"
}

# -----------------------------------------------
# Windows Defender uitzonderingen (Dev folders)
# -----------------------------------------------

Write-Host "🔐 Uitzonderingen voor Windows Defender..." -ForegroundColor Cyan
try {
    Add-MpPreference -ExclusionPath "$env:USERPROFILE\Projects"
    Add-MpPreference -ExclusionPath "$env:USERPROFILE\.ssh"
} catch {
    Write-Warning "❌ Kon geen uitzonderingen instellen voor Defender. $_"
}

# -----------------------------------------------
# Setup voltooid
# -----------------------------------------------

Write-Host "✅ DevOps omgeving installatie voltooid. Herstart aanbevolen." -ForegroundColor Green
Stop-Transcript
