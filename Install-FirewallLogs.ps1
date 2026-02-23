# Install-FirewallLogs.ps1
$repoUrl  = "https://github.com/ZeMaher/FirewllLogs.git"

$repoUrl  = "https://github.com/<YourRepo>/FirewallLogs/archive/refs/heads/main.zip"
$zipPath  = "$env:TEMP\FirewallLogs.zip"
$modulesPath = "$env:USERPROFILE\Documents\PowerShell\Modules"
$targetPath = Join-Path $modulesPath "FirewallLogs"

Write-Host "Installing FirewallLogs module..."

# Ensure Modules folder exists
if (-not (Test-Path $modulesPath)) {
    New-Item -ItemType Directory -Path $modulesPath | Out-Null
}

# Download the repo
Invoke-WebRequest -Uri $repoUrl -OutFile $zipPath -UseBasicParsing

# Extract to Modules folder
Expand-Archive -Path $zipPath -DestinationPath $modulesPath -Force

# GitHub zip adds '-main' to folder name, fix it
$extractedPath = Join-Path $modulesPath "FirewallLogs-main"
if (Test-Path $extractedPath) {
    if (Test-Path $targetPath) { Remove-Item $targetPath -Recurse -Force }
    Rename-Item -Path $extractedPath -NewName "FirewallLogs"
}

# Import the module
Import-Module FirewallLogs -Force

Write-Host "FirewallLogs module installed and imported successfully!"

