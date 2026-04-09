# Install-FirewallLogs.ps1

# URL to the Maher Gouja's FirewallLogs GitHub repository
$repoUrl  = "https://github.com/ZeMaher/FirewllLogs.git"

# URL to download the GitHub repository as a ZIP file (main branch)
$repoUrl  = "https://github.com/ZeMaher/FirewallLogs/archive/refs/heads/main.zip"

# Temporary file path where the ZIP file will be saved
$zipPath  = "$env:TEMP\FirewallLogs.zip"

# Path to the user's PowerShell Modules directory
$modulesPath = "$env:USERPROFILE\Documents\PowerShell\Modules"

# Target path where the FirewallLogs module should be in
$targetPath = Join-Path $modulesPath "FirewallLogs"

# Inform the user that the installation of the FirewallLogs module has started
Write-Host "Installing FirewallLogs module..."

# Ensure the Modules folder exists
# If it does not exist, it will be created.
if (-not (Test-Path $modulesPath)) {
    New-Item -ItemType Directory -Path $modulesPath | Out-Null
}

# Download the repository
Invoke-WebRequest -Uri $repoUrl -OutFile $zipPath -UseBasicParsing

# Extract to Modules folder
Expand-Archive -Path $zipPath -DestinationPath $modulesPath -Force

# GitHub zip adds '-main' to folder name, fix it
$extractedPath = Join-Path $modulesPath "FirewallLogs-main"

# Check the existence of the extracted path
if (Test-Path $extractedPath) {
    # If a previous version of the FirewallLogs exists, it will be removed.
    if (Test-Path $targetPath) { Remove-Item $targetPath -Recurse -Force }
    # Rename the extracted folder to "FirewallLogs
    Rename-Item -Path $extractedPath -NewName "FirewallLogs"
}

# Import the module
Import-Module FirewallLogs -Force

# Inform the user that the installation and the importation of the module were successful
Write-Host "FirewallLogs module installed and imported successfully!"
