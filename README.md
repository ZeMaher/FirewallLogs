# FirewllLogs
A PowerShell module for parsing, filtering, and analyzing firewall logs. Includes functions to read logs, apply filters (IP, port, user, rule), and resolve destination IPs to domain names using Pi-hole logs.

## Installation
## Option 1 - Installation script

To install the FirewallLogs module, simply downoad and run the included installer script (Install-FirewallLogs.ps1):

Open a PowerShell terminal and run the following command to download the installation script:

.\Install-FirewallLogs.ps1

This script will:
-Download the latest version of the module from GitHub
-Extract it into your PowerShell  folder
-Import the module automatically

## Option 2 - Manual installation

1) Open a new Powershell terminal

2) Clone this ripository: 
<<<<<<< HEAD
git clone https://github.com/ZeMaher/FirewllLogs.git
=======
git clone https://github.com/ZeMaher/FirewallLogs.git
>>>>>>> 780467ce2974e7b5b0fcc8912795354743af0581

3) Copy the FirewallLogs folder into your PowerShell Module path. 
To know the path you can run this commands:
 $env:PSModulePath -split ';'
 For example:
 - User scope: C:\Users\<User>\Documents\PowerShell\Modules\FirewallLogs
- System scope: C:\Program Files\PowerShell\Modules\FirewallLogs

4) Import the module with this command:
Import-Module FirewallLogs

5) Optional: Use this command to verify if the module is correctly installed: 
Get-Module -ListAvailable FirewallLogs
