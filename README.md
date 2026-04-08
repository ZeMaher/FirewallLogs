#FirewllLogs
A powershell module for parsing, filtering, and analyzing firewall logs. Includes functions to read logs, apply filters (IP, port, user, rule), and resolve destination IPs to domain names using Pi-hole logs.

---

## Installation

### Option 1 - Automatic (recommended)

Download and run the included installer script:
```powershell
.\Install-FirewallLogs.ps1
```
   

This script will automatically download the latest version from GitHub, extract it into your PowerShell Modules folder, and import the module.

---

### Option 2 - Manual

1. Open a PowerShell terminal

2. Clone the repository:
```powershell
git clone https://github.com/ZeMaher/FirewallLogs.git
```


3. Copy the  FirewallLogs  folder into your PowerShell Modules path:
```powershell
# To find your modules path run:
$env:PSModulePath -split ';'
```

Common locations:
- User scope:  C:\Users\<User>\Documents\PowerShell\Modules\FirewallLogs 
- System scope:  C:\Program Files\PowerShell\Modules\FirewallLogs 

4. Import the module:
```powershell
Import-Module FirewallLogs
```


5. Verify the installation:
```powershell
Get-Module -ListAvailable FirewallLogs
```

## Functions

### 1. Get-FirewallLog
Parses a firewall log file and displays each entry in a detailed vertical format with aligned colored output.

**Parameters**

| Parameter         | Alias | Type   | Required | Default | Description                                                 |
|-------------------|-------|--------|----------|---------|-------------------------------------------------------------|
|  FirewallLogPath  |  -P   | string | Yes      |    —    | Path to the firewall log file                               |
|  Full             |  -F   | switch | No       | Off     | Return all parsed fields instead of the default minimal set |
|  Limit            |  -L   | int    | No       | 0 (all) | Maximum number of entries to display                        |

**Examples**
```powershell
# Display the first 50 entries
Get-FirewallLog -P "C:\logs\fw.log" -L 50

# Display all fields for the first 10 entries
Get-FirewallLog -P "C:\logs\fw.log" -F -L 10
```   

---

### 2.  Get-FirewallLogTable 
Parses a firewall log file and displays entries as a compact color-coded table. Rows are colored green for allowed traffic and red for denied/dropped traffic.

**Parameters**

| Parameter         | Alias | Type   | Required | Default | Description                                                              |
|-------------------|-------|--------|----------|---------|--------------------------------------------------------------------------|
|  FirewallLogPath  |  -P   | string | Yes      |    —    | Path to the firewall log file                                            |
|  Limit            |  -L   | int    | No       | 200     | Maximum number of entries to display                                     |
|  GridView         |  -G   | switch | No       | Off     | Display results in an interactive GridView window instead of the console |

**Examples**
```powershell
# Display the first 200 entries as a table
Get-FirewallLogTable -P "C:\logs\fw.log"

# Display the first 500 entries in GridView
Get-FirewallLogTable -P "C:\logs\fw.log" -L 500 -G
```   

---

### 3.  Find-FirewallLog 
Parses a firewall log file and filters entries based on one or more criteria. Results are displayed as PowerShell objects and can be piped to other commands.

**Parameters**

| Parameter         | Alias | Type   | Required | Default | Description                      |
|-------------------|-------|--------|----------|---------|----------------------------------|
|  FirewallLogPath  | -P    | string | Yes      |    —    | Path to the firewall log file    |
|  SourceIP         | -Src  | string | No       |    —    | Filter by source IP address      |
|  DestinationIP    | -Dst  | string | No       |    —    | Filter by destination IP address |
|  DestinationPort  | -Port | int    | No       |    —    | Filter by destination port number|
|  User             | -U    | string | No       |    —    | Filter by username               |
|  RuleName         | -Rule | string | No       |    —    | Filter by firewall rule name     |

> IP addresses are validated - each octet must be between 0 and 255.

**Examples**
```powershell
# Filter by source IP
Find-FirewallLog -P "C:\logs\fw.log" -Src "10.1.120.5"

# Filter by user and destination port
Find-FirewallLog -P "C:\logs\fw.log" -U "barney" -Port 443

# Filter by rule name
Find-FirewallLog -P "C:\logs\fw.log" -Rule "Web Browsing"
```   

---

### 4.  Find-FirewallLogTable 
Same filtering capabilities as  Find-FirewallLog  but displays results as a color-coded table instead of raw objects. Supports both console and GridView output.

**Parameters**

| Parameter         | Alias | Type   | Required | Default | Description                                       |
|-------------------|-------|--------|----------|---------|---------------------------------------------------|
|  FirewallLogPath  | -P    | string | Yes      |    —    || Path to the firewall log file                    |
|  SourceIP         | -Src  | string | No       |    —    | Filter by source IP address                       |
|  DestinationIP    | -Dst  | string | No       |    —    | Filter by destination IP address                  |
|  DestinationPort  | -Port | int    | No       |    —    | Filter by destination port number                 |
|  User             | -U    | string | No       |    —    | Filter by username                                |
|  RuleName         | -Rule | string | No       |    —    | Filter by firewall rule name                      |
|  Limit            | -L    | int    | No       | 200     | Maximum number of entries to display              |
|  GridView         | -G    | switch | No       | Off     | Display results in an interactive GridView window |

> IP addresses are validated - each octet must be between 0 and 255.

**Examples**
```powershell
# Filter by destination port, display as table
Find-FirewallLogTable -P "C:\logs\fw.log" -Port 443

# Filter by user, display in GridView
Find-FirewallLogTable -P "C:\logs\fw.log" -U "barney" -G

# Filter by source IP and rule, limit to 100 results
Find-FirewallLogTable -P "C:\logs\fw.log" -Src "10.1.120.5" -Rule "Web Browsing" -L 100
```   

---

### 5.  Resolve-FirewallDestination 
Cross-references destination IPs from a firewall log against a Pi-hole DNS log to resolve IP addresses to their corresponding domain names. Each unique destination IP is resolved only once.

**Parameters**

| Parameter         | Alias  | Type   | Required | Default | Description                                                   |
|-------------------|--------|--------|----------|---------|---------------------------------------------------------------|
|  FirewallLogPath  |  -P    | string | Yes      |    —    | Path to the firewall log file                                 |
|  PiholeLogPath    |  -DNS  | string | Yes      |    —    | Path to the Pi-hole log file                                  |
|  DestinationIP    |  -Dst  | string | No       |    —    | Resolve only this specific destination IP                     |
|  Limit            |  -L    | int    | No       | 0 (all) | Maximum number of IPs to resolve - cannot be used with  -Dst  |

>  -Limit  and  -Dst  are mutually exclusive. Using both together will return an error.

**Examples**
```powershell
# Resolve all unique destination IPs
Resolve-FirewallDestination -P "C:\logs\fw.log" -DNS "C:\logs\pihole.log"

# Resolve only a specific destination IP
Resolve-FirewallDestination -P "C:\logs\fw.log" -DNS "C:\logs\pihole.log" -Dst "4.236.211.230"

# Resolve the first 50 unique destination IPs
Resolve-FirewallDestination -P "C:\logs\fw.log" -DNS "C:\logs\pihole.log" -L 50
```   

---

## Log Format

The module expects firewall logs in the following format:
   
2026-01-29 00:00:11 cr431-firewall [info] key1="value1" key2="value2" ...
   

Pi-hole logs must be in the standard dnsmasq format:
   
Jan 29 00:00:05 dnsmasq[2401431]: UDP 2276827 10.1.5.14/60439 reply api.weather.com is 1.2.3.4
   

---

## Notes

- All functions use  [System.IO.File]::ReadAllLines()  for fast file reading, significantly faster than  Get-Content  for large log files.
- Progress bars are displayed during parsing phases and dismissed automatically before results are printed.
- The  -GridView  option requires Windows PowerShell or the  Microsoft.PowerShell.GraphicalTools  module on PowerShell 7.
- For log files with 50,000+ entries, always use  -Limit  or  -GridView  to avoid console buffer limitations.

---

## Authors

Maher Gouja & Bryan Yu - Polytechnique Montréal, Winter 2026