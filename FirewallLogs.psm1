<#
Authors: Maher Gouja & Bryan Yu
Module Name: FirewallLogs
Term: Winter 2026
#>

# ---------------------------- #
# Function 1 : Get-FirewallLog #
# ---------------------------- #
function Get-FirewallLog {
    param (
        [Parameter(Mandatory=$true)]
        [Alias("P")]
        [string]$FirewallLogPath,

        # When used, all parsed fields are returned instead of the default minimal set
        [Alias("F")]
        [switch]$Full,

        # Limits the number of entries displayed (default: all)
        [Alias("L")]
        [int]$Limit = 0
    )

    # Verify that the specified log file exists before attempting to read it
    if (-not (Test-Path $FirewallLogPath)) {
        Write-Error "This firewall log file is not found : $FirewallLogPath"
        return
    }

    # Pre-compile regex patterns for performance
    $prefixRegex = [regex]'^(?<Date>\S+)\s+(?<Time>\S+)\s+(?<Device>\S+)\s+\[info\]'
    $kvRegex     = [regex]'(?<Key>\w+)=("(?<Value>[^"]+)"|(?<Value>\S+))'

    # Read all lines at once - faster than Get-Content for large files
    try {
        $lines = [System.IO.File]::ReadAllLines($FirewallLogPath)
    }
    catch {
        Write-Error "Failed to read firewall log file : $_"
        return
    }

    $total   = $lines.Count
    $i       = 0
    $entries = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Parse each line and collect entries
    foreach ($line in $lines) {
        $i++
        $percent = [math]::Round(($i / $total) * 100)
        Write-Progress -Activity "Fetching firewall logs..." -Status "Parsing entries ($i of $total)" -PercentComplete $percent

        $prefixMatch = $prefixRegex.Match($line)
        if (-not $prefixMatch.Success) { continue }

        # Build an ordered hashtable from the log prefix
        $entry = [ordered]@{
            Date   = $prefixMatch.Groups['Date'].Value
            Time   = $prefixMatch.Groups['Time'].Value
            Device = $prefixMatch.Groups['Device'].Value
        }

        # Extract all key=value pairs from the log line
        foreach ($match in $kvRegex.Matches($line)) {
            $entry[$match.Groups['Key'].Value] = $match.Groups['Value'].Value
        }

        if ($Full) {
            # Return all parsed fields
            $entries.Add([PSCustomObject]$entry)
        }
        else {
            # Return only the most relevant fields
            $entries.Add([PSCustomObject]@{
                Date     = $entry.Date
                Time     = $entry.Time
                Device   = $entry.Device
                Action   = $entry.log_subtype
                RuleName = $entry.fw_rule_name
                User     = $entry.user_name
                SrcIP    = $entry.src_ip
                SrcPort  = $entry.src_port
                DstIP    = $entry.dst_ip
                DstPort  = $entry.dst_Port
                Protocol = $entry.Protocol
            })
        }

        # Stop parsing once the limit is reached
        if ($Limit -gt 0 -and $entries.Count -ge $Limit) { break }
    }

    Write-Progress -Activity "Fetching firewall logs..." -Completed

    Write-Host "Showing $($entries.Count) of $total entries" -ForegroundColor Green

    # Calculate the longest property name for column alignment
    $maxLen    = ($entries[0].PSObject.Properties.Name | Measure-Object -Property Length -Maximum).Maximum
    $separator = "  $('-' * ($maxLen + 20))"

    # Display each entry with aligned colored output
    foreach ($result in $entries) {
        foreach ($prop in $result.PSObject.Properties) {
            $label = $prop.Name.PadRight($maxLen)
            Write-Host "  $label  " -ForegroundColor Cyan -NoNewline
            Write-Host ": " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($prop.Value)" -ForegroundColor White
        }
        Write-Host $separator -ForegroundColor DarkGray
    }
}


# --------------------------------- #
# Function 2 : Get-FirewallLogTable #
# --------------------------------- #

function Get-FirewallLogTable {
    param (
        [Parameter(Mandatory=$true)]
        [Alias("P")]
        [string]$FirewallLogPath,

        # Limits the number of entries displayed (default: 200)
        [Alias("L")]
        [int]$Limit = 200,

        # When used, results are displayed in a GridView window instead of the console
        [Alias("G")]
        [switch]$GridView
    )

    # Verify that the specified log file exists before attempting to read it
    if (-not (Test-Path $FirewallLogPath)) {
        Write-Error "This firewall log file is not found : $FirewallLogPath"
        return
    }

    # Read all lines at once - faster than Get-Content for large files
    try {
        $lines = [System.IO.File]::ReadAllLines($FirewallLogPath)
    }
    catch {
        Write-Error "Failed to read firewall log file : $_"
        return
    }

    $total = $lines.Count
    $i     = 0

    # Pre-compile regex patterns for performance
    $prefixRegex = [regex]'^(?<Date>\S+)\s+(?<Time>\S+)\s+(?<Device>\S+)\s+\[info\]'
    $kvRegex     = [regex]'(?<Key>\w+)=("(?<Value>[^"]+)"|(?<Value>\S+))'

    $entries = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Parse each line and collect entries up to the limit
    foreach ($line in $lines) {
        $i++
        $percent = [math]::Round(($i / $total) * 100)
        Write-Progress -Activity "Fetching firewall logs..." -Status "Parsing entries ($i of $total)" -PercentComplete $percent

        $prefixMatch = $prefixRegex.Match($line)
        if (-not $prefixMatch.Success) { continue }

        # Build an ordered hashtable from the log prefix
        $entry = [ordered]@{
            Date   = $prefixMatch.Groups['Date'].Value
            Time   = $prefixMatch.Groups['Time'].Value
            Device = $prefixMatch.Groups['Device'].Value
        }

        # Extract all key=value pairs from the log line
        foreach ($match in $kvRegex.Matches($line)) {
            $entry[$match.Groups['Key'].Value] = $match.Groups['Value'].Value
        }

        # Only keep the most relevant fields for the table view
        $entries.Add([PSCustomObject]@{
            Time      = $entry.Time
            Action    = $entry.log_subtype
            User      = $entry.user_name
            RuleName  = $entry.fw_rule_name
            SrcIP     = $entry.src_ip
            SrcPort   = $entry.src_port
            DstIP     = $entry.dst_ip
            DstPort   = $entry.dst_port
            Proto     = $entry.protocol
            App       = $entry.app_name
            SrcZone   = $entry.src_zone
            DstZone   = $entry.dst_zone
            SrcCtry   = $entry.src_country
            DstCtry   = $entry.dst_country
            BytesSent = $entry.bytes_sent
            BytesRecv = $entry.bytes_received
        })

        # Stop parsing once the limit is reached
        if ($entries.Count -ge $Limit) { break }
    }

    Write-Progress -Activity "Fetching firewall logs..." -Completed

    Write-Host "Showing $($entries.Count) of $total entries" -ForegroundColor Green

    if ($GridView) {
        # Open results in a separate interactive GridView window
        $entries | Out-GridView -Title "Get-FirewallLogTable - $FirewallLogPath ($($entries.Count) of $total entries)"
    }
    else {
        # Column definitions : header label, field name, column width
        $columns = @(
            @{ H = "Time";      F = "Time";      W = 10 }
            @{ H = "Action";    F = "Action";    W = 9  }
            @{ H = "User";      F = "User";      W = 14 }
            @{ H = "Rule";      F = "RuleName";  W = 20 }
            @{ H = "Src IP";    F = "SrcIP";     W = 16 }
            @{ H = "Src Pt";    F = "SrcPort";   W = 7  }
            @{ H = "Dst IP";    F = "DstIP";     W = 16 }
            @{ H = "Dst Pt";    F = "DstPort";   W = 7  }
            @{ H = "Proto";     F = "Proto";     W = 6  }
            @{ H = "App";       F = "App";       W = 22 }
            @{ H = "SrcZone";   F = "SrcZone";   W = 10 }
            @{ H = "DstZone";   F = "DstZone";   W = 8  }
            @{ H = "SrcCtry";   F = "SrcCtry";   W = 8  }
            @{ H = "DstCtry";   F = "DstCtry";   W = 8  }
            @{ H = "BytesSent"; F = "BytesSent"; W = 10 }
            @{ H = "BytesRecv"; F = "BytesRecv"; W = 10 }
        )

        # Build the header and separator lines from column definitions
        $header    = ""
        $separator = ""
        foreach ($col in $columns) {
            $header    += $col.H.PadRight($col.W)
            $separator += ('-' * ($col.W - 1)) + ' '
        }

        # Returns a color based on the firewall action
        function Get-ActionColor($action) {
            switch ($action) {
                "Allowed" { return "Green" }
                "Denied"  { return "Red"   }
                "Drop"    { return "Red"   }
                default   { return "White" }
            }
        }

        # Truncates a string to fit within the column width
        function Limit-String($str, $width) {
            if ($str.Length -gt ($width - 1)) {
                return $str.Substring(0, $width - 2) + "… "
            }
            return $str.PadRight($width)
        }

        Write-Host ""
        Write-Host $header -ForegroundColor Cyan
        Write-Host $separator -ForegroundColor DarkGray

        # Print each entry as a color-coded row
        foreach ($result in $entries) {
            $color = Get-ActionColor $result.Action
            $row   = ""
            foreach ($col in $columns) {
                $val  = if ($null -ne $result.($col.F)) { "$($result.($col.F))" } else { "" }
                $row += Limit-String $val $col.W
            }
            Write-Host $row -ForegroundColor $color
        }

        Write-Host ""
    }
}

# ----------------------------- #
# Function 3 : Find-FirewallLog #
# ----------------------------- #
function Find-FirewallLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias("P")]
        [string]$FirewallLogPath,

        # Filter results by source IP address
        [Alias("Src")]
        [string]$SourceIP,

        # Filter results by destination IP address
        [Alias("Dst")]
        [string]$DestinationIP,

        # Filter results by destination port number
        [Alias("Port")]
        [int]$DestinationPort,

        # Filter results by username
        [Alias("U")]
        [string]$User,

        # Filter results by firewall rule name
        [Alias("Rule")]
        [string]$RuleName
    )

    Write-Verbose "Checking if log file exists..."

    # Verify that the specified log file exists before attempting to read it
    if (-not (Test-Path $FirewallLogPath)) {
        Write-Error "This firewall log file is not found : $FirewallLogPath"
        return
    }
# Validate that each octet of the provided IP addresses is between 0 and 255
    if ($SourceIP) {
        $octets = $SourceIP.Split('.')
        foreach ($octet in $octets) {
            if ([int]$octet -lt 0 -or [int]$octet -gt 255) {
                Write-Error "Invalid source IP address : $SourceIP. Each octet must be between 0 and 255."
                return
            }
        }
    }

    if ($DestinationIP) {
        $octets = $DestinationIP.Split('.')
        foreach ($octet in $octets) {
            if ([int]$octet -lt 0 -or [int]$octet -gt 255) {
                Write-Error "Invalid destination IP address : $DestinationIP. Each octet must be between 0 and 255."
                return
            }
        }
    }
    Write-Verbose "Parsing log entries..."

    # Pre-compile regex patterns once for better performance across large log files
    $prefixRegex = [regex]'^(?<Date>\S+)\s+(?<Time>\S+)\s+(?<Device>\S+)\s+\[info\]'
    $kvRegex     = [regex]'(?<Key>\w+)=("(?<Value>[^"]+)"|(?<Value>\S+))'

    # Read all lines at once - faster than Get-Content for large files
    try {
        $lines = [System.IO.File]::ReadAllLines($FirewallLogPath)
    }
    catch {
        Write-Error "Failed to read firewall log file : $_"
        return
    }

    $total   = $lines.Count
    $i       = 0
    $entries = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Parse each line, extract the prefix and all key=value pairs,
    # and store the result as a PSCustomObject in the entries list
    foreach ($line in $lines) {
        $i++
        $percent = [math]::Round(($i / $total) * 100)
        Write-Progress -Activity "Fetching firewall logs..." -Status "Parsing entries ($i of $total)" -PercentComplete $percent

        # Skip lines that do not match the expected log prefix format
        $prefixMatch = $prefixRegex.Match($line)
        if (-not $prefixMatch.Success) { continue }

        # Build an ordered hashtable from the log prefix fields
        $entry = [ordered]@{
            Date   = $prefixMatch.Groups['Date'].Value
            Time   = $prefixMatch.Groups['Time'].Value
            Device = $prefixMatch.Groups['Device'].Value
        }

        # Append all key=value pairs found in the rest of the log line
        foreach ($match in $kvRegex.Matches($line)) {
            $entry[$match.Groups['Key'].Value] = $match.Groups['Value'].Value
        }

        $entries.Add([PSCustomObject]$entry)
    }

    Write-Progress -Activity "Fetching firewall logs..." -Completed

    Write-Verbose "Applying filters..."

    # Start with the full list and narrow it down based on whichever
    # filter parameters were provided by the user
    $results = $entries

    # Apply source IP filter if provided
    if ($SourceIP) {
        $results = $results | Where-Object { $_.src_ip -eq $SourceIP }
    }

    # Apply destination IP filter if provided
    if ($DestinationIP) {
        $results = $results | Where-Object { $_.dst_ip -eq $DestinationIP }
    }

    # Apply destination port filter if provided
    if ($DestinationPort) {
        $results = $results | Where-Object { $_.dst_port -eq $DestinationPort }
    }

    # Apply username filter if provided - field is user_name not user
    if ($User) {
        $results = $results | Where-Object { $_.user_name -eq $User }
    }

    # Apply rule name filter if provided - field is fw_rule_name not rule
    if ($RuleName) {
        $results = $results | Where-Object { $_.fw_rule_name -eq $RuleName }
    }

    Write-Verbose "Checking results..."

    # Notify the user if no entries matched the specified filters
    if (-not $results -or $results.Count -eq 0) {
        Write-Host "No matching firewall log entries found for the specified filters." -ForegroundColor Yellow
        return
    }

    # Display the number of matching entries and output the results
    Write-Host "$($results.Count) matching firewall log entries found." -ForegroundColor Green

    $results
}

# ---------------------------------- #
# Function 4 : Find-FirewallLogTable #
# ---------------------------------- #
function Find-FirewallLogTable {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias("P")]
        [string]$FirewallLogPath,

        # Filter results by source IP address
        [Alias("Src")]
        [string]$SourceIP,

        # Filter results by destination IP address
        [Alias("Dst")]
        [string]$DestinationIP,

        # Filter results by destination port number
        [Alias("Port")]
        [int]$DestinationPort,

        # Filter results by username
        [Alias("U")]
        [string]$User,

        # Filter results by firewall rule name
        [Alias("Rule")]
        [string]$RuleName,

        # Limits the number of entries displayed (default: 200)
        [Alias("L")]
        [int]$Limit = 200,

        # When used, results are displayed in a GridView window instead of the console
        [Alias("G")]
        [switch]$GridView
    )

    Write-Verbose "Checking if log file exists..."

    # Verify that the specified log file exists before attempting to read it
    if (-not (Test-Path $FirewallLogPath)) {
        Write-Error "This firewall log file is not found : $FirewallLogPath"
        return
    }

    # Validate that each octet of the provided IP addresses is between 0 and 255
    if ($SourceIP) {
        $octets = $SourceIP.Split('.')
        foreach ($octet in $octets) {
            if ([int]$octet -lt 0 -or [int]$octet -gt 255) {
                Write-Error "Invalid source IP address : $SourceIP. Each octet must be between 0 and 255."
                return
            }
        }
    }

    if ($DestinationIP) {
        $octets = $DestinationIP.Split('.')
        foreach ($octet in $octets) {
            if ([int]$octet -lt 0 -or [int]$octet -gt 255) {
                Write-Error "Invalid destination IP address : $DestinationIP. Each octet must be between 0 and 255."
                return
            }
        }
    }

    Write-Verbose "Parsing log entries..."

    # Pre-compile regex patterns once for better performance across large log files
    $prefixRegex = [regex]'^(?<Date>\S+)\s+(?<Time>\S+)\s+(?<Device>\S+)\s+\[info\]'
    $kvRegex     = [regex]'(?<Key>\w+)=("(?<Value>[^"]+)"|(?<Value>\S+))'

    # Read all lines at once -- faster than Get-Content for large files
    try {
        $lines = [System.IO.File]::ReadAllLines($FirewallLogPath)
    }
    catch {
        Write-Error "Failed to read firewall log file : $_"
        return
    }

    $total   = $lines.Count
    $i       = 0
    $entries = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Parse each line, extract the prefix and all key=value pairs,
    # and store the result as a PSCustomObject in the entries list
    foreach ($line in $lines) {
        $i++
        $percent = [math]::Round(($i / $total) * 100)
        Write-Progress -Activity "Fetching firewall logs..." -Status "Parsing entries ($i of $total)" -PercentComplete $percent

        # Skip lines that do not match the expected log prefix format
        $prefixMatch = $prefixRegex.Match($line)
        if (-not $prefixMatch.Success) { continue }

        # Build an ordered hashtable from the log prefix fields
        $entry = [ordered]@{
            Date   = $prefixMatch.Groups['Date'].Value
            Time   = $prefixMatch.Groups['Time'].Value
            Device = $prefixMatch.Groups['Device'].Value
        }

        # Append all key=value pairs found in the rest of the log line
        foreach ($match in $kvRegex.Matches($line)) {
            $entry[$match.Groups['Key'].Value] = $match.Groups['Value'].Value
        }

        $entries.Add([PSCustomObject]$entry)
    }

    Write-Progress -Activity "Fetching firewall logs..." -Completed

    Write-Verbose "Applying filters..."

    # Start with the full list and narrow it down based on whichever
    # filter parameters were provided by the user
    $results = $entries

    # Apply source IP filter if provided
    if ($SourceIP) {
        $results = $results | Where-Object { $_.src_ip -eq $SourceIP }
    }

    # Apply destination IP filter if provided
    if ($DestinationIP) {
        $results = $results | Where-Object { $_.dst_ip -eq $DestinationIP }
    }

    # Apply destination port filter if provided
    if ($DestinationPort) {
        $results = $results | Where-Object { $_.dst_port -eq $DestinationPort }
    }

    # Apply username filter if provided - field is user_name not user
    if ($User) {
        $results = $results | Where-Object { $_.user_name -eq $User }
    }

    # Apply rule name filter if provided - field is fw_rule_name not rule
    if ($RuleName) {
        $results = $results | Where-Object { $_.fw_rule_name -eq $RuleName }
    }

    Write-Verbose "Checking results..."

    # Notify the user if no entries matched the specified filters
    if (-not $results -or $results.Count -eq 0) {
        Write-Host "No matching firewall log entries found for the specified filters." -ForegroundColor Yellow
        return
    }

    # Select only the most relevant fields and apply the limit
    $table = $results | Select-Object -First $Limit | Select-Object `
        @{N="Time";      E={$_.Time}},
        @{N="Action";    E={$_.log_subtype}},
        @{N="User";      E={$_.user_name}},
        @{N="RuleName";  E={$_.fw_rule_name}},
        @{N="SrcIP";     E={$_.src_ip}},
        @{N="SrcPort";   E={$_.src_port}},
        @{N="DstIP";     E={$_.dst_ip}},
        @{N="DstPort";   E={$_.dst_port}},
        @{N="Proto";     E={$_.protocol}},
        @{N="App";       E={$_.app_name}},
        @{N="SrcZone";   E={$_.src_zone}},
        @{N="DstZone";   E={$_.dst_zone}},
        @{N="SrcCtry";   E={$_.src_country}},
        @{N="DstCtry";   E={$_.dst_country}},
        @{N="BytesSent"; E={$_.bytes_sent}},
        @{N="BytesRecv"; E={$_.bytes_received}}

    Write-Host "$($results.Count) matching entries found - showing first $($table.Count)" -ForegroundColor Green

    if ($GridView) {
        # Open results in a separate interactive GridView window
        $table | Out-GridView -Title "Find-FirewallLogTable - $FirewallLogPath ($($table.Count) of $($results.Count) entries)"
    }
    else {
        # Column definitions : header label, field name, column width
        $columns = @(
            @{ H = "Time";      F = "Time";      W = 10 }
            @{ H = "Action";    F = "Action";    W = 9  }
            @{ H = "User";      F = "User";      W = 14 }
            @{ H = "Rule";      F = "RuleName";  W = 20 }
            @{ H = "Src IP";    F = "SrcIP";     W = 16 }
            @{ H = "Src Pt";    F = "SrcPort";   W = 7  }
            @{ H = "Dst IP";    F = "DstIP";     W = 16 }
            @{ H = "Dst Pt";    F = "DstPort";   W = 7  }
            @{ H = "Proto";     F = "Proto";     W = 6  }
            @{ H = "App";       F = "App";       W = 22 }
            @{ H = "SrcZone";   F = "SrcZone";   W = 10 }
            @{ H = "DstZone";   F = "DstZone";   W = 8  }
            @{ H = "SrcCtry";   F = "SrcCtry";   W = 8  }
            @{ H = "DstCtry";   F = "DstCtry";   W = 8  }
            @{ H = "BytesSent"; F = "BytesSent"; W = 10 }
            @{ H = "BytesRecv"; F = "BytesRecv"; W = 10 }
        )

        # Build the header and separator lines from column definitions
        $header    = ""
        $separator = ""
        foreach ($col in $columns) {
            $header    += $col.H.PadRight($col.W)
            $separator += ('-' * ($col.W - 1)) + ' '
        }

        # Returns a color based on the firewall action
        function Get-ActionColor($action) {
            switch ($action) {
                "Allowed" { return "Green" }
                "Denied"  { return "Red"   }
                "Drop"    { return "Red"   }
                default   { return "White" }
            }
        }

        # Truncates a string to fit within the column width
        function Limit-String($str, $width) {
            if ($str.Length -gt ($width - 1)) {
                return $str.Substring(0, $width - 2) + "… "
            }
            return $str.PadRight($width)
        }

        Write-Host ""
        Write-Host $header -ForegroundColor Cyan
        Write-Host $separator -ForegroundColor DarkGray

        # Print each filtered entry as a color-coded row
        foreach ($result in $table) {
            $color = Get-ActionColor $result.Action
            $row   = ""
            foreach ($col in $columns) {
                $val  = if ($null -ne $result.($col.F)) { "$($result.($col.F))" } else { "" }
                $row += Limit-String $val $col.W
            }
            Write-Host $row -ForegroundColor $color
        }

        Write-Host ""
    }
}

# ---------------------------------------- #
# Function 5 : Resolve-FirewallDestination #
# ---------------------------------------- #
function Resolve-FirewallDestination {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias("P")]
        [string]$FirewallLogPath,

        [Parameter(Mandatory=$true)]
        [Alias("DNS")]
        [string]$PiholeLogPath,

        # When provided, resolution is only performed for this specific destination IP.
        # Cannot be used together with -Limit.
        [Alias("Dst")]
        [string]$DestinationIP,

        # Limits the number of resolved results when no destination IP is specified.
        # Cannot be used together with -Dst. (default: all)
        [Alias("L")]
        [int]$Limit = 0
    )

    if (-not (Test-Path $FirewallLogPath)) {
        Write-Error "This firewall log file is not found : $FirewallLogPath"
        return
    }

    if (-not (Test-Path $PiholeLogPath)) {
        Write-Error "This Pihole log file is not found : $PiholeLogPath"
        return
    }

    # -Limit and -Dst are mutually exclusive
    if ($DestinationIP -and $Limit -gt 0) {
        Write-Error "-Limit and -Dst cannot be used together. -Limit applies only when no destination IP is specified."
        return
    }

    # Hashtable used to map destination IPs to domain names
    $dnsTable = @{}

    # -- Phase 1 : Parse Pi-hole log and build DNS lookup table ----------------------
    # Only "reply <domain> is <IPv4>" lines are useful - CNAMEs and IPv6 are skipped.
    # The first domain seen for each IP is kept; duplicates are ignored.

    try {
        $piholeLines = [System.IO.File]::ReadAllLines($PiholeLogPath)
    }
    catch {
        Write-Error "Failed to read Pi-hole log file : $_"
        return
    }

    $total = $piholeLines.Count
    $i     = 0

    foreach ($line in $piholeLines) {
        $i++
        $percent = [math]::Round(($i / $total) * 100)
        Write-Progress -Id 1 -Activity "Parsing Pi-hole log..." -Status "Reading entries ($i of $total)" -PercentComplete $percent

        if ($line -match 'reply\s+(?<Domain>\S+)\s+is\s+(?<IP>\d+\.\d+\.\d+\.\d+)') {
            $ip     = $Matches.IP
            $domain = $Matches.Domain
            if (-not $dnsTable.ContainsKey($ip)) {
                $dnsTable[$ip] = $domain
            }
        }
    }

    Write-Progress -Id 1 -Activity "Parsing Pi-hole log..." -Completed

    # -- Phase 2 : Parse firewall log and collect unique destination IPs --------------
    # A HashSet is used to automatically deduplicate IPs across all log lines.

    $prefixRegex = [regex]'^(?<Date>\S+)\s+(?<Time>\S+)\s+(?<Device>\S+)\s+\[info\]'
    $kvRegex     = [regex]'(?<Key>\w+)=("(?<Value>[^"]+)"|(?<Value>\S+))'

    try {
        $fwLines = [System.IO.File]::ReadAllLines($FirewallLogPath)
    }
    catch {
        Write-Error "Failed to read firewall log file : $_"
        return
    }

    $total     = $fwLines.Count
    $i         = 0
    $uniqueIPs = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($line in $fwLines) {
        $i++
        $percent = [math]::Round(($i / $total) * 100)
        Write-Progress -Id 2 -Activity "Parsing firewall log..." -Status "Reading entries ($i of $total)" -PercentComplete $percent

        $prefixMatch = $prefixRegex.Match($line)
        if (-not $prefixMatch.Success) { continue }

        $entry = [ordered]@{}
        foreach ($match in $kvRegex.Matches($line)) {
            $entry[$match.Groups['Key'].Value] = $match.Groups['Value'].Value
        }

        $dstIP = $entry.dst_ip
        if ($dstIP) { $uniqueIPs.Add($dstIP) | Out-Null }
    }

    Write-Progress -Id 2 -Activity "Parsing firewall log..." -Completed

    # -- Phase 3 : Resolve each unique destination IP against the DNS table -----------

    $ipsToResolve = if ($DestinationIP) {
        @($DestinationIP)
    }
    else {
        $ips = $uniqueIPs | Sort-Object
        if ($Limit -gt 0) { $ips | Select-Object -First $Limit } else { $ips }
    }

    $total = $ipsToResolve.Count
    $i     = 0

    foreach ($ip in $ipsToResolve) {
        $i++
        $percent = [math]::Round(($i / $total) * 100)
        Write-Progress -Id 3 -Activity "Resolving destinations..." -Status "Processing ($i of $total)" -PercentComplete $percent

        $domain = if ($dnsTable.ContainsKey($ip)) { $dnsTable[$ip] } else { $null }

        [PSCustomObject]@{
            DestIP = $ip
            Domain = $domain
        }
    }

    Write-Progress -Id 3 -Activity "Resolving destinations..." -Completed
}

# Export the Get-FirewallLog, Get-FirewallLogTable, Find-FirewallLog, Find-FirewallLogTable, Resolve-FirewallDestination functions
Export-ModuleMember -Function Get-FirewallLog, Get-FirewallLogTable, Find-FirewallLog, Find-FirewallLogTable, Resolve-FirewallDestination
