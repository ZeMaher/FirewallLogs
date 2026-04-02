# Authors : Maher Gouja and Bryan Yu

# ---------------------------- #
# Function 1 : Get-FirewallLog #
# ---------------------------- #
function Get-FirewallLog {
    param (
        [Parameter(Mandatory=$true)]
        [Alias("P")]
        [string]$FirewallLogPath,

        [Alias("F")]
        [switch]$Full,

        # Limits the number of entries displayed (default: all)
        [Alias("L")]
        [int]$Limit = 0
    )

    if (-not (Test-Path $FirewallLogPath)) {
        Write-Error "This firewall log file is not found : $FirewallLogPath"
        return
    }

    # Read all lines at once — much faster than Get-Content for large files
    $lines = [System.IO.File]::ReadAllLines($FirewallLogPath)
    $total = $lines.Count
    $i = 0

    # Pre-compile regex patterns for performance
    $prefixRegex = [regex]'^(?<Date>\S+)\s+(?<Time>\S+)\s+(?<Device>\S+)\s+\[info\]'
    $kvRegex     = [regex]'(?<Key>\w+)=("(?<Value>[^"]+)"|(?<Value>\S+))'

    # Collect all parsed entries first
    $entries = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($line in $lines) {
        $i++

        # Calculate the percentage of the progress
        $percent = [math]::Round(($i / $total) * 100)
        # Display the progress of fetching and parsing the log entries in the firewall log file
        Write-Progress -Activity "Fetching firewall logs..." -Status "Parsing entries ($i of $total)" -PercentComplete $percent

        $prefixMatch = $prefixRegex.Match($line)

        # Skip lines that don't match the expected format
        if (-not $prefixMatch.Success) { continue }

        $entry = [ordered]@{
            Date   = $prefixMatch.Groups['Date'].Value
            Time   = $prefixMatch.Groups['Time'].Value
            Device = $prefixMatch.Groups['Device'].Value
        }

        foreach ($match in $kvRegex.Matches($line)) {
            $entry[$match.Groups['Key'].Value] = $match.Groups['Value'].Value
        }

        if ($Full) {
            $entries.Add([PSCustomObject]$entry)
        }
        else {
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

        # Stop parsing once we hit the limit — no point parsing the rest
        if ($Limit -gt 0 -and $entries.Count -ge $Limit) { break }
    }

    # Dismiss the progress bar before printing
    Write-Progress -Activity "Fetching firewall logs..." -Completed

    Write-Host "Showing $($entries.Count) of $total entries" -ForegroundColor Green

    # Find the longest property name for alignment (calculated once)
    $maxLen = ($entries[0].PSObject.Properties.Name | Measure-Object -Property Length -Maximum).Maximum
    $separator = "  $('─' * ($maxLen + 20))"

    # Display all entries
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

        # When this switch is used, results are displayed in a GridView window
        # instead of being printed in the console as a table
        [Alias("G")]
        [switch]$GridView
    )

    if (-not (Test-Path $FirewallLogPath)) {
        Write-Error "This firewall log file is not found : $FirewallLogPath"
        return
    }


    $lines = [System.IO.File]::ReadAllLines($FirewallLogPath)
    $total = $lines.Count
    $i = 0

    $prefixRegex = [regex]'^(?<Date>\S+)\s+(?<Time>\S+)\s+(?<Device>\S+)\s+\[info\]'
    $kvRegex     = [regex]'(?<Key>\w+)=("(?<Value>[^"]+)"|(?<Value>\S+))'

    $entries = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($line in $lines) {
        $i++
        $percent = [math]::Round(($i / $total) * 100)
        Write-Progress -Activity "Fetching firewall logs..." -Status "Parsing entries ($i of $total)" -PercentComplete $percent

        $prefixMatch = $prefixRegex.Match($line)
        if (-not $prefixMatch.Success) { continue }

        $entry = [ordered]@{
            Date   = $prefixMatch.Groups['Date'].Value
            Time   = $prefixMatch.Groups['Time'].Value
            Device = $prefixMatch.Groups['Device'].Value
        }

        foreach ($match in $kvRegex.Matches($line)) {
            $entry[$match.Groups['Key'].Value] = $match.Groups['Value'].Value
        }

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

        # Stop parsing once we hit the limit — no point parsing the rest
        if ($entries.Count -ge $Limit) { break }
    }

    Write-Progress -Activity "Fetching firewall logs..." -Completed

    Write-Host "Showing $($entries.Count) of $total entries" -ForegroundColor Green

    if ($GridView) {
        # Display results in a separate GridView window
        $entries | Out-GridView -Title "Get-FirewallLogTable — $FirewallLogPath ($($entries.Count) of $total entries)"
    }
    else {
        # Display results as a colored console table

        # Column definitions : header, field name, width
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

        $header    = ""
        $separator = ""
        foreach ($col in $columns) {
            $header    += $col.H.PadRight($col.W)
            $separator += ('─' * ($col.W - 1)) + ' '
        }

        function Get-ActionColor($action) {
            switch ($action) {
                "Allowed" { return "Green" }
                "Denied"  { return "Red"   }
                "Drop"    { return "Red"   }
                default   { return "White" }
            }
        }

        function Limit-String($str, $width) {
            if ($str.Length -gt ($width - 1)) {
                return $str.Substring(0, $width - 2) + "… "
            }
            return $str.PadRight($width)
        }

        Write-Host ""
        Write-Host $header -ForegroundColor Cyan
        Write-Host $separator -ForegroundColor DarkGray

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
    # enables -Verbose support
    [CmdletBinding()]
    param (
        # Path to the specified log file
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
        # int : integer (e.g. 80, 443, etc.)
        [Alias("Port")]
        [int]$DestinationPort,

        # Filter results by username
        [Alias("U")]
        [string]$User,

        # Filter results by firewall rule name
        [Alias("Rule")]
        [string]$RuleName
    )

    # Verify that the specified log file exists
    Write-Verbose "Checking if log file exists..."
    
    if (-not (Test-Path $FirewallLogPath)) {
        Write-Error "This firewall log file is not found : $FirewallLogPath"
        return
    }

    Write-Verbose "Parsing log entries..."
    
    # Loader start
    $lines = Get-Content $FirewallLogPath
    $total = $lines.Count
    $i = 0

    # Parse each line of the firewall log file
    $entries = foreach ($line in $lines) {
        $i++
        # Calculate the percentage of the progress
        $percent = [math]::Round(($i / $total) * 100)
        # Display the progress of fetching and parsing the log entries in the firewall log file
        Write-Progress -Activity "Fetching firewall logs..." -Status "Parsing entries ($i of $total)" -PercentComplete $percent

        # Extract all key=value pairs contained in the log entries
        $prefixPattern = '^(?<Date>\S+)\s+(?<Time>\S+)\s+(?<Device>\S+)\s+\[info\]'
        $prefixMatch = [regex]::Match($line, $prefixPattern)

        # Creation of an ordered hashtable so that properties appear
        # in order when they are converted in objects.
        $entry = [ordered]@{
            Date   = $prefixMatch.Groups['Date'].Value
            Time   = $prefixMatch.Groups['Time'].Value
            Device = $prefixMatch.Groups['Device'].Value
        }

        # Extract all key=value pairs contained in the log entries
        $kvPattern = '(?<Key>\w+)=("(?<Value>[^"]+)"|(?<Value>\S+))'
        foreach ($match in [regex]::Matches($line, $kvPattern)) {
            $entry[$match.Groups['Key'].Value] = $match.Groups['Value'].Value
        }

        # Convert the parsed entry to a PowerShell object
        [PSCustomObject]$entry
    }

    # Only apply filtering if at least one filter parameter is provided
    Write-Verbose "Applying filters..."
    $results = $entries

    #Loader end
    Write-Progress -Activity "Fetching firewall logs..." -Completed

    # If statement that applies the source IP address filter
    if ($SourceIP) {
        $results = $results | Where-Object { $_.src_ip -eq $SourceIP }
    }

    # If statement that applies the destination IP address filter
    if ($DestinationIP) {
        $results = $results | Where-Object { $_.dst_ip -eq $DestinationIP }
    }

    # If statement that applies the destination port number filter
    if ($DestinationPort) {
        $results = $results | Where-Object { $_.dst_port -eq $DestinationPort }
    }

    # If statement that applies the username (user) filter
    if ($User) {
        $results = $results | Where-Object { $_.user -eq $User }
    }

    # If statement that applies the firewall rule name filter
    if ($RuleName) {
        $results = $results | Where-Object { $_.rule -eq $RuleName }
    }
    
    # Display the filtered results
    $results

    Write-Verbose "Checking results..."

    # If no firewall log entries matched the filters, the user who
    # executed the Find-FirewallLog command will be notified.
    if (-not $results -or $results.Count -eq 0) {
        Write-Host "No matching firewall log entries found for the specified filters." -ForegroundColor Yellow
        return
    }

    # Display the number of matching log entries
    Write-Host "$($results.Count) matching firewall log entries found." -ForegroundColor Green
    
}

# ---------------------------------- #
# Function 4 : Find-FirewallLogTable #
# ---------------------------------- #
function Find-FirewallLogTable {
    [CmdletBinding()]
    param (
        # Path to the specified log file
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

        # When this switch is used, results are displayed in a GridView window
        # instead of being printed in the console as a table
        [Alias("G")]
        [switch]$GridView
    )

    Write-Verbose "Checking if log file exists..."

    if (-not (Test-Path $FirewallLogPath)) {
        Write-Error "This firewall log file is not found : $FirewallLogPath"
        return
    }

    Write-Verbose "Parsing log entries..."

    $lines = [System.IO.File]::ReadAllLines($FirewallLogPath)
    $total = $lines.Count
    $i = 0

    $prefixRegex = [regex]'^(?<Date>\S+)\s+(?<Time>\S+)\s+(?<Device>\S+)\s+\[info\]'
    $kvRegex     = [regex]'(?<Key>\w+)=("(?<Value>[^"]+)"|(?<Value>\S+))'

    $entries = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($line in $lines) {
        $i++
        $percent = [math]::Round(($i / $total) * 100)
        Write-Progress -Activity "Fetching firewall logs..." -Status "Parsing entries ($i of $total)" -PercentComplete $percent

        $prefixMatch = $prefixRegex.Match($line)
        if (-not $prefixMatch.Success) { continue }

        $entry = [ordered]@{
            Date   = $prefixMatch.Groups['Date'].Value
            Time   = $prefixMatch.Groups['Time'].Value
            Device = $prefixMatch.Groups['Device'].Value
        }

        foreach ($match in $kvRegex.Matches($line)) {
            $entry[$match.Groups['Key'].Value] = $match.Groups['Value'].Value
        }

        $entries.Add([PSCustomObject]$entry)
    }

    Write-Progress -Activity "Fetching firewall logs..." -Completed

    Write-Verbose "Applying filters..."

    $results = $entries

    if ($SourceIP) {
        $results = $results | Where-Object { $_.src_ip -eq $SourceIP }
    }

    if ($DestinationIP) {
        $results = $results | Where-Object { $_.dst_ip -eq $DestinationIP }
    }

    if ($DestinationPort) {
        $results = $results | Where-Object { $_.dst_port -eq $DestinationPort }
    }

    if ($User) {
        $results = $results | Where-Object { $_.user_name -eq $User }
    }

    if ($RuleName) {
        $results = $results | Where-Object { $_.fw_rule_name -eq $RuleName }
    }

    Write-Verbose "Checking results..."

    if (-not $results -or $results.Count -eq 0) {
        Write-Host "No matching firewall log entries found for the specified filters." -ForegroundColor Yellow
        return
    }

    # Select only the most relevant fields for the table
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

    Write-Host "$($results.Count) matching entries found — showing first $($table.Count)" -ForegroundColor Green

    if ($GridView) {
        # Display results in a separate GridView window
        $table | Out-GridView -Title "Find-FirewallLogTable — $FirewallLogPath ($($table.Count) of $($results.Count) entries)"
    }
    else {
        # Display results as a colored console table

        # Column definitions : header, field name, width
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

        $header    = ""
        $separator = ""
        foreach ($col in $columns) {
            $header    += $col.H.PadRight($col.W)
            $separator += ('─' * ($col.W - 1)) + ' '
        }

        function Get-ActionColor($action) {
            switch ($action) {
                "Allowed" { return "Green" }
                "Denied"  { return "Red"   }
                "Drop"    { return "Red"   }
                default   { return "White" }
            }
        }

        function Limit-String($str, $width) {
            if ($str.Length -gt ($width - 1)) {
                return $str.Substring(0, $width - 2) + "… "
            }
            return $str.PadRight($width)
        }

        Write-Host ""
        Write-Host $header -ForegroundColor Cyan
        Write-Host $separator -ForegroundColor DarkGray

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
        # Path to the specified specified firewall log file
        [Parameter(Mandatory=$true)]
        [Alias("P")]
        [string]$FirewallLogPath,

        # Path to the specified Pi-hole log file
        [Parameter(Mandatory=$true)]
        [Alias("DNS")]
        [string]$PiholeLogPath
    )

    # This 'if' statement checks whether the specified firewall log file exists in your system or not.
    if (-not (Test-Path $FirewallLogPath)) {
        Write-Error "This firewall log file is not found : $FirewallLogPath"
        return
    }

    # This 'if' statement checks whether the specified Pi-hole log file exists in your system or not.
    if (-not (Test-Path $PiholeLogPath)) {
        Write-Error "This Pihole log file is not found : $PiholeLogPath"
        return
    }

    # This hashtable is used to map IP addresses to domains.
    $dnsTable = @{}

    # Read and parse the contents of the specified Pi-hole log file
    Get-Content $PiholeLogPath | ForEach-Object {

        $line = $_

        if ($line -match 'reply\s+(?<Domain>\S+)\s+is\s+(?<IP>\d+\.\d+\.\d+\.\d+)') {

            $ip = $Matches.IP
            $domain = $Matches.Domain

            if (-not $dnsTable.ContainsKey($ip)) {
                $dnsTable[$ip] = $domain
            }
        }

        elseif ($line -match 'cached\s+(?<Domain>\S+)\s+is\s+(?<IP>\d+\.\d+\.\d+\.\d+)') {

            $ip = $Matches.IP
            $domain = $Matches.Domain

            if (-not $dnsTable.ContainsKey($ip)) {
                $dnsTable[$ip] = $domain
            }
        }
    }

    # Read firewall log entries
    $lines = Get-Content $FirewallLogPath

    foreach ($line in $lines) {

        $prefixPattern = '^(?<Date>\S+)\s+(?<Time>\S+)\s+(?<Device>\S+)\s+\[info\]'
        $prefixMatch = [regex]::Match($line, $prefixPattern)

        $entry = [ordered]@{
            Date   = $prefixMatch.Groups['Date'].Value
            Time   = $prefixMatch.Groups['Time'].Value
            Device = $prefixMatch.Groups['Device'].Value
        }

        $kvPattern = '(?<Key>\w+)=("(?<Value>[^"]+)"|(?<Value>\S+))'
        foreach ($match in [regex]::Matches($line, $kvPattern)) {
            $entry[$match.Groups['Key'].Value] = $match.Groups['Value'].Value
        }

        $dstIP = $entry.dst_ip
        $domain = $null

        # This if statement checks if the destination IP address can resolve its domain name
        # from the specified Pi-hole log file.
        if ($dstIP -and $dnsTable.ContainsKey($dstIP)) {
            $domain = $dnsTable[$dstIP]
        }

        # Display the associated results (Destination IP address -> Domain name)
        [PSCustomObject]@{
            DestIP     = $dstIP
            Domain     = $domain
        }
    }
    
}

# Export the Get-FirewallLog, Find-FirewallLog and Resolve-FirewallDestination functions
Export-ModuleMember -Function Get-FirewallLog, Get-FirewallLogTable, Find-FirewallLog, Find-FirewallLogTable, Resolve-FirewallDestination
