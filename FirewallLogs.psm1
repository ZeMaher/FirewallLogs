# Authors : Maher Gouja and Bryan Yu

# ---------------------------- #
# Function 1 : Get-FirewallLog #
# ---------------------------- #
function Get-FirewallLog {
    param (
        # Path to the specified firewall log file
        [Parameter(Mandatory=$true)]
        [Alias("P")]
        [string]$Path,

        # When this switch is used, all parsed fields from the firewall log entries
        # will be returned instead of specified ones.
        [Alias("F")]
        [switch]$Full
    )

    # Verify that the specified log file exists in your system before attempting to read it.
    if (-not (Test-Path $Path)) {
        Write-Error "Log file not found: $Path"
        return
    }

    # Read the firewall log file line-by-line and parse each entry
    Get-Content $Path | ForEach-Object {
        $line = $_

        # Extract the fixed prefix of each log entry
        # Format : Date Time Device [info]
        $prefixPattern = '^(?<Date>\S+)\s+(?<Time>\S+)\s+(?<Device>\S+)\s+\[info\]'
        $prefixMatch = [regex]::Match($line, $prefixPattern)

        # Creation of an ordered hashtable so that properties appear
        # in order when they are converted to Powershell objects
        $entry = [ordered]@{
            Date   = $prefixMatch.Groups['Date'].Value
            Time   = $prefixMatch.Groups['Time'].Value
            Device = $prefixMatch.Groups['Device'].Value
        }

        # Extract all key=value pairs contained in the log entries
        $kvPattern = '(?<Key>\w+)=("(?<Value>[^"]+)"|(?<Value>\S+))'
        
        # Iteration through each key=value match found in each line
        foreach ($match in [regex]::Matches($line, $kvPattern)) {
            $entry[$match.Groups['Key'].Value] = $match.Groups['Value'].Value
        }

        if ($Full) {
            # Show everything
            [PSCustomObject]$entry
        }
        else {
            # Show only minimal fields
            [PSCustomObject]@{
                Date        = $entry.Date
                Time        = $entry.Time
                Device      = $entry.Device
                Action      = $entry.log_subtype
                SrcIP       = $entry.src_ip
                SrcPort     = $entry.src_port
                DstIP       = $entry.dst_ip
                DstPort     = $entry.dst_Port
                Protocol    = $entry.Protocol
            }
        }

        '--------------------------------' # spacer line
    }
}

# ----------------------------- #
# Function 2 : Find-FirewallLog #
# ----------------------------- #
function Find-FirewallLog {
    # enables -Verbose support
    [CmdletBinding()]
    param (
        # Path to the specified log file
        [Parameter(Mandatory=$true)]
        [Alias("P")]
        [string]$Path,

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
    
    if (-not (Test-Path $Path)) {
        Write-Error "Log file not found: $Path"
        return
    }

    Write-Verbose "Parsing log entries..."
    
    # Loader start
    $lines = Get-Content $Path
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

# ---------------------------------------- #
# Function 3 : Resolve-FirewallDestination #
# ---------------------------------------- #
function Resolve-FirewallDestination {
    [CmdletBinding()]
    param (
        # Path to the specified specified firewall log file
        [Parameter(Mandatory=$true)]
        [Alias("FW")]
        [string]$FirewallLogPath,

        # Path to the specified Pi-hole log file
        [Parameter(Mandatory=$true)]
        [Alias("DNS")]
        [string]$PiHoleLogPath
    )

    # This 'if' statement checks whether the specified firewall log file exists in your system or not.
    if (-not (Test-Path $FirewallLogPath)) {
        Write-Error "Firewall log file not found: $FirewallLogPath"
        return
    }

    # This 'if' statement checks whether the specified Pi-hole log file exists in your system or not.
    if (-not (Test-Path $PiHoleLogPath)) {
        Write-Error "PiHole log file not found: $PiHoleLogPath"
        return
    }

    # This hashtable is used to map IP addresses to domains.
    $dnsTable = @{}

    # Read and parse the contents of the specified Pi-hole log file
    Get-Content $PiHoleLogPath | ForEach-Object {

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
Export-ModuleMember -Function Get-FirewallLog, Find-FirewallLog, Resolve-FirewallDestination
