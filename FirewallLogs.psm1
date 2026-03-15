
function Get-FirewallLog {
    param (
        [Parameter(Mandatory=$true)]
        [Alias("P")]
        [string]$Path,

        [Alias("F")]
        [switch]$Full
    )

    if (-not (Test-Path $Path)) {
        Write-Error "Log file not found: $Path"
        return
    }



    Get-Content $Path | ForEach-Object {
        $line = $_

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


function Find-FirewallLog {
    [CmdletBinding()]   # enables -Verbose support
    param (
        [Parameter(Mandatory=$true)]
        [Alias("P")]
        [string]$Path,

        [Alias("Src")]
        [string]$SourceIP,

        [Alias("Dst")]
        [string]$DestinationIP,

        [Alias("Port")]
        [int]$DestinationPort,

        [Alias("U")]
        [string]$User,

        [Alias("Rule")]
        [string]$RuleName
    )

    Write-Verbose "hecking if log file exists..."
    if (-not (Test-Path $Path)) {
        Write-Error "Log file not found: $Path"
        return
    }

    Write-Verbose "Parsing log entries..."
    
    #Loader start
    $lines = Get-Content $Path
    $total = $lines.Count
    $i = 0

    $entries = foreach ($line in $lines) {
        $i++
        $percent = [math]::Round(($i / $total) * 100)
        Write-Progress -Activity "Fetching firewall logs..." -Status "Parsing entries ($i of $total)" -PercentComplete $percent

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



        [PSCustomObject]$entry
    }

    # Only apply filtering if at least one filter parameter is provided
     Write-Verbose "Applying filters..."
    $results = $entries

    #Loader end
    Write-Progress -Activity "Fetching firewall logs..." -Completed



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
        $results = $results | Where-Object { $_.user -eq $User }
    }
    if ($RuleName) {
        $results = $results | Where-Object { $_.rule -eq $RuleName }
    }
    
    $results


    Write-Verbose "Checking results..."
    if (-not $results -or $results.Count -eq 0) {
        Write-Host "No matching firewall log entries found for the specified filters." -ForegroundColor Yellow
        return
    }

    Write-Host "$($results.Count) matching firewall log entries found." -ForegroundColor Green
    
}

Export-ModuleMember -Function Get-FirewallLog, Find-FirewallLog

function Resolve-FirewallDestination {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias("FW")]
        [string]$FirewallLogPath,

        [Parameter(Mandatory=$true)]
        [Alias("DNS")]
        [string]$PiHoleLogPath
    )

    if (-not (Test-Path $FirewallLogPath)) {
        Write-Error "Firewall log file not found: $FirewallLogPath"
        return
    }

    if (-not (Test-Path $PiHoleLogPath)) {
        Write-Error "PiHole log file not found: $PiHoleLogPath"
        return
    }
    
}

Export-ModuleMember -Function Resolve-FirewallDestination
