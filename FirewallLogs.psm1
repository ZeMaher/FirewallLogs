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

Export-ModuleMember -Function Get-FirewallLog