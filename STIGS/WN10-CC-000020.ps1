<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Steven Arterbery
    LinkedIn        : linkedin.com/in/steven-arterbery/
    GitHub          : github.com/StevenArter
    Date Created    : 2025-04-05
    Last Modified   : 2025-04-05
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000020

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-CC-000020).ps1 
#>

# Tcpip6 Parameters
$basePath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"

# Set top-level parameters
New-Item -Path $basePath -Force | Out-Null
Set-ItemProperty -Path $basePath -Name "Dhcpv6DUID" -Value ([byte[]](0x00,0x01,0x00,0x01,0x2f,0x76,0xd2,0x23,0x7c,0x1e,0x52,0x96,0xb8,0x37))
Set-ItemProperty -Path $basePath -Name "DisableIpSourceRouting" -Value 2 -Type DWord

# Interfaces subkeys
$interfacesPath = "$basePath\Interfaces"
New-Item -Path $interfacesPath -Force | Out-Null

$interfaceIDs = @(
    "{07374750-e68b-490e-9330-9fd785cd71b6}",
    "{1dfc0dfb-c1ba-454e-80c7-7bf68e9ca4fb}",
    "{2ee2c70c-a092-4d88-a654-98c8d7645cd5}",
    "{68e0f7bb-4b8b-4f66-8dd4-b754f5c91228}",
    "{93123211-9629-4e04-82f0-ea2e4f221468}"
)

foreach ($id in $interfaceIDs) {
    $path = "$interfacesPath\$id"
    New-Item -Path $path -Force | Out-Null
    Set-ItemProperty -Path $path -Name "EnableDHCP" -Value 1 -Type DWord
}

# Add extra properties to the second interface
$specialPath = "$interfacesPath\{1dfc0dfb-c1ba-454e-80c7-7bf68e9ca4fb}"
Set-ItemProperty -Path $specialPath -Name "Dhcpv6Iaid" -Value 0x067c1e52 -Type DWord
Set-ItemProperty -Path $specialPath -Name "Dhcpv6State" -Value 1 -Type DWord

# Winsock parameters
$winsockPath = "$basePath\Winsock"
New-Item -Path $winsockPath -Force | Out-Null
Set-ItemProperty -Path $winsockPath -Name "UseDelayedAcceptance" -Value 0 -Type DWord
Set-ItemProperty -Path $winsockPath -Name "MaxSockAddrLength" -Value 0x1c -Type DWord
Set-ItemProperty -Path $winsockPath -Name "MinSockAddrLength" -Value 0x1c -Type DWord
Set-ItemProperty -Path $winsockPath -Name "OfflineCapable" -Value 1 -Type DWord

# Binary/Expandable properties
Set-ItemProperty -Path $winsockPath -Name "HelperDllName" -Value ([System.Text.Encoding]::Unicode.GetBytes("%SystemRoot%\System32\wship6.dll" + "`0")) -Type ExpandString
Set-ItemProperty -Path $winsockPath -Name "ProviderGUID" -Value ([byte[]](0xc0,0xb0,0xea,0xf9,0xd4,0x26,0xd0,0x11,0xbb,0xbf,0x00,0xaa,0x00,0x6c,0x34,0xe4))
Set-ItemProperty -Path $winsockPath -Name "Mapping" -Value ([byte[]](0x08,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x17,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
  0x06,0x00,0x00,0x00,0x17,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x17,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x17,0x00,0x00,0x00,
  0x02,0x00,0x00,0x00,0x11,0x00,0x00,0x00,0x17,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x17,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x00,0x00,0x00,
  0x17,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0xff,0x00,0x00,0x00,0x17,0x00,0x00,0x00,
  0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

# Winsock entries 0, 1, 2
$winsockEntries = @(
    @{
        Index = 0
        Version = 2
        AddressFamily = 0x17
        MaxSockAddrLength = 0x1c
        MinSockAddrLength = 0x1c
        SocketType = 1
        Protocol = 6
        ProtocolMaxOffset = 0
        ByteOrder = 0
        MessageSize = 0
        szProtocol = "%SystemRoot%\System32\mswsock.dll,-60200"
        ProviderFlags = 8
        ServiceFlags = 0x20066
    },
    @{
        Index = 1
        Version = 2
        AddressFamily = 0x17
        MaxSockAddrLength = 0x1c
        MinSockAddrLength = 0x1c
        SocketType = 2
        Protocol = 0x11
        ProtocolMaxOffset = 0
        ByteOrder = 0
        MessageSize = 0xfff7
        szProtocol = "%SystemRoot%\System32\mswsock.dll,-60201"
        ProviderFlags = 8
        ServiceFlags = 0x20609
    },
    @{
        Index = 2
        Version = 2
        AddressFamily = 0x17
        MaxSockAddrLength = 0x1c
        MinSockAddrLength = 0x1c
        SocketType = 3
        Protocol = 0
        ProtocolMaxOffset = 0xff
        ByteOrder = 0
        MessageSize = 0x8000
        szProtocol = "%SystemRoot%\System32\mswsock.dll,-60202"
        ProviderFlags = 0x0c
        ServiceFlags = 0x20609
    }
)

foreach ($entry in $winsockEntries) {
    $subKey = "$winsockPath\$($entry.Index)"
    New-Item -Path $subKey -Force | Out-Null

    foreach ($key in $entry.Keys) {
        if ($key -eq "szProtocol") {
            $val = [System.Text.Encoding]::Unicode.GetBytes($entry[$key] + "`0")
            Set-ItemProperty -Path $subKey -Name $key -Value $val -Type ExpandString
        } elseif ($key -ne "Index") {
            Set-ItemProperty -Path $subKey -Name $key -Value $entry[$key] -Type DWord
        }
    }
}
