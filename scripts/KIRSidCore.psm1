# Core, mostly side-effect-free helpers for Windows PowerShell 5.1.
Set-StrictMode -Version Latest

function Get-KIRPlatformAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DisplayVersion,
        [Parameter(Mandatory)][int]$Build,
        [Parameter(Mandatory)][int]$ProductType
    )

    $supported = $false
    if ($ProductType -eq 1) {
        $supported = (($DisplayVersion -eq '24H2' -and $Build -eq 26100) -or
                      ($DisplayVersion -eq '25H2' -and $Build -eq 26200))
    }
    elseif ($ProductType -eq 3) {
        # Windows Server 2025; product/edition should be verified separately.
        $supported = ($Build -eq 26100)
    }

    $explanation = 'Outside the explicitly tested Windows 11 24H2/25H2 or Server 2025 build family.'
    if ($supported) { $explanation = 'Matched the legacy KIR MSI version family.' }

    [pscustomobject]@{
        Supported      = [bool]$supported
        DisplayVersion = $DisplayVersion
        Build          = $Build
        ProductType    = $ProductType
        Explanation    = $explanation
    }
}

function Get-KIRMachineSidFromUserSid {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Sid)

    if ($Sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') {
        throw 'Not a local Windows account SID in the expected format.'
    }
    return ($Sid -replace '-\d+$', '')
}

function Test-KIRHostName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    # Intentionally limited to DNS names and IPv4 literals. No UNC, spaces, or shell metacharacters.
    return ($Name.Length -le 253 -and $Name -match '^[A-Za-z0-9][A-Za-z0-9._-]*$' -and
            $Name -notmatch '\.\.' -and $Name -notmatch '[\\/]')
}

function Get-KIRRegistrySnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubKey,
        [Parameter(Mandatory)][string]$ValueName
    )

    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey, $false)
    if ($null -eq $key) {
        return [pscustomobject]@{ KeyExists = $false; Exists = $false; Kind = $null; Value = $null }
    }

    try {
        $exists = (@($key.GetValueNames()) -contains $ValueName)
        if (-not $exists) {
            return [pscustomobject]@{ KeyExists = $true; Exists = $false; Kind = $null; Value = $null }
        }
        $kind = $key.GetValueKind($ValueName).ToString()
        $value = $key.GetValue($ValueName)
        return [pscustomobject]@{ KeyExists = $true; Exists = $true; Kind = $kind; Value = $value }
    }
    finally {
        $key.Close()
    }
}

function New-KIRBackupRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$MachineSid,
        [Parameter(Mandatory)][string]$RegistryPath,
        [Parameter(Mandatory)][string]$ValueName
    )

    [pscustomobject]@{
        SchemaVersion = 1
        CreatedUtc    = [DateTime]::UtcNow.ToString('o')
        ComputerName  = $ComputerName
        MachineSid    = $MachineSid
        RegistryPath  = $RegistryPath
        ValueName     = $ValueName
        KeyExisted    = [bool]$Snapshot.KeyExists
        ValueExisted  = [bool]$Snapshot.Exists
        OriginalKind  = $Snapshot.Kind
        OriginalValue = $Snapshot.Value
        AppliedValue  = 0
    }
}

function Test-KIRBackupRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$MachineSid,
        [Parameter(Mandatory)][string]$RegistryPath,
        [Parameter(Mandatory)][string]$ValueName
    )

    try {
        if ([int]$Record.SchemaVersion -ne 1) { return $false }
        if ($Record.ComputerName -cne $ComputerName) { return $false }
        if ($Record.MachineSid -cne $MachineSid) { return $false }
        if ($Record.RegistryPath -cne $RegistryPath) { return $false }
        if ($Record.ValueName -cne $ValueName) { return $false }
        if ([int]$Record.AppliedValue -ne 0) { return $false }
        if ($Record.ValueExisted -and $Record.OriginalKind -ne 'DWord') { return $false }
        if ($Record.ValueExisted -and $null -eq $Record.OriginalValue) { return $false }
        return $true
    }
    catch {
        return $false
    }
}

Export-ModuleMember -Function Get-KIRPlatformAssessment,Get-KIRMachineSidFromUserSid,Test-KIRHostName,Get-KIRRegistrySnapshot,New-KIRBackupRecord,Test-KIRBackupRecord
