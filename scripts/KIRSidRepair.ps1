#requires -Version 5.1
<#
.SYNOPSIS
  Diagnostic-first helper for the legacy KB5065426 KIR registry override.
.DESCRIPTION
  Community-observed compatibility workaround only. NOT an official Microsoft
  supported replacement for the support-only workaround introduced in 2026.
  It does not repair duplicate SIDs or change NTLM/SMB/NLA security policies.
#>
[CmdletBinding()]
param(
    [ValidateSet('zh-TW','en')][string]$Language = 'zh-TW',
    [ValidateSet('Menu','Status','Diagnose','Apply','Rollback','TestSMB','Events','Export','CompareSID')][string]$Action = 'Menu',
    [string]$Target = '',
    [string]$Account = '',
    [switch]$AcceptRisk
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'KIRSidCore.psm1') -Force

$Script:Version = '1.0.0'
$Script:SelfPath = $PSCommandPath
$Script:RegSubKey = 'SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides'
$Script:RegPSPath = 'HKLM:\' + $Script:RegSubKey
$Script:RegNativePath = 'HKLM\' + $Script:RegSubKey
$Script:ValueName = '1517186191'
$Script:StateRoot = Join-Path $env:ProgramData 'DuplicateSID-KIR-Toolkit'
$Script:BackupFile = Join-Path $Script:StateRoot 'baseline.json'
$Script:LogFile = Join-Path $Script:StateRoot 'actions.log'
$Script:LockFile = Join-Path $Script:StateRoot 'mutation.lock'

$Script:Messages = @{
    'en' = @{
        title = 'Duplicate SID / Legacy KIR SMB toolkit'
        subtitle = 'Diagnostic-first | Registry workaround only | No SID modification'
        warning = 'SECURITY WARNING: This legacy rollback weakens Windows authentication hardening.'
        obsolete = 'Microsoft superseded the older KIR policy in 2026. Contact Microsoft Support for current guidance.'
        menu = '1 Diagnose   2 Apply (one-click)   3 Status   4 Roll back   5 Test SMB   6 Event 6167   7 Export report   8 Compare SID   9 Records   L Language   0 Exit'
        choice = 'Choose an option'
        press = 'Press Enter to continue'
        admin = 'Administrator privileges are required. Requesting UAC elevation...'
        cancel = 'Cancelled. No changes made.'
        riskPrompt = 'Type APPLY to accept the security risk and continue'
        restorePrompt = 'Type RESTORE to restore the original registry state'
        msiMissing = 'Matching KB5065426_20250923_06201 KIR policy template not detected. Install the MSI first.'
        unsupported = 'This Windows build is not in the allowed legacy KIR version family.'
        backup = 'Baseline saved (do not delete this file)'
        existing = 'Override is already 0. No changes made. Original value cannot be inferred without a baseline.'
        applied = 'Override written and verified. Reboot required to test its effect.'
        rollback = 'Original registry state restored and verified.'
        reboot = 'Schedule a restart in 60 seconds? [y/N] (cancel with shutdown /a)'
        rebootPending = 'Restart scheduled. Save your work. Run shutdown /a to cancel.'
        noBaseline = 'No valid baseline found. Refusing to guess the previous value.'
        changed = 'Registry value differs from the tool-managed value. Refusing to overwrite external changes.'
        noEvents = 'No local Event 6167 found. Check the AUTHENTICATION TARGET computer as well.'
        target = 'SMB server IP or DNS name (example: 192.168.50.20)'
        account = 'Server account (example: FILE-SERVER\user)'
        smbAsk = 'Test credentials with net use? [y/N] (password is prompted securely by Windows)'
        disconnect = 'Disconnect the newly created IPC$ test connection? [Y/n]'
        export = 'Diagnostic report created (review for sensitive machine names/SIDs before sharing)'
        peerSid = 'Paste the other computer Machine SID (S-1-5-21-...)'
        sameSid = 'DUPLICATE Machine SID detected. Confirm Event 6167 on the target before using a workaround.'
        diffSid = 'Machine SIDs differ. This specific duplicate-SID cause is less likely.'
        noAdmin = 'Run the BAT as Administrator if UAC elevation is unavailable.'
    }
    'zh-TW' = @{
        title = 'Windows 重複 SID／舊版 KIR SMB 驗證工具'
        subtitle = '先診斷、後修復｜僅修改指定登錄值｜不會變更 SID'
        warning = '安全性警告：此舊版相容性回復會降低 Windows 身分驗證防護。'
        obsolete = 'Microsoft 已在 2026 年以支援管道的新方案取代早期 KIR，請優先諮詢官方支援。'
        menu = '1 診斷   2 一鍵套用   3 檢查狀態   4 還原   5 SMB 測試   6 6167 事件   7 匯出報告   8 比對 SID   9 開啟紀錄   L 語言   0 離開'
        choice = '請選擇功能'
        press = '按 Enter 繼續'
        admin = '需要系統管理員權限，正在要求 UAC 提權...'
        cancel = '已取消，未進行變更。'
        riskPrompt = '確認理解安全風險後，輸入 APPLY 才會繼續'
        restorePrompt = '輸入 RESTORE 才會還原原始登錄設定'
        msiMissing = '未偵測到 KB5065426_20250923_06201 KIR 原則範本，請先安裝 MSI。'
        unsupported = '目前 Windows 版本不在此舊版 KIR 的允許範圍內。'
        backup = '已保存原始狀態，請勿刪除備份檔'
        existing = '登錄值已經是 0，未做變更；沒有先前備份時無法推斷原始值。'
        applied = '已寫入並驗證登錄值，必須重新啟動才能測試效果。'
        rollback = '已恢復並驗證原始登錄狀態。'
        reboot = '是否排程 60 秒後重新啟動？[y/N]（可用 shutdown /a 取消）'
        rebootPending = '已排程重新啟動，請儲存工作；可用 shutdown /a 取消。'
        noBaseline = '沒有有效的原始備份，拒絕猜測原本的值。'
        changed = '目前登錄值與工具管理的值不同，為避免覆蓋其他修改，已停止。'
        noEvents = '本機未找到 6167 事件；也請檢查負責驗證的伺服器。'
        target = 'SMB 伺服器 IP 或 DNS 名稱（例：192.168.50.20）'
        account = '伺服器帳號（例：FILE-SERVER\user）'
        smbAsk = '是否使用 net use 測試驗證？[y/N]（由 Windows 提示輸入密碼）'
        disconnect = '是否中斷這次新建立的 IPC$ 測試連線？[Y/n]'
        export = '診斷報告已產生（分享前請遮蔽電腦名稱、SID 等資訊）'
        peerSid = '貼上另一台電腦的 Machine SID（S-1-5-21-...）'
        sameSid = '兩台 Machine SID 相同。使用緩解措施前請確認目標電腦有事件 6167。'
        diffSid = '兩台 Machine SID 不同，重複 SID 不是目前最可能的原因。'
        noAdmin = '如果無法取得 UAC 權限，請右鍵以系統管理員身分執行 BAT。'
    }
}

function T([string]$Key) {
    $entry = $Script:Messages[$Language][$Key]
    if ($null -eq $entry) { return $Key }
    return [string]$entry
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-Elevation([string]$NextAction) {
    Write-Host (T 'admin') -ForegroundColor Yellow
    $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $argLine = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "' + $Script:SelfPath + '" -Language ' + $Language + ' -Action ' + $NextAction
    try { Start-Process -FilePath $psExe -ArgumentList $argLine -Verb RunAs | Out-Null }
    catch { Write-Warning (T 'noAdmin'); throw }
}

function Initialize-State {
    if (-not (Test-Path -LiteralPath $Script:StateRoot)) {
        New-Item -Path $Script:StateRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
}

function Write-Audit([string]$Message) {
    Initialize-State
    $line = ('{0} | {1} | {2}' -f [DateTime]::UtcNow.ToString('o'), $env:COMPUTERNAME, $Message)
    try { Add-Content -LiteralPath $Script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop }
    catch { Write-Warning ('Unable to write audit log: ' + $_.Exception.Message) }
}

function Get-LocalMachineSid {
    $users = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
    $localUser = $users | Where-Object { $_.SID -match '^S-1-5-21-\d+-\d+-\d+-500$' } | Select-Object -First 1
    if ($null -eq $localUser) {
        $localUser = $users | Where-Object { $_.SID -match '^S-1-5-21-\d+-\d+-\d+-\d+$' } | Select-Object -First 1
    }
    if ($null -eq $localUser) { throw 'Unable to read local machine SID.' }
    return (Get-KIRMachineSidFromUserSid -Sid $localUser.SID)
}

function Get-Platform {
    $os = Get-CimInstance Win32_OperatingSystem
    $versionInfo = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [int]$os.BuildNumber
    $assessment = Get-KIRPlatformAssessment -DisplayVersion ([string]$versionInfo.DisplayVersion) -Build $build -ProductType ([int]$os.ProductType)
    [pscustomobject]@{
        Caption = $os.Caption
        DisplayVersion = [string]$versionInfo.DisplayVersion
        Build = $build
        UBR = [int]$versionInfo.UBR
        ProductType = [int]$os.ProductType
        Supported = $assessment.Supported
    }
}

function Get-InstalledTemplate {
    $policyDir = Join-Path $env:WINDIR 'PolicyDefinitions'
    $files = @()
    if (Test-Path -LiteralPath $policyDir) {
        $files = @(Get-ChildItem -LiteralPath $policyDir -File -Filter '*5065426*.admx' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '5065426' })
    }
    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $installed = @()
    foreach ($root in $uninstallRoots) {
        if (Test-Path -LiteralPath $root) {
            $installed += @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue |
                ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue } |
                Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -match 'KB5065426' -and $_.DisplayName -match 'Known Issue Rollback' })
        }
    }
    [pscustomobject]@{
        Found = ($files.Count -gt 0 -or $installed.Count -gt 0)
        PolicyFiles = @($files | ForEach-Object { $_.FullName })
        InstalledNames = @($installed | ForEach-Object { $_.DisplayName })
    }
}

function Get-Snapshot {
    return (Get-KIRRegistrySnapshot -SubKey $Script:RegSubKey -ValueName $Script:ValueName)
}

function Ensure-OverrideRegistryPath {
    # New-Item on the full path does not reliably create every missing parent.
    $paths = @(
        'HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft',
        'HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement',
        $Script:RegPSPath
    )
    foreach ($path in $paths) {
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -Path $path -Force -ErrorAction Stop | Out-Null
        }
    }
}

function Show-Status {
    $os = Get-Platform
    $template = Get-InstalledTemplate
    $snapshot = Get-Snapshot
    $sid = Get-LocalMachineSid
    Write-Host "`n=== $(T 'title') v$($Script:Version) ===" -ForegroundColor Cyan
    Write-Host ('Computer : {0}' -f $env:COMPUTERNAME)
    Write-Host ('Windows  : {0} / {1} / {2}.{3}' -f $os.Caption, $os.DisplayVersion, $os.Build, $os.UBR)
    Write-Host ('MachineSID: {0}' -f $sid)
    Write-Host ('Platform allowed: {0}' -f $os.Supported)
    Write-Host ('KIR MSI/template detected: {0}' -f $template.Found)
    if ($template.PolicyFiles.Count -gt 0) { Write-Host ('ADMX: ' + ($template.PolicyFiles -join ', ')) }
    if ($snapshot.Exists) {
        Write-Host ('Override {0}: {1} ({2})' -f $Script:ValueName, $snapshot.Value, $snapshot.Kind)
    }
    else { Write-Host ('Override {0}: ABSENT' -f $Script:ValueName) }
    Write-Host ('Baseline file: {0} ({1})' -f $Script:BackupFile, (Test-Path -LiteralPath $Script:BackupFile))
    Write-Host (T 'obsolete') -ForegroundColor Yellow
    Write-Host ''
}

function Get-Recent6167 {
    try {
        return @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 6167; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 15 -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { return @() }
        if ($_.Exception.Message -match 'No events were found') { return @() }
        Write-Warning $_.Exception.Message
        return @()
    }
}

function Show-Events {
    $events = @(Get-Recent6167)
    if ($events.Count -eq 0) { Write-Host (T 'noEvents') -ForegroundColor Yellow; return }
    $events | Select-Object TimeCreated,ProviderName,Id,Message | Format-List | Out-Host
}

function Show-Diagnosis {
    Show-Status
    $events = @(Get-Recent6167)
    Write-Host ('Local LsaSrv 6167 events in 7 days: {0}' -f $events.Count)
    if ($events.Count -gt 0) { $events | Select-Object -First 3 TimeCreated,ProviderName,Id | Format-Table | Out-Host }
    Write-Host 'KB5070568: https://support.microsoft.com/help/5070568'
    Write-Host 'Microsoft 2026 guidance: https://techcommunity.microsoft.com/blog/windows-itpro-blog/hardening-administrative-actions-what-it-pros-need-to-know/4503956'
}

function Enter-MutationLock {
    Initialize-State
    try {
        return [System.IO.File]::Open($Script:LockFile,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None)
    }
    catch { throw 'Another instance is changing KIR state, or the lock file cannot be opened.' }
}

function Read-Baseline {
    if (-not (Test-Path -LiteralPath $Script:BackupFile)) { return $null }
    $record = Get-Content -LiteralPath $Script:BackupFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $sid = Get-LocalMachineSid
    $valid = Test-KIRBackupRecord -Record $record -ComputerName $env:COMPUTERNAME -MachineSid $sid -RegistryPath $Script:RegSubKey -ValueName $Script:ValueName
    if (-not $valid) { throw 'Backup metadata is invalid or belongs to another machine. Refusing to proceed.' }
    return $record
}

function Write-Baseline($Snapshot) {
    Initialize-State
    if (Test-Path -LiteralPath $Script:BackupFile) { throw 'Baseline already exists; refusing to overwrite it.' }
    $record = New-KIRBackupRecord -Snapshot $Snapshot -ComputerName $env:COMPUTERNAME -MachineSid (Get-LocalMachineSid) -RegistryPath $Script:RegSubKey -ValueName $Script:ValueName
    $json = $record | ConvertTo-Json -Depth 5
    $temp = $Script:BackupFile + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [System.IO.File]::WriteAllText($temp, $json, ([System.Text.UTF8Encoding]::new($false)))
        [System.IO.File]::Move($temp, $Script:BackupFile)
    }
    finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
    # An optional .reg export is useful for human inspection, but the JSON is authoritative.
    if ($Snapshot.KeyExists) {
        $export = Join-Path $Script:StateRoot ('registry-before-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.reg')
        try {
            & reg.exe export $Script:RegNativePath $export /y *> $null
            if ($LASTEXITCODE -ne 0) { Write-Warning 'Optional .reg export failed. Atomic JSON baseline is intact.' }
        }
        catch { Write-Warning 'Optional .reg export failed. Atomic JSON baseline is intact.' }
    }
    Write-Host (T 'backup') -ForegroundColor Green
    Write-Host $Script:BackupFile
}

function Invoke-GroupPolicyRefresh {
    Write-Host 'gpupdate /target:computer /force ...'
    & gpupdate.exe /target:computer /force
    if ($LASTEXITCODE -ne 0) {
        Write-Warning ('gpupdate returned exit code ' + $LASTEXITCODE + '. Registry may still be changed; check policy and reboot later.')
        return $false
    }
    return $true
}

function Offer-Restart {
    $answer = Read-Host (T 'reboot')
    if ($answer -match '^(y|yes)$') {
        & shutdown.exe /r /t 60 /c 'Legacy KIR setting changed by administrator'
        if ($LASTEXITCODE -eq 0) { Write-Host (T 'rebootPending') -ForegroundColor Yellow }
        else { Write-Warning ('shutdown returned ' + $LASTEXITCODE) }
    }
}

function Assert-ApplyPrerequisites {
    $os = Get-Platform
    if (-not $os.Supported) { throw (T 'unsupported') }
    if ((Get-Date) -ge [datetime]'2028-01-01') {
        throw 'Microsoft documented an end-of-2027 lifetime for the transitional compatibility workaround. This tool will not apply it after that date.'
    }
    $template = Get-InstalledTemplate
    if (-not $template.Found) { throw (T 'msiMissing') }
}

function Invoke-Apply {
    if (-not (Test-Admin)) { Request-Elevation -NextAction 'Apply'; return }
    Assert-ApplyPrerequisites
    $snapshot = Get-Snapshot
    if ($snapshot.Exists -and $snapshot.Kind -ne 'DWord') { throw 'Registry value exists with a non-DWORD type. Refusing to replace it.' }
    if ($snapshot.Exists -and [int64]$snapshot.Value -eq 0) {
        Write-Host (T 'existing') -ForegroundColor Yellow
        return
    }

    Write-Host (T 'warning') -ForegroundColor Red
    Write-Host (T 'obsolete') -ForegroundColor Yellow
    Write-Host 'Reference: https://support.microsoft.com/help/5070568'
    if (-not $AcceptRisk) {
        $answer = Read-Host (T 'riskPrompt')
        if ($answer -cne 'APPLY') { Write-Host (T 'cancel'); return }
    }

    $lock = Enter-MutationLock
    try {
        $snapshot = Get-Snapshot
        if ($snapshot.Exists -and $snapshot.Kind -ne 'DWord') { throw 'Registry value is not a DWORD.' }
        if ($snapshot.Exists -and [int64]$snapshot.Value -eq 0) { Write-Host (T 'existing'); return }

        $baseline = Read-Baseline
        if ($null -eq $baseline) {
            Write-Baseline -Snapshot $snapshot
        }
        else {
            # A previous attempt may have failed before writing. Only retry if the
            # current value still equals the captured original state.
            if ([bool]$baseline.ValueExisted -ne [bool]$snapshot.Exists) { throw (T 'changed') }
            if ($snapshot.Exists -and [int64]$snapshot.Value -ne [int64]$baseline.OriginalValue) { throw (T 'changed') }
        }

        Ensure-OverrideRegistryPath
        New-ItemProperty -Path $Script:RegPSPath -Name $Script:ValueName -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
        $after = Get-Snapshot
        if (-not $after.Exists -or $after.Kind -ne 'DWord' -or [int64]$after.Value -ne 0) { throw 'Registry write verification failed.' }
        Write-Audit 'APPLY: 1517186191=0; original baseline preserved'
        $gpOk = Invoke-GroupPolicyRefresh
        $afterGp = Get-Snapshot
        if (-not $afterGp.Exists -or [int64]$afterGp.Value -ne 0) {
            Write-Warning 'A policy or other process replaced the registry value after gpupdate. Check Local Group Policy and domain policies.'
            return
        }
        if (-not $gpOk) { Write-Warning 'gpupdate failed. Do not assume the workaround is active.' }
        Write-Host (T 'applied') -ForegroundColor Green
    }
    finally { $lock.Dispose() }
    Offer-Restart
}

function Assert-RollbackSnapshot($Snapshot, $Baseline) {
    if ($Snapshot.Exists) {
        if ($Snapshot.Kind -ne 'DWord') { throw (T 'changed') }
        if ([int64]$Snapshot.Value -ne 0) {
            if (-not [bool]$Baseline.ValueExisted -or
                [int64]$Snapshot.Value -ne [int64]$Baseline.OriginalValue) {
                throw (T 'changed')
            }
        }
    }
    elseif ([bool]$Baseline.ValueExisted) {
        throw (T 'changed')
    }
}

function Invoke-Rollback {
    if (-not (Test-Admin)) { Request-Elevation -NextAction 'Rollback'; return }
    if (-not (Test-Path -LiteralPath $Script:BackupFile)) { throw (T 'noBaseline') }
    $baseline = Read-Baseline
    if ($null -eq $baseline) { throw (T 'noBaseline') }
    $snapshot = Get-Snapshot
    Assert-RollbackSnapshot -Snapshot $snapshot -Baseline $baseline

    $answer = Read-Host (T 'restorePrompt')
    if ($answer -cne 'RESTORE') { Write-Host (T 'cancel'); return }
    $lock = Enter-MutationLock
    try {
        $baseline = Read-Baseline
        $snapshot = Get-Snapshot
        Assert-RollbackSnapshot -Snapshot $snapshot -Baseline $baseline
        if ([bool]$baseline.ValueExisted) {
            Ensure-OverrideRegistryPath
            New-ItemProperty -Path $Script:RegPSPath -Name $Script:ValueName -PropertyType DWord -Value ([int]$baseline.OriginalValue) -Force | Out-Null
        }
        elseif ($snapshot.Exists) {
            Remove-ItemProperty -Path $Script:RegPSPath -Name $Script:ValueName -ErrorAction Stop
        }
        $after = Get-Snapshot
        if ([bool]$after.Exists -ne [bool]$baseline.ValueExisted) { throw 'Rollback verification failed (existence mismatch).' }
        if ($after.Exists -and [int64]$after.Value -ne [int64]$baseline.OriginalValue) { throw 'Rollback verification failed (value mismatch).' }
        Write-Audit ('ROLLBACK: restored original value; existed=' + $baseline.ValueExisted)
        $gpOk = Invoke-GroupPolicyRefresh
        $afterGp = Get-Snapshot
        if ([bool]$afterGp.Exists -ne [bool]$baseline.ValueExisted -or
            ($afterGp.Exists -and [int64]$afterGp.Value -ne [int64]$baseline.OriginalValue)) {
            Write-Warning 'A Group Policy re-applied the override. Set the corresponding GPO to Not Configured first.'
            return
        }
        if (-not $gpOk) {
            Write-Warning 'gpupdate failed; keeping baseline for another rollback attempt.'
            return
        }
        $history = Join-Path $Script:StateRoot 'history'
        New-Item -Path $history -ItemType Directory -Force | Out-Null
        $archive = Join-Path $history ('baseline-restored-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8) + '.json')
        Move-Item -LiteralPath $Script:BackupFile -Destination $archive -ErrorAction Stop
        Write-Host (T 'rollback') -ForegroundColor Green
        Write-Host ('Archived backup: ' + $archive)
    }
    finally { $lock.Dispose() }
    Offer-Restart
}

function Invoke-SMBTest {
    $server = $Target
    if ([string]::IsNullOrWhiteSpace($server)) { $server = Read-Host (T 'target') }
    if (-not (Test-KIRHostName -Name $server)) { throw 'Invalid server name. Use a DNS name or IPv4 address, not a UNC path.' }
    $accountName = $Account
    if ([string]::IsNullOrWhiteSpace($accountName)) { $accountName = Read-Host (T 'account') }
    if ([string]::IsNullOrWhiteSpace($accountName) -or $accountName -match '[\r\n"\x00]') { throw 'Invalid account name.' }

    Write-Host ('TCP 445: ' + $server)
    $reachable = Test-NetConnection -ComputerName $server -Port 445 -InformationLevel Quiet -WarningAction SilentlyContinue
    Write-Host ('Reachable: ' + $reachable)
    if (-not $reachable) { Write-Warning 'Port 445 is not reachable. Check firewall, routing and server service first.'; return }
    $answer = Read-Host (T 'smbAsk')
    if ($answer -notmatch '^(y|yes)$') { return }
    $unc = '\\' + $server + '\IPC$'
    Write-Host ('Authenticating to ' + $unc + ' as ' + $accountName)
    # '*' makes NET USE prompt for a password; it is never stored in arguments/logs.
    & net.exe use $unc '*' ("/user:" + $accountName) '/persistent:no'
    $code = $LASTEXITCODE
    Write-Host ('net use exit code: ' + $code)
    if ($code -eq 0) {
        $disconnect = Read-Host (T 'disconnect')
        if ($disconnect -notmatch '^(n|no)$') {
            & net.exe use $unc '/delete' '/y'
        }
    }
}

function Invoke-CompareSID {
    $mine = Get-LocalMachineSid
    Write-Host ('Local Machine SID: ' + $mine)
    $other = Read-Host (T 'peerSid')
    if ($other -notmatch '^S-1-5-21-\d+-\d+-\d+$') { throw 'Invalid Machine SID format.' }
    if ($mine -ceq $other) { Write-Host (T 'sameSid') -ForegroundColor Yellow }
    else { Write-Host (T 'diffSid') -ForegroundColor Green }
}

function Invoke-Export {
    Initialize-State
    $path = Join-Path $Script:StateRoot ('diagnostic-' + $env:COMPUTERNAME + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
    $os = Get-Platform
    $snapshot = Get-Snapshot
    $template = Get-InstalledTemplate
    $events = @(Get-Recent6167)
    $report = [System.Collections.Generic.List[string]]::new()
    $report.Add('Duplicate SID KIR Toolkit - diagnostic report')
    $report.Add('Created UTC: ' + [DateTime]::UtcNow.ToString('o'))
    $report.Add('Computer: ' + $env:COMPUTERNAME)
    $report.Add('Windows: ' + $os.Caption + ' ' + $os.DisplayVersion + ' ' + $os.Build + '.' + $os.UBR)
    $report.Add('Machine SID: ' + (Get-LocalMachineSid))
    $report.Add('Legacy KIR template detected: ' + $template.Found)
    $report.Add('Override exists: ' + $snapshot.Exists)
    $report.Add('Override kind: ' + $snapshot.Kind)
    $report.Add('Override value: ' + $snapshot.Value)
    $report.Add('Baseline exists: ' + (Test-Path -LiteralPath $Script:BackupFile))
    $report.Add('Event 6167 count (last 7 days, max 15): ' + $events.Count)
    foreach ($event in $events) {
        $report.Add(('--- {0} {1} ---' -f $event.TimeCreated, $event.ProviderName))
        $report.Add([string]$event.Message)
    }
    [System.IO.File]::WriteAllLines($path, $report.ToArray(), ([System.Text.UTF8Encoding]::new($true)))
    Write-Host (T 'export') -ForegroundColor Green
    Write-Host $path
}

function Open-Records {
    Initialize-State
    Start-Process explorer.exe -ArgumentList ('"' + $Script:StateRoot + '"')
}

function Show-Menu {
    while ($true) {
        Clear-Host
        Write-Host ('=== ' + (T 'title') + ' v' + $Script:Version + ' ===') -ForegroundColor Cyan
        Write-Host (T 'subtitle')
        Write-Host (T 'warning') -ForegroundColor Yellow
        Write-Host (T 'obsolete') -ForegroundColor Yellow
        Write-Host ''
        Write-Host (T 'menu')
        $choice = (Read-Host (T 'choice')).Trim().ToUpperInvariant()
        if ($choice -eq '0') { return }
        try {
            switch ($choice) {
                '1' { Show-Diagnosis }
                '2' { Invoke-Apply }
                '3' { Show-Status }
                '4' { Invoke-Rollback }
                '5' { Invoke-SMBTest }
                '6' { Show-Events }
                '7' { Invoke-Export }
                '8' { Invoke-CompareSID }
                '9' { Open-Records }
                'L' {
                    if ($Script:Language -eq 'zh-TW') { $Script:Language = 'en' }
                    else { $Script:Language = 'zh-TW' }
                    continue
                }
                default { Write-Host 'Unknown option.' }
            }
        }
        catch { Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red }
        [void](Read-Host (T 'press'))
    }
}

try {
    switch ($Action) {
        'Menu' { Show-Menu }
        'Status' { Show-Status }
        'Diagnose' { Show-Diagnosis }
        'Apply' { Invoke-Apply }
        'Rollback' { Invoke-Rollback }
        'TestSMB' { Invoke-SMBTest }
        'Events' { Show-Events }
        'Export' { Invoke-Export }
        'CompareSID' { Invoke-CompareSID }
    }
}
catch {
    Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
