# Windows Duplicate SID Authentication Workaround

English | [繁體中文](README_ZH-TW.md)

Troubleshoot SMB and RDP authentication failures between Windows machines with duplicate Machine SIDs after Windows updates. This project includes diagnostic steps and a BAT/PowerShell tool for applying, backing up, and restoring the earlier KB5065426 KIR setting.

## Background

Microsoft strengthened Windows authentication checks in the following updates:

| Date       | Update                  | Details                                                                  |
| ---------- | ----------------------- | ------------------------------------------------------------------------ |
| 2025-08-29 | [KB5064081][aug-update] | Windows 11 24H2 preview update introducing the changes.                  |
| 2025-09-09 | [KB5065426][sep-update] | Subsequent security cumulative update incorporating the earlier changes. |

[KB5070568][sid-kb] identifies Windows 11 24H2, Windows 11 25H2, and Windows Server 2025 as affected. Machines that already share a Machine SID may fail NTLM or Kerberos authentication with each other after installing the relevant updates. **The updates expose an existing identity conflict; they do not create duplicate SIDs.**

## Symptoms

- Shared folders repeatedly prompt for credentials and reject a valid account.
- Remote Desktop reports a failed logon or rejected credentials.
- The target machine records **LsaSrv Event 6167** in its System log, describing a partial mismatch in the machine ID. Microsoft identifies this event as a diagnostic indicator. [Source][sid-kb]

The SMB case recorded in this project also produced **System error 1326**, Security **4625**, and NTLM Operational **4022**. Interpret these general authentication failure records together with the SID comparison and Event 6167.

## Diagnosis

In these instructions, the **client** initiates the connection and the **server** accepts the logon and hosts the share. For RDP, the server is the remote computer you are trying to sign in to.

### 1. Record the Windows versions

Run on each computer:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
    Select-Object DisplayVersion, CurrentBuild, UBR
```

Keep each version and full build number, such as `25H2 / 26200.9457`, for checking package applicability.

### 2. Compare the Machine SIDs

Run locally in PowerShell on both computers:

```powershell
Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' |
    Where-Object { $_.SID -match '^S-1-5-21-\d+-\d+-\d+-\d+$' } |
    Select-Object -First 1 `
        @{Name='Computer'; Expression={$env:COMPUTERNAME}}, Name, SID,
        @{Name='MachineSID'; Expression={$_.SID -replace '-\d+$', ''}}
```

A local account SID consists of the computer SID prefix followed by the account's RID. The command removes that final RID. Compare the **entire MachineSID value** and check that `Computer` identifies two different machines. [SID structure][imaging]

### 3. Check the server for Event 6167

Retry the failed connection from the client, then open PowerShell as Administrator on the server:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 6167
    StartTime = (Get-Date).AddHours(-1)
} -MaxEvents 10 |
    Select-Object TimeCreated, ProviderName, Message |
    Format-List
```

Look for provider `LsaSrv` and a timestamp matching the connection attempt. A no-matching-events error means nothing was found in that one-hour window. An access-denied error requires resolving log access first.

**Matching Machine SIDs and a corresponding target-side 6167 event** match the main indicators described in KB5070568. The next step is to choose an applicable remediation. If the only evidence is error 1326 or a password prompt, first check account scope, credentials, existing SMB sessions, and logon rights.

## Microsoft's resolution

### Permanent remediation

Microsoft recommends rebuilding affected devices through a supported deployment process so that each receives a unique SID. When deploying an image, run Sysprep **before capturing the source image**. Running it afterward on an already deployed machine is not a supported way to correct the deployment. [Deployment policy][imaging]

### Temporary support option

Microsoft initially provided a special KIR Group Policy. Its Windows IT Pro Blog guidance, **updated October 22, 2026**, describes a newer temporary registry option available through [Microsoft business support][support]. It replaces the KIR policies from August 2025 through March 2026. The newer option is available through **the end of 2027**; applicants must explain the need and provide a plan to rebuild affected devices. [Official guidance][hardening]

These options relax authentication protections during the transition to rebuilt systems. This repository retains the earlier KIR registry method. Confirm that the package applies to your Windows build before using it.

## Using the tool

The tool uses Windows PowerShell 5.1. Applying or restoring the setting requires Administrator privileges; keep a restorable system backup. The steps below cover the earlier KIR. If Microsoft Support has supplied a newer setting, follow the instructions from that support case.

### Install the KIR MSI

The package used in this case was:

```text
Windows 11 24H2, Windows 11 25H2 and Windows Server 2025
KB5065426 250923_06201 Known Issue Rollback.msi
```

The [Microsoft-hosted MSI link][msi] comes from GTS-NJ's [December 19, 2025 Microsoft Q&A reply][kir-thread]. That reply records both the Group Policy method and the registry value. This project's observed result is recorded under **Case record** below.

Check that the downloaded file has a valid Microsoft digital signature, then install it. The MSI installs policy definitions; configuring the policy and restarting are separate steps. [KIR deployment][kir-deploy]

### Run the BAT

In this case, the setting was applied to the failing SMB client. For other deployments, follow the applicable package or Microsoft Support instructions.

1. Extract the entire project and run `KIR_SID_SMB_Repair.bat` on the computer with the matching MSI installed.
2. Choose **1 (Diagnose)** to inspect the local build, SID, events, and package detection. Compare the other computer using the diagnostic steps above.
3. Choose **2 (Apply)**, approve elevation, and type `APPLY`. The tool then saves the original registry state, writes the setting, and runs `gpupdate /target:computer /force`.
4. The tool will ask whether to restart. Save your work before confirming.

The menu defaults to Traditional Chinese; press `L` for English. To run only the diagnostic action from a command line:

```powershell
.\KIR_SID_SMB_Repair.bat -Action Diagnose -Language en
```

The tool writes the following setting. See [KIRSidRepair.ps1](scripts/KIRSidRepair.ps1) for the implementation.

```text
Key:   HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides
Name:  1517186191
Type:  REG_DWORD
Data:  0
```

It writes the registry directly rather than editing Local Group Policy files, so `gpedit.msc` may still show the policy as Not Configured. The machines retain their existing SIDs.

### Verify the connection

On the client, choose **5 (Test SMB)** or run the following command. Replace `SERVER` with the server's name and `user` with an account on that server:

```cmd
net use \\SERVER\IPC$ /user:SERVER\user *
```

The `*` prompts for the password. Test a fresh authentication attempt rather than reusing an existing SMB session. Once authentication succeeds, open the actual share and check whether the server recorded a new 6167 during the test.

If the same event persists, provide the build numbers, test time, and event details to Microsoft Support to confirm an applicable mitigation. Investigate any different error using the new logs.

### Restore the original setting

Choose **4 (Rollback)** and type `RESTORE`. The tool restores the saved value, or removes just the value it created if none existed before. The baseline is stored at:

```text
%ProgramData%\DuplicateSID-KIR-Toolkit\baseline.json
```

If the setting was already `0` when the tool was first used, it has no earlier value to restore. Without a valid `baseline.json`, rollback stops. If you also configured the KIR through `gpedit.msc`, first return that policy to **Not Configured** so that `gpupdate` does not reapply it. Restart after restoring the setting.

## Case record

| Item             | SMB client      | SMB server              |
| ---------------- | --------------- | ----------------------- |
| Windows          | Windows 11 25H2 | Windows 11 25H2         |
| Build            | 26200.9457      | 26200.9168              |
| Machine SID      | Same as server  | Same as client          |
| Recorded failure | SMB error 1326  | 4625, 4022, LsaSrv 6167 |

The failing connection used NTLMv2. A separate laptop successfully authenticated with the same server account. After configuring the KIR on the failing client, the user reported restored SMB access. The investigation confirmed duplicate SIDs; it did not establish how they originated.

This is a Windows 11 25H2 SMB test. Other builds, Windows Server 2025, and RDP recovery have not been verified in this project.

## References

- [KB5070568: Kerberos and NTLM authentication failures due to duplicate SIDs][sid-kb] — Microsoft Support; symptoms and affected versions.
- [Hardening administrative actions: What IT pros need to know][hardening] — Microsoft Windows IT Pro Blog; authentication changes and current remediation.
- [Windows imaging and duplication policy][imaging] — Microsoft Learn; SID structure and Sysprep requirements.
- [Deploy a KIR with Group Policy][kir-deploy] — Microsoft Learn; MSI templates and deployment steps.
- [GTS-NJ's KIR reply][kir-thread] — community provenance for the earlier package and setting.


## License

[MIT](LICENSE). The license covers this project's code and documentation. The Microsoft MSI is provided by its original download source.

[aug-update]: https://support.microsoft.com/help/5064081
[sep-update]: https://support.microsoft.com/help/5065426
[sid-kb]: https://support.microsoft.com/help/5070568
[hardening]: https://techcommunity.microsoft.com/blog/windows-itpro-blog/hardening-administrative-actions-what-it-pros-need-to-know/4503956
[imaging]: https://learn.microsoft.com/en-us/troubleshoot/windows-server/setup-upgrade-and-drivers/windows-installations-disk-duplication
[kir-deploy]: https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/use-group-policy-to-deploy-known-issue-rollback
[kir-thread]: https://learn.microsoft.com/en-us/answers/questions/5643615/i-need-a-workaround-for-the-smb-issues-in-win11-en
[support]: https://support.serviceshub.microsoft.com/supportforbusiness/onboarding
[msi]: https://download.microsoft.com/download/c6c70455-59ce-4d47-b13c-56b99d0435f1/Windows%2011%2024H2%2c%20Windows%2011%2025H2%20and%20Windows%20Server%202025%20KB5065426%20250923_06201%20Known%20Issue%20Rollback.msi
