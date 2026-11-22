# Windows Duplicate SID Authentication Workaround

[English](README.md) | 繁體中文

協助處理 Windows 更新後，重複 Machine SID 裝置之間發生的 SMB／RDP 驗證失敗。本專案包含排查步驟，以及套用、備份與還原早期 KB5065426 KIR 設定的 BAT／PowerShell 工具。

## 問題背景

Microsoft 在下列更新中加強了 Windows 身分驗證檢查：

| 日期       | 更新                    | 說明                                         |
| ---------- | ----------------------- | -------------------------------------------- |
| 2025-08-29 | [KB5064081][aug-update] | Windows 11 24H2 預覽更新，開始引入相關變更。 |
| 2025-09-09 | [KB5065426][sep-update] | 後續安全性累積更新，包含前述更新的變更。     |

[KB5070568][sid-kb] 列出的受影響系統為 Windows 11 24H2、25H2 與 Windows Server 2025。原本就具有相同 Machine SID 的裝置，安裝相關更新後，彼此的 NTLM／Kerberos 驗證可能遭到拒絕。**更新使既有的 SID 重複開始影響驗證，並未造成 SID 重複。**

## 可能出現的現象

- 開啟共用資料夾時反覆要求帳密，即使憑證有效仍無法登入。
- 遠端桌面顯示登入失敗或認證無效。
- 拒絕登入的目標電腦，在 System 紀錄中出現 **LsaSrv 6167**，訊息包含「機器識別碼有部分不相符」。這是 Microsoft 文件指出的辨識線索。[來源][sid-kb]

本專案的 SMB 案例另外出現系統錯誤 **1326**、Security **4625** 與 NTLM Operational **4022**。這些一般驗證失敗紀錄需配合 SID 比對與 6167 判讀。

## 排查與適用條件

以下將發起連線的一端稱為「客戶端」，提供共用資料夾、接受登入的一端稱為「伺服器」。以 RDP 排查時，伺服器就是遠端桌面的目標電腦。

### 1. 確認 Windows 版本

在兩台電腦各執行一次：

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
    Select-Object DisplayVersion, CurrentBuild, UBR
```

記下各自的版本與完整組建，例如 `25H2 / 26200.9457`，供後續查詢套件適用性。

### 2. 比較兩台的 Machine SID

在兩台電腦各自的 PowerShell 執行：

```powershell
Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' |
    Where-Object { $_.SID -match '^S-1-5-21-\d+-\d+-\d+-\d+$' } |
    Select-Object -First 1 `
        @{Name='Computer'; Expression={$env:COMPUTERNAME}}, Name, SID,
        @{Name='MachineSID'; Expression={$_.SID -replace '-\d+$', ''}}
```

本機帳號的 SID 由電腦 SID 前綴與帳號的 RID 組成。這段指令移除最後的 RID，讓兩台輸出可以直接比較。請比對 **MachineSID 的整串數值**，並確認 `Computer` 確實是兩台不同電腦。[SID 結構說明][imaging]

### 3. 在伺服器查看 6167

先從客戶端重試一次失敗的連線，再到伺服器以系統管理員開啟 PowerShell：

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 6167
    StartTime = (Get-Date).AddHours(-1)
} -MaxEvents 10 |
    Select-Object TimeCreated, ProviderName, Message |
    Format-List
```

確認來源為 `LsaSrv`，且事件時間對得上剛才的連線。若顯示找不到符合條件的事件，表示這一小時內沒有查到；若顯示存取被拒，則需要先處理讀取權限。

當**兩台 Machine SID 相同，且該次驗證失敗伴隨目標端的 6167**，即符合 KB5070568 描述的主要特徵，可接著確認適用的處理方案。只有 1326 或密碼提示時，應先查帳號範圍、密碼、既有 SMB 連線與登入權限。

## Microsoft 提供的處理方式

### 推薦的永久處理方式

Microsoft 建議以受支援的部署方式重建受影響裝置，使每台電腦取得唯一 SID。若使用映像部署，應在擷取來源映像**之前**執行 Sysprep。部署完成後才補跑 Sysprep，不是 Microsoft 支援的補救方式。[部署政策][imaging]

### 過渡期間的官方緩解措施

Microsoft 最初提供特殊 KIR 群組原則。依 Windows IT Pro Blog **2026-10-22 更新的說明**，目前改由 [Microsoft 商務支援][support]提供新的暫時相容性登錄設定，取代 2025 年 8 月至 2026 年 3 月期間的 KIR 原則。新方案的過渡期限為 **2027 年底**，申請時需要說明使用原因及裝置重建計畫。[官方說明][hardening]

這類緩解會放寬部分驗證防護，供裝置重建前過渡使用。本專案保留的是較早期的 KIR 登錄方式，套用前仍須確認套件是否適用於你的 Windows 組建。

## 使用本工具

工具使用 Windows 內建 PowerShell 5.1。套用與還原需要系統管理員權限，請先保留可還原的系統備份。以下流程針對早期 KIR；若已取得商務支援的新設定，請使用該支援案件提供的操作說明。

### 安裝 KIR MSI

本案例使用的套件為：

```text
Windows 11 24H2, Windows 11 25H2 and Windows Server 2025
KB5065426 250923_06201 Known Issue Rollback.msi
```

[Microsoft 網域上的 MSI 下載連結][msi]，出處為 GTS-NJ 在 Microsoft Q&A 的 [2025-12-19 回覆][kir-thread]。該回覆記載了群組原則作法與登錄值；本專案的實際使用結果記於下方「案例紀錄」。

下載後確認檔案的數位簽章有效且簽署者為 Microsoft，再安裝 MSI。MSI 會安裝原則範本；設定原則與重新開機是後續步驟。[KIR 部署說明][kir-deploy]

### 執行 BAT

本案例在失敗的 SMB 客戶端套用設定。其他部署方式請依適用套件或 Microsoft 支援的指示。

1. 完整解壓縮專案，在已安裝對應 MSI 的電腦執行 `KIR_SID_SMB_Repair.bat`。
2. 選 **1（診斷）**，查看本機的版本、SID、事件與套件偵測結果。另一台的資料仍需依前面的步驟比對。
3. 選 **2（套用）**，取得管理員權限並輸入 `APPLY`。工具接著保存原始登錄狀態、寫入設定，再執行 `gpupdate /target:computer /force`。
4. 完成後，工具會詢問是否重新開機；請先儲存工作。

選單預設繁體中文，可按 `L` 切換英文。要從命令列只執行診斷，可使用：

```powershell
.\KIR_SID_SMB_Repair.bat -Action Diagnose -Language zh-TW
```

本工具套用的內容如下，原始碼位於 [KIRSidRepair.ps1](scripts/KIRSidRepair.ps1)：

```text
機碼：HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides
名稱：1517186191
類型：REG_DWORD
數值：0
```

它直接寫入登錄值，並未編輯本機群組原則檔案，因此 `gpedit.msc` 不一定會顯示「已停用」。兩台電腦的 SID 仍會保留原值。

### 驗證連線

在客戶端選 **5（SMB 測試）**，或執行下列指令。將 `SERVER` 換成伺服器名稱，`user` 換成伺服器上的帳號：

```cmd
net use \\SERVER\IPC$ /user:SERVER\user *
```

`*` 會要求輸入密碼。請使用新的驗證連線測試，避免沿用既有 SMB 工作階段。連線成功後，再開啟實際共用資料夾，並確認伺服器在這次測試期間是否新增 6167。

若仍出現相同事件，保留組建版本、測試時間與事件內容，交由 Microsoft 支援確認適用方案。其他錯誤則依新紀錄繼續排查。

### 還原設定

選 **4（還原）**，輸入 `RESTORE`，工具會恢復套用前保存的值；原本沒有該值時，就只刪除工具建立的那一項。備份位於：

```text
%ProgramData%\DuplicateSID-KIR-Toolkit\baseline.json
```

若工具第一次執行時設定已經是 `0`，便沒有更早的原值可供還原。缺少有效的 `baseline.json` 時，工具會停止還原。若先前另用 `gpedit.msc` 設定過 KIR，請先將該原則改回「尚未設定」，避免 `gpupdate` 再次套用。還原完成後重新開機。

## 案例紀錄

| 項目        | SMB 客戶端      | SMB 伺服器              |
| ----------- | --------------- | ----------------------- |
| Windows     | Windows 11 25H2 | Windows 11 25H2         |
| 組建        | 26200.9457      | 26200.9168              |
| Machine SID | 與伺服器相同    | 與客戶端相同            |
| 排查紀錄    | SMB 回傳 1326   | 4625、4022、LsaSrv 6167 |

兩端使用 NTLMv2，另有一台筆電使用相同伺服器帳號成功登入。使用者在失敗的客戶端完成 KIR 設定後，回報 SMB 已恢復。紀錄確認了 SID 重複，未確認重複的形成原因。

此處記錄的是 Windows 11 25H2 的 SMB 測試；其他組建、Windows Server 2025 與 RDP 尚未在本專案驗證。

## 參考資料

- [KB5070568：重複 SID 導致的 Kerberos／NTLM 驗證失敗][sid-kb] — Microsoft Support，問題現象與受影響版本。
- [Hardening administrative actions: What IT pros need to know][hardening] — Microsoft Windows IT Pro Blog，驗證變更及現行處理方式。
- [Windows 映像與複製部署政策][imaging] — Microsoft Learn，SID 結構及 Sysprep 使用時機。
- [使用群組原則部署 KIR][kir-deploy] — Microsoft Learn，MSI 範本與部署流程。
- [GTS-NJ 的 KIR 回覆][kir-thread] — 社群提供的早期套件與設定出處。

## License

[MIT](LICENSE)。本專案的授權涵蓋程式與文件；Microsoft MSI 由原下載來源提供。

[aug-update]: https://support.microsoft.com/help/5064081
[sep-update]: https://support.microsoft.com/help/5065426
[sid-kb]: https://support.microsoft.com/help/5070568
[hardening]: https://techcommunity.microsoft.com/blog/windows-itpro-blog/hardening-administrative-actions-what-it-pros-need-to-know/4503956
[imaging]: https://learn.microsoft.com/en-us/troubleshoot/windows-server/setup-upgrade-and-drivers/windows-installations-disk-duplication
[kir-deploy]: https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/use-group-policy-to-deploy-known-issue-rollback
[kir-thread]: https://learn.microsoft.com/en-us/answers/questions/5643615/i-need-a-workaround-for-the-smb-issues-in-win11-en
[support]: https://support.serviceshub.microsoft.com/supportforbusiness/onboarding
[msi]: https://download.microsoft.com/download/c6c70455-59ce-4d47-b13c-56b99d0435f1/Windows%2011%2024H2%2c%20Windows%2011%2025H2%20and%20Windows%20Server%202025%20KB5065426%20250923_06201%20Known%20Issue%20Rollback.msi
