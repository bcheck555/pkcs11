<# :
@echo off
cls
set "SCRIPT_FILE=%~f0"
wt powershell -NoProfile -ExecutionPolicy Bypass -Command "IEX (Get-Content -LiteralPath '%~f0' -Raw)"
exit /b
#>

$currentScriptPath = $env:SCRIPT_FILE
if (-not $currentScriptPath) { $currentScriptPath = $PSCommandPath }

# --- AZURE B-SERIES CREDIT PROTECTION ---
$Process = [System.Diagnostics.Process]::GetCurrentProcess()
$Process.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle



# 1. Grab the path that CMD safely captured for us
$currentScriptPath = $env:SCRIPT_FILE
$desktopPath  = [Environment]::GetFolderPath("Desktop")
$shortcutName = "Anton-Gate Workspace.lnk"
$OldshortcutName = "Launch Workspace.lnk"
$shortcutPath = Join-Path $desktopPath $shortcutName
$OldshortcutPath = Join-Path $desktopPath $OldshortcutName
if (Test-Path -Path $OldshortcutPath) { Remove-Item -Path $OldshortcutPath -Force -Recurse }

if (-not (Test-Path $shortcutPath)) {
    $wshShell = New-Object -ComObject WScript.Shell
    $shortcut = $wshShell.CreateShortcut($shortcutPath)
    
    # Securely map the path string into the shell arguments
    $shortcut.TargetPath   = "C:\Windows\System32\cmd.exe"
    $shortcut.Arguments    = "/c `"$currentScriptPath`""
    $shortcut.WindowStyle  = 7  # Minimized state flag
    $shortcut.IconLocation = "C:\Windows\System32\ddores.dll, 58" 
    $shortcut.Description  = "Anton-Gate Workspace"
    $shortcut.Save()
    
    Write-Host "Shortcut successfully generated on your Desktop!" -ForegroundColor Green
    Start-Sleep -Seconds 2
}

# --- ENVIRONMENT CONFIGURATION ---
$scriptVersion = [PSCustomObject]@{ Major = 13; Minor = 2; Build = 0; Revision = 1; Engine = "PowerShell 5.1 Hybrid B-Series"; LastUpdated = "2024-08-12" }
$windowsUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
#$pkcs11Path  = "C:\Program Files\HID Global\ActivClient\acpkcs211.dll"
$pkcs11Path  = "C:\Program Files\HID Global\ActivClient\activclient-pkcs11.dll"
$tempKeyPath = "$env:TEMP\workspace_ad_pubkey.pub"
$tempConfigPath = "$env:TEMP\workspace_ad_config"
$baseDir = Split-Path -Path $currentScriptPath -Parent
if (-not $baseDir) { $baseDir = ".\" }
$csvPath = Join-Path $baseDir "nodes.csv"

# Win32 API
$win32ApiCode = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [StructLayout(LayoutKind.Sequential)]
    public struct CONSOLE_CURSOR_INFO { public int dwSize; public bool bVisible; }
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetConsoleCursorInfo(IntPtr hConsoleOutput, out CONSOLE_CURSOR_INFO cci);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetConsoleCursorInfo(IntPtr hConsoleOutput, ref CONSOLE_CURSOR_INFO cci);
    public static void SetVisibility(bool Visible) {
        IntPtr handle = GetStdHandle(-11); CONSOLE_CURSOR_INFO cci;
        if (GetConsoleCursorInfo(handle, out cci)) { cci.bVisible = Visible; SetConsoleCursorInfo(handle, ref cci); }
    }
}
"@
if (-not ([System.Management.Automation.PSTypeName]'Win32').Type) { Add-Type -TypeDefinition $win32ApiCode }

if (-not (Test-Path $csvPath)) { Write-Host "Fatal Error: nodes.csv missing." -ForegroundColor Red; Read-Host; Exit }

# --- AD-SSH IDENTITY MODULE (SILENT) ---
$adSshKeysEnabled = $false
function Initialize-AdSshModule {
    if (-not (Get-Module -ListAvailable ActiveDirectory)) { return }
    try {
        $adUser = Get-ADUser -Identity $windowsUser -Properties altSecurityIdentities -ErrorAction SilentlyContinue
        $adSshKeys = @($adUser.altSecurityIdentities | Where-Object { $_ -like "ssh-rsa*" } | ForEach-Object { $_ -replace '^(\S+\s+\S+).*', '$1' })
        if (-not $adSshKeys) { return }
        $getBlobPart = { param([byte[]]$bytes); $len = [BitConverter]::GetBytes($bytes.Length); if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($len) }; return $len + $bytes }
        foreach ($c in (Get-ChildItem Cert:\CurrentUser\My)) {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($c)
            if ($rsa) {
                $params = $rsa.ExportParameters($false); $exp = $params.Exponent; $mod = $params.Modulus
                if ($exp[0] -ge 0x80) { $exp = [byte[]]@(0x00) + $exp }
                if ($mod[0] -ge 0x80) { $mod = [byte[]]@(0x00) + $mod }
                $sshBlob = (& $getBlobPart ([System.Text.Encoding]::ASCII.GetBytes("ssh-rsa"))) + (& $getBlobPart $exp) + (& $getBlobPart $mod)
                $pubKeyStr = "ssh-rsa $([Convert]::ToBase64String($sshBlob))"
                if ($pubKeyStr -in $adSshKeys) { 
                    $pubKeyStr | Out-File $tempKeyPath -Encoding ascii -Force
                    $cfg = @("Host *", "    IdentityFile `"$tempKeyPath`"", "    PKCS11Provider `"$pkcs11Path`"", "    IdentitiesOnly yes") -join "`r`n"
                    $cfg | Out-File $tempConfigPath -Encoding ascii -Force
                    $global:adSshKeysEnabled = $true; return 
                }
            }
        }
    } catch { }
}

function Get-NodeUserPool {
    param($nodeRow)
    $userPool = [System.Collections.Generic.List[string]]::new(); $userPool.Add($windowsUser)
    if ($nodeRow.FallbackUsers) { foreach ($u in $nodeRow.FallbackUsers.Split(',')) { if ($u.Trim()) { $userPool.Add($u.Trim()) } } }
    return $userPool
}

$nodes = Import-Csv -Path $csvPath
if ($nodes | Where-Object { $_.AuthMode -eq 'adSshKeys' }) { Initialize-AdSshModule }

# Dynamic UI
$maxNameLength = [Math]::Max(15, ($nodes | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum + 1)
[Console]::WindowWidth = 120; [Console]::WindowHeight = [Math]::Max(20, $nodes.Count + 8)

$sharedData = [hashtable]::Synchronized(@{})
foreach ($n in $nodes) {
    $sharedData[$n.Label] = [hashtable]::Synchronized(@{ Name = $n.Name; IP = $n.IP; AuthMode = $n.AuthMode; DefaultUserName = $n.DefaultUserName; UserPool = (Get-NodeUserPool $n); Status = "UNKNOWN"; ChangeTime = [DateTime]::MinValue })
}
$sharedData["Running"] = $true

# Background Pings
$pingBlock = {
    param($data)
    $ping = New-Object System.Net.NetworkInformation.Ping
    while ($data["Running"]) {
        foreach ($key in ($data.Keys | Where-Object { $_ -ne "Running" })) {
            $node = $data[$key]
            try { $res = $ping.Send($node.IP, 600); $newS = if ($res.Status -eq 'Success') { "ON" } else { "OFF" } } catch { $newS = "OFF" }
            if ($node.Status -ne "UNKNOWN" -and $node.Status -ne $newS) { $node.ChangeTime = Get-Date }
            $node.Status = $newS
            Start-Sleep -Milliseconds 50
        }
        Start-Sleep -Seconds 3
    }
}
$ps = [powershell]::Create().AddScript($pingBlock).AddArgument($sharedData); $handle = $ps.BeginInvoke()

function Write-MonitorHeader {
    param([int]$timeLeft)
    $adStatus = if ($global:adSshKeysEnabled) { "AD-SSH:READY" } else { "AD-SSH:OFF" }
    Write-Host "Anton-Gate v$($scriptVersion.Major).$($scriptVersion.Minor) | $adStatus | Azure B-Series Engine" -ForegroundColor Yellow
    if ($global:fallbackActive) {
        Write-Host "PENDING SELECTION: " -NoNewline -ForegroundColor Cyan
        Write-Host "[$timeLeft s remaining] " -NoNewline -ForegroundColor Red
        Write-Host "Press target node key to open account choice block..." -ForegroundColor White
    } else {
        Write-Host "Controls:  [Key] Quick SSH | [ `` ] Select Username | [Q] Exit" -ForegroundColor DarkGray
    }
    Write-Host ("-" * 80) -ForegroundColor DarkGray
}

$lastRedraw = [DateTime]::MinValue; $lastKeystroke = Get-Date; $lastCsvWrite = (Get-Item $csvPath).LastWriteTime

# --- MAIN CONTROLLER ---
try {
    [Console]::Clear(); [Win32]::SetVisibility($false)
    while ($true) {
        $now = Get-Date; $timeLeft = 0
        if ($global:fallbackActive) {
            $timeLeft = [Math]::Max(0, [Math]::Ceiling(($global:fallbackExpires - $now).TotalSeconds))
            if ($timeLeft -le 0) { $global:fallbackActive = $false }
        }

        # Hot-Reload
        try {
            $curWrite = (Get-Item $csvPath).LastWriteTime
            if ($curWrite -gt $lastCsvWrite) {
                $lastCsvWrite = $curWrite; $nodes = Import-Csv $csvPath
                foreach ($rn in $nodes) {
                    $uPool = Get-NodeUserPool $rn
                    if ($sharedData.ContainsKey($rn.Label)) { $sharedData[$rn.Label].Name=$rn.Name; $sharedData[$rn.Label].IP=$rn.IP; $sharedData[$rn.Label].UserPool=$uPool; $sharedData[$rn.Label].AuthMode=$rn.AuthMode }
                    else { $sharedData[$rn.Label] = [hashtable]::Synchronized(@{ Name=$rn.Name; IP=$rn.IP; AuthMode=$rn.AuthMode; DefaultUserName=$rn.DefaultUserName; UserPool=$uPool; Status="UNKNOWN"; ChangeTime=[DateTime]::MinValue }) }
                }
                Clear-Host
            }
        } catch {}

        # Throttled Render
        if (($now - $lastRedraw).TotalSeconds -ge 2.0 -or $global:fallbackActive) {
            [Console]::SetCursorPosition(0, 0); Write-MonitorHeader -timeLeft $timeLeft
            $snap = $sharedData.Clone()
            foreach ($key in ($snap.Keys | Where-Object {$_ -ne "Running"} | Sort-Object { $i=0; if ([int]::TryParse($_,[ref]$i)){$i}else{$_} })) {
                $node = $snap[$key]; $col = if($node.Status -eq "ON"){"Green"}elseif($node.Status -eq "OFF"){"Red"}else{"Yellow"}
                $chg = "Stable"; if($node.ChangeTime -ne [DateTime]::MinValue){ $diff = $now - $node.ChangeTime; $chg = "$([int]$diff.TotalSeconds)s ago" }
                Write-Host " [$key] " -ForegroundColor White -NoNewline
                Write-Host "$($node.Name.PadRight($maxNameLength))" -ForegroundColor Cyan -NoNewline
                Write-Host " $($node.IP.PadRight(15)) " -ForegroundColor Gray -NoNewline
                Write-Host "[$($node.Status)]".PadRight(9) -ForegroundColor $col -NoNewline
                Write-Host " Auth: $($node.AuthMode.PadRight(10))" -ForegroundColor DarkYellow -NoNewline
                Write-Host " $chg"
            }
            $lastRedraw = $now
        }

        if ([Console]::KeyAvailable) {
            $lastKeystroke = $now; $keyInfo = [Console]::ReadKey($true); $pressed = $keyInfo.KeyChar.ToString().ToUpper()
            if ($pressed -eq "Q" -or $keyInfo.Key -eq [ConsoleKey]::Escape) { break }
            if ($keyInfo.KeyChar -eq '`') { $global:fallbackActive = $true; $global:fallbackExpires = $now.AddSeconds(10); continue }

            if ($sharedData.ContainsKey($pressed) -and $pressed -ne "Running") {
                $node = $sharedData[$pressed]
                $sshUser = if ($node.DefaultUserName -eq "Windows") { $windowsUser } else { $node.UserPool[1] }
                $authMethod = $node.AuthMode
                $abort = $false

                if ($global:fallbackActive) {
                    $global:fallbackActive = $false; $modalExp = (Get-Date).AddSeconds(10); Clear-Host
                    while (((Get-Date) -lt $modalExp) -and -not $selectionMade) {
                        $mRemaining = [Math]::Max(0, [int]($modalExp - (Get-Date)).TotalSeconds)
                        [Console]::SetCursorPosition(0, 0)
                        Write-Host ("=" * 80) -ForegroundColor Cyan
                        Write-Host " ACCOUNT SELECTION MODAL - NODE: $($node.Name) ($($node.IP))" -ForegroundColor Yellow
                        Write-Host " Auto-Aborting in: " -NoNewline -ForegroundColor DarkGray; Write-Host "[$mRemaining s]" -ForegroundColor Red
                        Write-Host ("=" * 80) -ForegroundColor Cyan
                        Write-Host "`n  [0] " -NoNewline; Write-Host "Smartcard - Custom Username" -ForegroundColor Cyan
                        Write-Host "  [1] " -NoNewline; Write-Host "Password  - Custom Username" -ForegroundColor Cyan
                        if ($adSshKeysEnabled) { Write-Host "  [2] " -NoNewline; Write-Host "AD-SSH    - Forced Identity" -ForegroundColor Green }
                        Write-Host "  --- --------------------------------------------------------------------------" -ForegroundColor Cyan
                        for ($i=0; $i -lt $node.UserPool.Count; $i++) {
                            Write-Host "  [$($i+3)] " -NoNewline; Write-Host "Password  - Profile: $($node.UserPool[$i])" -ForegroundColor Gray
                        }
                        Write-Host "`n  [ESC/Q] Abort back to Monitor" -ForegroundColor DarkGray
                        
                        if ([Console]::KeyAvailable) {
                            $mKey = [Console]::ReadKey($true); $mPressed = $mKey.KeyChar.ToString().ToUpper()
                            if ($mKey.Key -eq [ConsoleKey]::Escape -or $mPressed -eq "Q") { $abort = $true; break }
                            
                            if ($mPressed -eq "0") { $authMethod = "smartcard"; [Win32]::SetVisibility($true); $sshUser = Read-Host "`n  Enter custom username"; break }
                            if ($mPressed -eq "1") { $authMethod = "password"; [Win32]::SetVisibility($true); $sshUser = Read-Host "`n  Enter custom username"; break }
                            if ($mPressed -eq "2" -and $adSshKeysEnabled) { $authMethod = "adSshKeys"; break }
                            
                            $idx = ([int]$mPressed) - 3
                            if ($idx -ge 0 -and $idx -lt $node.UserPool.Count) { $sshUser = $node.UserPool[$idx]; $authMethod = "password"; break }
                        }
                        Start-Sleep -Milliseconds 100
                    }
                    Clear-Host; [Win32]::SetVisibility($false)
                }

                if (-not $abort -and $sshUser) {
                    $args = @()
                    if ($authMethod -eq "adSshKeys" -and $adSshKeysEnabled) { $args += "-F", "`"$tempConfigPath`"" }
                    elseif ($authMethod -eq "smartcard" -or $authMethod -eq "adSshKeys") { $args += "-I", "`"$pkcs11Path`"" }
                    $args += "$sshUser@$($node.IP)"
                    wt -w 0 new-tab -p "Windows PowerShell" --title "$($node.Name)" ssh.exe $args
                    $lastRedraw = [DateTime]::MinValue
                }
            }
        }

        if (($now - $lastKeystroke).TotalSeconds -ge 3600) {
            Clear-Host; Write-Host "Suspended (Idle). Press any key..." -ForegroundColor Yellow
            [Console]::ReadKey($true) | Out-Null; $lastKeystroke = Get-Date; Clear-Host
        }
        Start-Sleep -Milliseconds 100
    }
} finally {
    $sharedData["Running"] = $false
    if ($handle) { $ps.EndInvoke($handle) }; $ps.Dispose()
    [Win32]::SetVisibility($true)
    foreach($f in @($tempKeyPath, $tempConfigPath)) { if(Test-Path $f){Remove-Item $f -Force -ErrorAction SilentlyContinue} }
}