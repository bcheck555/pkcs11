[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$DllPath,
    [string]$SshTarget
)

$ErrorActionPreference = 'Stop'
$resolvedDll = (Resolve-Path $DllPath).Path
$sshKeygen = Get-Command ssh-keygen.exe -ErrorAction Stop

Write-Host 'RSA/ECDSA certificates with private keys (the bridge applies its smart-card provider filter):' -ForegroundColor Cyan
$eligible = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
    $_.HasPrivateKey -and $_.PublicKey.Oid.Value -in @(
        '1.2.840.113549.1.1.1',
        '1.2.840.10045.2.1'
    )
}
$eligible | Select-Object Subject, Thumbprint,
    @{Name='Algorithm'; Expression={$_.PublicKey.Oid.FriendlyName}}, NotAfter |
    Format-Table -AutoSize

$abiTest = Join-Path (Split-Path $resolvedDll -Parent) 'test-pkcs11-abi.exe'
if (Test-Path $abiTest) {
    Write-Host "`nRunning PKCS#11 ABI checks..." -ForegroundColor Cyan
    & $abiTest $resolvedDll
    if ($LASTEXITCODE -ne 0) { throw "PKCS#11 ABI tests failed with exit code $LASTEXITCODE" }
}

Write-Host "`nKeys exposed by $resolvedDll`:" -ForegroundColor Cyan
$keys = & $sshKeygen.Source -D $resolvedDll 2>&1
$exitCode = $LASTEXITCODE
$keys | ForEach-Object { Write-Host $_ }
if ($exitCode -ne 0) { throw "ssh-keygen -D failed with exit code $exitCode" }
if (-not ($keys | Where-Object { $_ -match '^(ssh-rsa|ecdsa-sha2-nistp(256|384|521))\s+' })) {
    throw 'The bridge returned no supported SSH public keys.'
}

if ($SshTarget) {
    Write-Host "`nStarting interactive SSH validation for $SshTarget..." -ForegroundColor Cyan
    & ssh.exe -vvv -I $resolvedDll $SshTarget
    if ($LASTEXITCODE -ne 0) { throw "SSH validation failed with exit code $LASTEXITCODE" }
}
