[CmdletBinding()]
param(
    [ValidateSet('All', 'x64', 'x86')]
    [string]$Architecture = 'All',
    [string]$SignThumbprint,
    [string]$TimestampUrl
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$buildRoot = Join-Path $root 'build'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'

if (-not (Test-Path $vswhere)) {
    throw 'MSVC Build Tools were not found. Install Desktop development with C++ and a Windows SDK.'
}

$installation = & $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
if (-not $installation) { throw 'No MSVC C++ toolset was found.' }
$vsDevCmd = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path $vsDevCmd)) { throw "VsDevCmd.bat not found at $vsDevCmd" }

New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null
$targets = if ($Architecture -eq 'All') { @('x64', 'x86') } else { @($Architecture) }

foreach ($target in $targets) {
    $outputDir = Join-Path $buildRoot $target
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    $outputDll = Join-Path $outputDir 'pkcs11-cng-bridge.dll'
    $outputPdb = Join-Path $outputDir 'pkcs11-cng-bridge.pdb'
    $machine = if ($target -eq 'x64') { 'X64' } else { 'X86' }

    $compilerArgs = @(
        '/nologo', '/TC', '/std:c11', '/O2', '/W3', '/WX',
        '/wd4054', '/wd4055', '/wd4191', '/MT', '/LD',
        '/DWIN32_LEAN_AND_MEAN', '/DUNICODE', '/D_UNICODE',
        "/I`"$root\include`"",
        "`"$root\src\core.c`"",
        "`"$root\src\windows_store.c`"",
        "`"$root\src\pkcs11_bridge.c`"",
        '/link', "/DEF:`"$root\src\pkcs11_bridge.def`"",
        "/OUT:`"$outputDll`"", "/PDB:`"$outputPdb`"", "/MACHINE:$machine",
        'crypt32.lib', 'ncrypt.lib', 'bcrypt.lib', 'advapi32.lib', 'winscard.lib'
    ) -join ' '

    $command = "call `"$vsDevCmd`" -no_logo -arch=$target -host_arch=x64 && cl.exe $compilerArgs"
    Write-Host "Building $target..." -ForegroundColor Cyan
    & $env:ComSpec /d /s /c $command
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $outputDll)) {
        throw "$target build failed with exit code $LASTEXITCODE"
    }

    $testExe = Join-Path $outputDir 'test-pkcs11-abi.exe'
    $testArgs = @(
        '/nologo', '/TC', '/std:c11', '/O2', '/W3', '/WX', '/wd4191', '/MT',
        "/I`"$root\include`"",
        "`"$root\tests\test_pkcs11_abi.c`"",
        "/Fe:`"$testExe`"", '/link', "/MACHINE:$machine"
    ) -join ' '
    $testCommand = "call `"$vsDevCmd`" -no_logo -arch=$target -host_arch=x64 && cl.exe $testArgs"
    & $env:ComSpec /d /s /c $testCommand
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $testExe)) {
        throw "$target ABI test build failed with exit code $LASTEXITCODE"
    }

    if ($SignThumbprint) {
        $signTool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' `
            -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
            Sort-Object FullName -Descending | Select-Object -First 1
        if (-not $signTool) { throw 'signtool.exe was not found in the Windows SDK.' }
        $signArgs = @('sign', '/sha1', $SignThumbprint, '/fd', 'SHA256')
        if ($TimestampUrl) { $signArgs += @('/tr', $TimestampUrl, '/td', 'SHA256') }
        $signArgs += $outputDll
        & $signTool.FullName @signArgs
        if ($LASTEXITCODE -ne 0) { throw "Signing $target failed." }
    }
}

Write-Host "Build complete: $buildRoot" -ForegroundColor Green
