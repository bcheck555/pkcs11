# Windows CNG/CAPI PKCS#11 Bridge

This project exposes smart-card keys already managed by Windows as a small
PKCS#11 2.40 module for the native Windows OpenSSH client. Private keys never
leave the Windows KSP/CSP. Windows and the installed smart-card minidriver own
PIN collection and signing.

## Scope

- Direct `ssh.exe -I` and `PKCS11Provider` use.
- Certificates from the current user's `MY` certificate store.
- Microsoft Smart Card Key Storage Provider and Microsoft Base Smart Card
  Crypto Provider certificates.
- RSA PKCS#1 signatures using SHA-1, SHA-256, SHA-384, or SHA-512.
- ECDSA signatures using NIST P-256, P-384, or P-521.

The DLL does not implement an SSH agent, certificate enrollment, raw smart-card
APDUs, or server-side X.509 validation. Red Hat must already authorize the SSH
public key produced from the card certificate.

## Build on Windows

Use a separate Windows build host with MSVC Build Tools and a Windows SDK. The
client machines do not need compilers or Visual Studio.

```powershell
.\Build-Bridge.ps1
```

Outputs:

- `build\x64\pkcs11-cng-bridge.dll`
- `build\x86\pkcs11-cng-bridge.dll`

To Authenticode-sign both outputs with an existing current-user code-signing
certificate:

```powershell
.\Build-Bridge.ps1 -SignThumbprint 'CERTIFICATE_THUMBPRINT'
```

Add `-TimestampUrl` when the build host can reach the organization's approved
RFC 3161 timestamp service.

## Cross-build on Linux

Install MinGW-w64, then run:

```sh
make windows
```

The MSVC build is authoritative. The MinGW build provides reproducibility and
early ABI/compiler validation; validate its DLLs on the same Windows test
matrix before deployment.

## Validate on Windows

Run the smoke test in the interactive user's session with a card inserted:

```powershell
.\Test-Bridge.ps1 -DllPath .\build\x64\pkcs11-cng-bridge.dll
```

Optionally test a real connection and native PIN prompt:

```powershell
.\Test-Bridge.ps1 -DllPath .\build\x64\pkcs11-cng-bridge.dll `
    -SshTarget 'user@redhat-host'
```

Direct commands:

```powershell
ssh-keygen.exe -D .\pkcs11-cng-bridge.dll
ssh.exe -vvv -I .\pkcs11-cng-bridge.dll user@redhat-host
```

After hardware validation, update `anton-gate13.2.bat` so `$pkcs11Path` points
to the deployed x64 DLL. No registration or service installation is required.

## Security Notes

- The module never requests, stores, logs, or caches a PIN.
- `C_Login` is unsupported. The PKCS#11 token does not advertise
  `CKF_LOGIN_REQUIRED`, so `NCryptSignHash` or `CryptSignHash` triggers the
  Windows/minidriver PIN workflow during signing.
- Certificate thumbprints are used as stable PKCS#11 `CKA_ID` values.
- Enumeration exposes only certificates bound to the two Windows smart-card
  providers listed above. Software and TPM keys are excluded.
- SHA-1 signing exists only for compatibility with `ssh-rsa`. Prefer
  `rsa-sha2-256`, `rsa-sha2-512`, or ECDSA on the Red Hat server.
