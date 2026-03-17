# Install-PkcsServer

PowerShell script to prepare a Windows server for the installation of the Microsoft Intune Certificate Connector for PKCS certificate deployment.

## Overview

Before installing the Intune Certificate Connector, the target server requires several configuration changes. This script automates all required preparation tasks, ensuring a consistent and repeatable setup process.

## What It Does

The script performs the following tasks:

1. **Disables IE Enhanced Security Configuration** - Required for the Intune Certificate Connector installer to run successfully.
2. **Adds the service account to the local Administrators group** - Checks if the specified PKCS service account is already a member and adds it if not.
3. **Enables the SID security extension on PKCS-issued certificates** - Updates the registry at `HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\PFXCertificateConnector` to set `EnableSidSecurityExtension = 1`, which is required for proper certificate management in Intune.
4. **Grants "Log on as a service" right** - Uses the LSA API (`LsaAddAccountRights`) to assign `SeServiceLogonRight` to the service account, which is required for the certificate connector service to function.

## Requirements

- Windows Server
- PowerShell 5.1 or later
- **Must be run as Administrator**
- The PKCS service account must already exist in Active Directory

## Parameters

| Parameter | Required | Description |
|---|---|---|
| `ServiceAccount` | Yes | The domain service account for PKCS certificate deployment. Must be in `domain\username` format. |

## Installation

### PowerShell Gallery

The script can be installed directly from the [PowerShell Gallery](https://www.powershellgallery.com/packages/Install-PkcsServer):

```powershell
Install-Script -Name Install-PkcsServer
```

> **Note:** You may be prompted to install or update the `NuGet` provider and to trust the `PSGallery` repository the first time you run this command.

Once installed, the script can be run directly without specifying a path:

```powershell
Install-PkcsServer.ps1 -ServiceAccount 'contoso\svc-pkcs'
```

### Manual Installation

Alternatively, download the script directly from this repository and run it from its saved location:

```powershell
.\Install-PkcsServer.ps1 -ServiceAccount 'contoso\svc-pkcs'
```

## Usage

```powershell
Install-PkcsServer.ps1 -ServiceAccount 'contoso\svc-pkcs'
```

After the script completes, **log off and log back on** before installing the Intune Certificate Connector.

## Notes

- Version: 1.1
- Author: Richard Hicks, [Richard M. Hicks Consulting, Inc.](https://www.richardhicks.com/)
- The script is digitally signed with a DigiCert code signing certificate.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.
