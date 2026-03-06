<#PSScriptInfo

.VERSION 1.0

.GUID 55f351d8-b3f7-48d8-b847-49a6a7652380

.AUTHOR Richard Hicks

.COMPANYNAME Richard M. Hicks Consulting, Inc.

.COPYRIGHT Copyright (C) 2026 Richard M. Hicks Consulting, Inc. All Rights Reserved.

.LICENSE Licensed under the MIT License. See LICENSE file in the project root for full license information.

.LICENSEURI https://github.com/richardhicks/pkcs/blob/main/LICENSE

.PROJECTURI https://github.com/richardhicks/pkcs

.TAGS PKCS, Intune, Certificate, PKI, x509

#>

<#

.SYNOPSIS
    PowerShell script to prepare a server for the installation of the Microsoft Intune Certificate Connector for PKCS certificate deployment.

.DESCRIPTION
    This script performs the following tasks:

    - Disables Internet Explorer enhanced security configuration, which is required for the Intune Certificate Connector installer to run successfully.
    - Checks if the specified PKCS service account is a member of the local administrators group and adds it if necessary.
    - Updates the registry to enable the SID security extension on PKCS issued certificates, which is required for proper certificate management in Intune.
    - Grants the "Log on as a service" right to the PKCS service account, which is required for the certificate connector service to function properly.

.PARAMETER ServiceAccount
    Specifies the service account to be used for the PKCS certificate deployment.

.INPUTS
    None

.OUTPUTS
    None.

.EXAMPLE
    Install-PkcsServer.ps1 -ServiceAccount 'domain\user'

    Prepares the server for the installation of the Intune Certificate Connector using the specified service account.

.LINK
    https://www.richardhicks.com/

.NOTES
    Version:        1.0
    Creation Date:  March 5, 2026
    Last Updated:   March 5, 2026
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

[CmdletBinding()]

Param(

    [Parameter(Mandatory)]
    [ValidatePattern('^[^\\]+\\[^\\]+$')]
    [string]$ServiceAccount

)

# Requirements
#Requires -RunAsAdministrator

# Disable IE enhanced security - required to install the Intune Certificate Connector
Write-Verbose 'Disabling IE enhanced security...'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Type DWORD -Value '0'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Type DWORD -Value '0'

# Check local administrators group for PKCS service account
Write-Verbose "Checking if PKCS service account $ServiceAccount is a member of the local administrators group..."
$PKCS = Get-LocalGroupMember -Group Administrators -Member $ServiceAccount -ErrorAction SilentlyContinue

# Add PKCS service account to local administrators group if required
If ($Null -eq $PKCS) {

    Write-Verbose "Adding PKCS service account $ServiceAccount to local administrators group..."
    Add-LocalGroupMember -Group Administrators -Member $ServiceAccount

}

Else {

    Write-Verbose "PKCS service account $ServiceAccount is already a member of the local administrators group."

}

# Add SID to PKCS issued certificates
Write-Verbose 'Updating registry to add SID security extension to PKCS issued certificates...'
[void](New-Item -Path 'HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\PFXCertificateConnector' -Force)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\PFXCertificateConnector' -Name EnableSidSecurityExtension -Value 1 -Force

# Grant 'Log on as a service' right to PKCS service account
$lsaCode = @'
using System;
using System.Runtime.InteropServices;

public class LsaApi

{

    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
    public static extern uint LsaOpenPolicy(

        ref LSA_UNICODE_STRING SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        uint DesiredAccess,
        out IntPtr PolicyHandle

    );

    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
    public static extern uint LsaAddAccountRights(

        IntPtr PolicyHandle,
        IntPtr AccountSid,
        LSA_UNICODE_STRING[] UserRights,
        long CountOfRights

    );

    [DllImport("advapi32.dll")]
    public static extern uint LsaClose(IntPtr ObjectHandle);

    [DllImport("advapi32.dll")]
    public static extern uint LsaNtStatusToWinError(uint Status);

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING

    {

        public ushort Length;
        public ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Buffer;

    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES

    {

        public uint   Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint   Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;

    }

}

'@

Add-Type -TypeDefinition $lsaCode -Language CSharp

Function Grant-LogOnAsService {

    Param([string]$ServiceAccount)

    # Resolve account name to a SID
    Try {

        $ntAccount = New-Object System.Security.Principal.NTAccount($ServiceAccount)
        $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])

    }

    Catch {

        Throw "Could not resolve account '$ServiceAccount' to a SID. Verify the account exists and the format is 'domain\user'. Error: $_"

    }

    # Marshal the SID to unmanaged memory
    $sidBytes = New-Object byte[] $sid.BinaryLength
    $sid.GetBinaryForm($sidBytes, 0)
    $sidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sidBytes.Length)
    [System.Runtime.InteropServices.Marshal]::Copy($sidBytes, 0, $sidPtr, $sidBytes.Length)

    Try {

        $objAttr         = New-Object LsaApi+LSA_OBJECT_ATTRIBUTES
        $objAttr.Length  = [System.Runtime.InteropServices.Marshal]::SizeOf($objAttr)
        $emptyName       = New-Object LsaApi+LSA_UNICODE_STRING
        $policyHandle    = [IntPtr]::Zero

        # POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES = 0x00000010 | 0x00000800
        $status = [LsaApi]::LsaOpenPolicy([ref]$emptyName, [ref]$objAttr, 0x00000810, [ref]$policyHandle)
        If ($status -ne 0) {

            $winErr = [LsaApi]::LsaNtStatusToWinError($status)
            Throw "LsaOpenPolicy failed. Win32 error: $winErr"

        }

        Try {

            $right               = New-Object LsaApi+LSA_UNICODE_STRING
            $right.Buffer        = 'SeServiceLogonRight'
            $right.Length        = [uint16]($right.Buffer.Length * 2)
            $right.MaximumLength = [uint16]($right.Buffer.Length * 2 + 2)

            $status = [LsaApi]::LsaAddAccountRights($policyHandle, $sidPtr, @($right), 1)
            If ($status -ne 0) {

                $winErr = [LsaApi]::LsaNtStatusToWinError($status)
                Throw "LsaAddAccountRights failed. Win32 error: $winErr"

            }

            Write-Verbose "Successfully granted 'Log on as a service' to '$ServiceAccount' (SID: $($sid.Value))."

        }

        Finally {

            [LsaApi]::LsaClose($policyHandle) | Out-Null

        }

    }

    Finally {

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($sidPtr)

    }

}

# Grant the service account the "Log on as a service" right
Write-Verbose "Granting 'Log on as a service' right to PKCS service account $ServiceAccount..."
Grant-LogOnAsService -ServiceAccount $ServiceAccount

Write-Output 'Preparation complete. Be sure to log off and log back on before installing the Intune Certificate Connector.'
