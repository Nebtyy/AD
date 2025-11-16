<#===========================================================
 AD Ultimate Baseline Non-Invasive Scanner
 Version: Stable 1.2
 Author: Nebty

 NOTE:
  - NO exploitation
  - SAFE read-only scanning
  - Designed for pentesters baselines
===========================================================#>

[CmdletBinding()]
param()

# --- Active Directory module ---
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

if (-not (Get-Module ActiveDirectory -ErrorAction SilentlyContinue)) {
    Write-Error "ActiveDirectory module not found. Install RSAT / AD DS tools and try again."
    return
}

function Banner {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    Write-Host ""
    Write-Host "------------------------------"
    Write-Host "=== $Text ==="
    Write-Host "------------------------------"
    Write-Host ""
}

Banner "Active Directory Baseline Security Scan"

# ===========================================================
# MACHINE ACCOUNT QUOTA
# ===========================================================
Banner "MachineAccountQuota"

try {
    $dom = Get-ADDomain -ErrorAction Stop
    Write-Host "MachineAccountQuota: $($dom.MachineAccountQuota)"
    if ($dom.MachineAccountQuota -gt 0) {
        Write-Host "[!] RISK: Users can create machine accounts (NoPac/RBCD surface)." -ForegroundColor Red
    } else {
        Write-Host "[+] MachineAccountQuota is 0 (safer default)"
    }
} catch {
    Write-Warning "Failed to query domain info: $($_.Exception.Message)"
}

# ===========================================================
# PRINTNIGHTMARE (Print Spooler on DCs)
# ===========================================================
Banner "PrintNightmare - Spooler on DCs"

try {
    $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
    foreach ($dc in $dcs) {
        try {
            $spooler = Get-Service -ComputerName $dc.HostName -Name "Spooler" -ErrorAction SilentlyContinue
            if ($spooler -and $spooler.Status -eq "Running") {
                Write-Host "[!] Spooler running on: $($dc.HostName)" -ForegroundColor Red
            } else {
                Write-Host "[+] Spooler disabled on: $($dc.HostName)"
            }
        } catch {
            Write-Warning "Failed to query Spooler on $($dc.HostName): $($_.Exception.Message)"
        }
    }
} catch {
    Write-Warning "Failed to enumerate domain controllers: $($_.Exception.Message)"
}

# ===========================================================
# NTLM / SMB SIGNING / LLMNR / WPAD
# ===========================================================
Banner "Network Authentication Risks"

# NTLM level
try {
    $lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
    $ntlm = $lsa.LmCompatibilityLevel
    Write-Host "NTLM Level (LmCompatibilityLevel): $ntlm"

    if (-not $ntlm -or $ntlm -lt 5) {
        Write-Host "[!] NTLM enabled or weak level (Relay possible)" -ForegroundColor Red
    } else {
        Write-Host "[+] NTLM hardened (LmCompatibilityLevel >= 5)"
    }
} catch {
    Write-Warning "Failed to read NTLM settings: $($_.Exception.Message)"
}

# SMB Signing
try {
    $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop
    $smb = $smbConfig.RequireSecuritySignature
    Write-Host "SMB Signing required (server): $smb"
    if (-not $smb) {
        Write-Host "[!] SMB Signing disabled (Relay possible)" -ForegroundColor Red
    } else {
        Write-Host "[+] SMB Signing is required on this server"
    }
} catch {
    Write-Warning "Failed to read SMB Signing configuration: $($_.Exception.Message)"
}

# LLMNR
try {
    $llmnrKey = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue
    $llmnr = $llmnrKey.EnableMulticast

    if ($llmnr -eq 0) {
        Write-Host "[+] LLMNR disabled"
    } else {
        Write-Host "[!] LLMNR enabled or not explicitly disabled (NTLM hijack possible)" -ForegroundColor Red
    }
} catch {
    Write-Warning "Failed to read LLMNR setting: $($_.Exception.Message)"
}

# WPAD
try {
    $wpad = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue)."AutoConfigURL"
    if ($wpad) {
        Write-Host "[!] WPAD proxy set: $wpad" -ForegroundColor Yellow
    } else {
        Write-Host "[+] No WPAD AutoConfigURL set for current user"
    }
} catch {
    Write-Warning "Failed to read WPAD settings: $($_.Exception.Message)"
}

# ===========================================================
# PETITPOTAM / NTLM RELAY SURFACE
# ===========================================================
Banner "PetitPotam / NTLM Relay Surface"

# 1) Outgoing NTLM restriction (RestrictSendingNTLMTraffic)
try {
    $msv = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ErrorAction SilentlyContinue
    $restrictOut = $msv.RestrictSendingNTLMTraffic

    Write-Host "RestrictSendingNTLMTraffic: $restrictOut"

    if ($restrictOut -eq 2) {
        Write-Host "[+] Outgoing NTLM is blocked to remote servers (PetitPotam-resistant)" -ForegroundColor Green
    } elseif ($restrictOut -eq 1) {
        Write-Host "[!] Outgoing NTLM allowed only to whitelist (review whitelist for safety)" -ForegroundColor Yellow
    } else {
        Write-Host "[!] Outgoing NTLM allowed to any host (NTLM relay / PetitPotam possible)" -ForegroundColor Red
    }
} catch {
    Write-Warning "Failed to read RestrictSendingNTLMTraffic (cannot determine PetitPotam exposure): $($_.Exception.Message)"
}

# 2) LM hash storage (NoLMHash)
try {
    $lsa2 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
    $noLmHash = $lsa2.NoLMHash
    Write-Host "NoLMHash: $noLmHash"

    if ($noLmHash -eq 1) {
        Write-Host "[+] LM hashes are not stored (safer against offline cracking)"
    } else {
        Write-Host "[!] LM hashes may be stored (weaker posture for any relay/credential theft)" -ForegroundColor Yellow
    }
} catch {
    Write-Warning "Failed to read NoLMHash setting: $($_.Exception.Message)"
}

# 3) NTLM minimum client security (NtlmMinClientSec)
try {
    $ntlmMin = $msv.NtlmMinClientSec
    Write-Host "NtlmMinClientSec: $ntlmMin"
    if (-not $ntlmMin -or $ntlmMin -eq 0) {
        Write-Host "[!] NtlmMinClientSec not hardened (weak NTLM client protections)" -ForegroundColor Yellow
    } else {
        Write-Host "[+] NtlmMinClientSec set (NTLM client security options in effect)"
    }
} catch {
    Write-Warning "Failed to read NtlmMinClientSec: $($_.Exception.Message)"
}

# 4) EFS service on Domain Controllers (PetitPotam path via EFSRPC)
try {
    if (-not $dcs) {
        $dcs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
    }

    if ($dcs) {
        foreach ($dc in $dcs) {
            try {
                $efs = Get-Service -ComputerName $dc.HostName -Name "EFS" -ErrorAction SilentlyContinue
                if ($efs -and $efs.Status -eq "Running") {
                    Write-Host "[!] EFS service running on DC: $($dc.HostName) (PetitPotam path available if NTLM relay allowed)" -ForegroundColor Yellow
                } elseif ($efs) {
                    Write-Host "[+] EFS service not running or disabled on DC: $($dc.HostName)"
                } else {
                    Write-Host "[!] EFS service not found on DC: $($dc.HostName) (cannot assess EFSRPC exposure)" -ForegroundColor Yellow
                }
            } catch {
                Write-Warning "Failed to query EFS service on $($dc.HostName): $($_.Exception.Message)"
            }
        }
    } else {
        Write-Warning "No DC list available to assess EFS service for PetitPotam."
    }
} catch {
    Write-Warning "Error while evaluating EFS service on DCs: $($_.Exception.Message)"
}

# ===========================================================
# KERBEROAST
# ===========================================================
Banner "Kerberoastable Accounts"

try {
    $spnUsers = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName -ErrorAction Stop
    if ($spnUsers) {
        foreach ($u in $spnUsers) {
            Write-Host "[!] Kerberoastable user (has SPN): $($u.SamAccountName)" -ForegroundColor Yellow
            foreach ($spn in $u.ServicePrincipalName) {
                Write-Host "    SPN: $spn"
            }
        }
    } else {
        Write-Host "[+] No SPN-bearing users found (unusual for many environments)"
    }
} catch {
    Write-Warning "Failed to enumerate SPN users: $($_.Exception.Message)"
}

# ===========================================================
# AS-REP ROASTING
# ===========================================================
Banner "AS-REP Roast (Do not require Kerberos pre-auth)"

try {
    $asrep = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -Properties DoesNotRequirePreAuth -ErrorAction Stop
    if ($asrep) {
        foreach ($u in $asrep) {
            Write-Host "[!] AS-REP Roastable user: $($u.SamAccountName)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[+] No AS-REP roastable users found"
    }
} catch {
    Write-Warning "Failed to query AS-REP roastable users: $($_.Exception.Message)"
}

# ===========================================================
# DELEGATION (Unconstrained / Constrained / RBCD)
# ===========================================================
Banner "Delegation (Unconstrained / Constrained / RBCD)"

# Unconstrained
try {
    $deleg1 = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation -ErrorAction Stop
    if ($deleg1) {
        foreach ($d in $deleg1) {
            Write-Host "[!] Unconstrained Delegation: $($d.Name)" -ForegroundColor Red
        }
    } else {
        Write-Host "[+] No computers with Unconstrained Delegation"
    }
} catch {
    Write-Warning "Failed to query Unconstrained Delegation computers: $($_.Exception.Message)"
}

# Constrained
try {
    $deleg2 = Get-ADComputer -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties msDS-AllowedToDelegateTo -ErrorAction Stop
    if ($deleg2) {
        foreach ($d in $deleg2) {
            Write-Host "[!] Constrained Delegation: $($d.Name)" -ForegroundColor Yellow
            foreach ($svc in $d."msDS-AllowedToDelegateTo") {
                Write-Host "    Allowed service: $svc"
            }
        }
    } else {
        Write-Host "[+] No computers with Constrained Delegation"
    }
} catch {
    Write-Warning "Failed to query Constrained Delegation computers: $($_.Exception.Message)"
}

# RBCD
try {
    $rbcd = Get-ADComputer -Filter * -Properties "msDS-AllowedToActOnBehalfOfOtherIdentity" -ErrorAction Stop
    $rbcdTargets = $rbcd | Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" }

    if ($rbcdTargets) {
        foreach ($c in $rbcdTargets) {
            Write-Host "[!] RBCD configured on: $($c.Name)" -ForegroundColor Red
        }
    } else {
        Write-Host "[+] No RBCD configurations found"
    }
} catch {
    Write-Warning "Failed to query RBCD settings: $($_.Exception.Message)"
}

# ===========================================================
# PASSWORD RISKS (PasswordNotRequired)
# ===========================================================
Banner "Password Hygiene Risks"

try {
    $weak1 = Get-ADUser -Filter { PasswordNotRequired -eq $true } -Properties PasswordNotRequired -ErrorAction Stop
    if ($weak1) {
        foreach ($u in $weak1) {
            Write-Host "[!] PasswordNotRequired user: $($u.SamAccountName)" -ForegroundColor Red
        }
    } else {
        Write-Host "[+] No users with PasswordNotRequired"
    }
} catch {
    Write-Warning "Failed to query PasswordNotRequired users: $($_.Exception.Message)"
}

# ===========================================================
# ADMINSDHOLDER PROTECTION CHECK
# ===========================================================
Banner "AdminSDHolder Hardening"

try {
    $adminSD = Get-ADObject -LDAPFilter "(distinguishedName=CN=AdminSDHolder,*)" -Properties ntSecurityDescriptor -ErrorAction Stop
    if ($adminSD) {
        Write-Host "[+] AdminSDHolder object exists (ACL review recommended manually)"
    } else {
        Write-Host "[!] AdminSDHolder not found (VERY unusual)" -ForegroundColor Red
    }
} catch {
    Write-Warning "Failed to query AdminSDHolder: $($_.Exception.Message)"
}

# ===========================================================
# DC SYNC PERMISSIONS
# ===========================================================
Banner "DC Sync Permissions"

try {
    $domain = Get-ADDomain -ErrorAction Stop
    $domainDn = $domain.DistinguishedName
    $acl = Get-ACL ("AD:" + $domainDn)

    $danger = $acl.Access | Where-Object {
        $_.ActiveDirectoryRights -match "Replicating Directory Changes"
    }

    if ($danger) {
        foreach ($d in $danger) {
            Write-Host "[!] Possible DC Sync right: $($d.IdentityReference) - $($d.ActiveDirectoryRights)" -ForegroundColor Red
        }
    } else {
        Write-Host "[+] No non-default Replicating Directory Changes rights detected (or none found)"
    }
} catch {
    Write-Warning "Failed to read domain ACL for DC Sync rights: $($_.Exception.Message)"
}

# ===========================================================
# ADCS (CERTIFICATE SERVICES)
# ===========================================================
Banner "ADCS / ESC Vulnerability Indicators"

try {
    $adcs = Get-ADObject -LDAPFilter "(objectClass=pKIEnrollmentService)" -ErrorAction Stop
    if ($adcs) {
        Write-Host "[!] ADCS CA Detected (ESC1-ESC8 possible - further review required)" -ForegroundColor Yellow
        foreach ($cs in $adcs) {
            Write-Host "    CA: $($cs.Name)"
        }
    } else {
        Write-Host "[+] No ADCS detected (no pKIEnrollmentService objects)"
    }
} catch {
    Write-Warning "Failed to query ADCS objects: $($_.Exception.Message)"
}

# ===========================================================
Banner "Scan Complete"
