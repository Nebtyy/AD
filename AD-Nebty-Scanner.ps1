<#===========================================================
  AD Ultimate Baseline Scanner (PowerView)

 Version: Stable 2.0
 Author: Nebty

 NOTE:
  - NO exploitation
  - SAFE read-only scanning
  - Designed for pentesters baselines
  - VISUAL: Summary Scorecard enabled.
  - REQ: PowerView.ps1 must be loaded (. .\PowerView.ps1).
===========================================================#>

[CmdletBinding()]
param()

# --- PowerView Check ---
if (-not (Get-Command Get-Domain -ErrorAction SilentlyContinue)) {
    Write-Host "[X] PowerView not loaded!" -ForegroundColor Red
    Write-Host "    Please run: . .\PowerView.ps1" -ForegroundColor Gray
    return
}

# --- GLOBAL REPORT STORAGE ---
$Global:ScanResults = @()

# --- UI HELPER FUNCTIONS ---
function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkCyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor DarkCyan
}

function Log-Result {
    param(
        [string]$Section,
        [string]$Status, # SECURE, VULN, WARN, INFO
        [string]$Message
    )
    
    $color = "Gray"
    $prefix = "[?]"

    switch ($Status) {
        "SECURE" { $color = "Green";  $prefix = "[+]" }
        "VULN"   { $color = "Red";    $prefix = "[!]" }
        "WARN"   { $color = "Yellow"; $prefix = "[-]" }
        "INFO"   { $color = "Cyan";   $prefix = "[*]" }
    }

    Write-Host "$prefix $Message" -ForegroundColor $color
    
    # Add to summary (Skip INFO for summary)
    if ($Status -ne "INFO") {
        $Global:ScanResults += [PSCustomObject]@{
            Section = $Section
            Status  = $Status
            Message = $Message
        }
    }
}

function Log-Item {
    param([string]$Text, [string]$Color="Gray")
    Write-Host "    |-> $Text" -ForegroundColor $Color
}

# --- 1. INITIAL CONTEXT ---
function Get-InitialContext {
    Write-Header "1. Initial Context & Privilege Check"

    # Local
    $localUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $isAdmin = ([Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    
    Log-Result "Context" "INFO" "Host: $env:COMPUTERNAME | User: $localUser"
    if ($isAdmin) { Log-Result "Privilege" "VULN" "Running as Local Administrator (Be careful)" }
    else { Log-Result "Privilege" "SECURE" "Running as Standard User" }

    # Domain
    try {
        $dom = Get-Domain -ErrorAction Stop
        Log-Result "Domain" "INFO" "Domain: $($dom.Name) (SID: $($dom.SID))"
        
        # AdminCount Check
        $adObject = Get-DomainUser -Identity $env:USERNAME -ErrorAction SilentlyContinue
        if ($adObject.AdminCount -eq 1) {
            Log-Result "AdminCount" "WARN" "Current user is AdminSDHolder protected (High Value Target)"
        }

        # Group Check
        $groups = Get-DomainGroup -MemberIdentity $localUser -Properties samaccountname, admincount -ErrorAction Stop
        $privGroups = ($groups | Where-Object {$_.AdminCount -eq 1}).SamAccountName
        
        if ($privGroups) {
            Log-Result "Groups" "WARN" "User is in Privileged Groups:"
            foreach ($g in $privGroups) { Log-Item $g "Red" }
        } else {
            Log-Result "Groups" "SECURE" "User is not in high-privilege groups"
        }

    } catch {
        Log-Result "Context" "WARN" "Could not fully query Domain context: $($_.Exception.Message)"
    }
}

# --- MAIN EXECUTION ---
Get-InitialContext

# --- 2. MACHINE ACCOUNT QUOTA ---
Write-Header "2. Machine Account Quota (MAQ)"
try {
    $maq = (Get-Domain). 'ms-DS-MachineAccountQuota'
    if ($maq -gt 0) {
        Log-Result "MAQ" "VULN" "MAQ is set to $maq (Default is 10). Allows NoPac/RBCD attacks."
    } else {
        Log-Result "MAQ" "SECURE" "MAQ is set to 0."
    }
} catch { Log-Result "MAQ" "WARN" "Failed to check MAQ." }

# --- 3. DOMAIN TRUSTS ---
Write-Header "3. Domain Trusts"
try {
    $trusts = Get-DomainTrust -ErrorAction Stop
    if ($trusts) {
        Log-Result "Trusts" "WARN" "Found $(@($trusts).Count) Domain Trusts:"
        foreach ($t in $trusts) { Log-Item "$($t.SourceName) -> $($t.TargetName) [$($t.TrustType)]" "Cyan" }
    } else {
        Log-Result "Trusts" "SECURE" "No external domain trusts found."
    }
} catch { Log-Result "Trusts" "WARN" "Failed to check Trusts." }

# --- 4. PRINTNIGHTMARE ---
Write-Header "4. PrintNightmare (Spooler on DCs)"
try {
    if (-not $Global:dcs) { $Global:dcs = Get-DomainController -ErrorAction Stop }
    $vulnDCs = @()
    foreach ($dc in $Global:dcs) {
        $spooler = Get-Service -ComputerName $dc.Name -Name "Spooler" -ErrorAction SilentlyContinue
        if ($spooler.Status -eq "Running") { $vulnDCs += $dc.Name }
    }
    
    if ($vulnDCs.Count -gt 0) {
        Log-Result "Spooler" "VULN" "Print Spooler running on $(@($vulnDCs).Count) DC(s):"
        foreach ($d in $vulnDCs) { Log-Item $d "Red" }
    } else {
        Log-Result "Spooler" "SECURE" "Print Spooler disabled on all audited DCs."
    }
} catch { Log-Result "Spooler" "WARN" "Failed to check Spooler on DCs." }

# --- 5. NETWORK AUTH HYGIENE ---
Write-Header "5. Network Authentication Hygiene"

# NTLM
try {
    $ntlm = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").LmCompatibilityLevel
    if ($ntlm -lt 5) { Log-Result "NTLM" "VULN" "NTLM Level is $ntlm (Weak). Relay possible." }
    else { Log-Result "NTLM" "SECURE" "NTLM Level is hardened ($ntlm)." }
} catch { Log-Result "NTLM" "WARN" "Check failed." }

# SMB Signing
try {
    $smb = (Get-SmbServerConfiguration).RequireSecuritySignature
    if (-not $smb) { Log-Result "SMB Sign" "VULN" "SMB Signing NOT required on this host." }
    else { Log-Result "SMB Sign" "SECURE" "SMB Signing is enforced." }
} catch { Log-Result "SMB Sign" "WARN" "Check failed." }

# LLMNR
try {
    $llmnr = (Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue).EnableMulticast
    if ($llmnr -ne 0) { Log-Result "LLMNR" "VULN" "LLMNR is enabled (or default)." }
    else { Log-Result "LLMNR" "SECURE" "LLMNR is explicitly disabled." }
} catch { Log-Result "LLMNR" "WARN" "Check failed." }

# WPAD
try {
    $wpad = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue)."AutoConfigURL"
    if ($wpad) { Log-Result "WPAD" "VULN" "WPAD Proxy detected: $wpad" } 
    else { Log-Result "WPAD" "SECURE" "No WPAD configuration detected." }
} catch { Log-Result "WPAD" "WARN" "Check failed." }

# --- 6. PETITPOTAM / RELAY ---
Write-Header "6. PetitPotam & Relay Vectors"
# EFS
try {
    $efsDCs = @()
    foreach ($dc in $Global:dcs) {
        if ((Get-Service -ComputerName $dc.Name -Name "EFS" -ErrorAction SilentlyContinue).Status -eq "Running") { $efsDCs += $dc.Name }
    }
    if ($efsDCs.Count -gt 0) {
        Log-Result "EFSRPC" "VULN" "EFS Service running on $(@($efsDCs).Count) DC(s) (PetitPotam risk)."
    } else {
        Log-Result "EFSRPC" "SECURE" "EFS Service disabled on audited DCs."
    }
} catch { Log-Result "EFSRPC" "WARN" "Check failed." }

# --- 7. KERBEROASTING ---
Write-Header "7. Kerberoasting"
try {
    $spnUsers = Get-DomainUser -SPN -ErrorAction Stop
    if ($spnUsers) {
        Log-Result "Kerberoast" "VULN" "Found $(@($spnUsers).Count) Kerberoastable accounts."
        foreach ($u in $spnUsers) { Log-Item "$($u.SamAccountName)" "Yellow" }
    } else {
        Log-Result "Kerberoast" "SECURE" "No SPN-bearing user accounts found."
    }
} catch { Log-Result "Kerberoast" "WARN" "Check failed." }

# --- 8. AS-REP ROASTING ---
Write-Header "8. AS-REP Roasting"
try {
    $asrep = Get-DomainUser -PreauthNotRequired -ErrorAction Stop
    if ($asrep) {
        Log-Result "AS-REP" "VULN" "Found $(@($asrep).Count) accounts with 'Do not require Kerberos preauth'."
        foreach ($u in $asrep) { Log-Item "$($u.SamAccountName)" "Yellow" }
    } else {
        Log-Result "AS-REP" "SECURE" "No AS-REP roastable users found."
    }
} catch { Log-Result "AS-REP" "WARN" "Check failed." }

# --- 9. DELEGATION ---
Write-Header "9. Delegation Risks"
try {
    # Unconstrained
    $ud = Get-DomainComputer -Unconstrained -ErrorAction Stop
    if ($ud) {
        Log-Result "Unconstrained" "VULN" "Found $(@($ud).Count) Unconstrained Delegation computers (Critical):"
        foreach ($c in $ud) { Log-Item $c.Name "Red" }
    } else { Log-Result "Unconstrained" "SECURE" "No Unconstrained Delegation found." }

    # Constrained (Restored check)
    $cd = Get-DomainComputer -LDAPFilter '(&(objectCategory=computer)(msDS-AllowedToDelegateTo=*))'
    if ($cd) {
        Log-Result "Constrained" "WARN" "Found $(@($cd).Count) Constrained Delegation computers (Recon)."
    } else { Log-Result "Constrained" "SECURE" "No Constrained Delegation found." }

    # RBCD
    $rbcd = Get-DomainComputer -LDAPFilter '(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))'
    if ($rbcd) {
        Log-Result "RBCD" "WARN" "Found $(@($rbcd).Count) computers configured for RBCD."
    } else { Log-Result "RBCD" "SECURE" "No Resource-Based Constrained Delegation found." }
} catch { Log-Result "Delegation" "WARN" "Check failed." }

# --- 10. KRBTGT & PASSWORD HYGIENE ---
Write-Header "10. KRBTGT & Password Hygiene"
try {
    $krbtgt = Get-DomainUser -Identity krbtgt -Properties pwdlastset -ErrorAction SilentlyContinue
    if ($krbtgt) {
        $days = (New-TimeSpan -Start ([DateTime]::FromFileTime($krbtgt.pwdlastset)) -End (Get-Date)).Days
        if ($days -gt 365) { Log-Result "KRBTGT" "VULN" "KRBTGT password last set $days days ago (> 1 year)." }
        else { Log-Result "KRBTGT" "SECURE" "KRBTGT password rotated $days days ago." }
    }
    
    $nopw = Get-DomainUser | Where-Object { $_.PasswordNotRequired -eq $true }
    if ($nopw) {
        Log-Result "PassNotReq" "VULN" "Found $(@($nopw).Count) users with 'Password Not Required'."
    } else { Log-Result "PassNotReq" "SECURE" "No users with 'Password Not Required'." }

} catch { Log-Result "Passwords" "WARN" "Check failed." }

# --- 11. ADMINSDHOLDER & PRE-WIN 2000 ---
Write-Header "11. Critical Groups & Objects"
try {
    if (Get-DomainObject -LDAPFilter "(cn=AdminSDHolder)") {
        Log-Result "AdminSDHolder" "SECURE" "AdminSDHolder object exists."
    } else { Log-Result "AdminSDHolder" "VULN" "AdminSDHolder object MISSING!" }
} catch { Log-Result "AdminSDHolder" "WARN" "Check failed." }

try {
    $risky = @("Everyone", "Anonymous Logon", "Guests")
    $members = Get-DomainGroupMember -Identity "Pre-Windows 2000 Compatible Access" -ErrorAction SilentlyContinue
    $found = $false
    foreach ($m in $members) {
        if ($risky -contains $m.MemberName -or $m.MemberName -match "S-1-1-0") {
            Log-Result "PreWin2000" "VULN" "Dangerous member in Pre-Windows 2000 group: $($m.MemberName)"
            $found = $true
        }
    }
    if (-not $found) { Log-Result "PreWin2000" "SECURE" "Pre-Windows 2000 group looks safe." }
} catch { Log-Result "PreWin2000" "WARN" "Check failed." }

try {
    if (Get-DomainGroupMember -Identity "DnsAdmins" -ErrorAction SilentlyContinue) {
        Log-Result "DnsAdmins" "WARN" "DnsAdmins is NOT empty. Check members for DLL Injection risks."
    } else { Log-Result "DnsAdmins" "SECURE" "DnsAdmins is empty." }
} catch { }

# --- 12. ACL SCANS ---
Write-Header "12. Access Control Lists (ACLs)"
Log-Result "Status" "INFO" "Scanning ACLs... (This may take a moment)"

# Users
try {
    $vulnUsers = Get-DomainUser -LDAPFilter "(sAMAccountName=*)" | Get-ObjectAcl -ResolveGuids -ErrorAction SilentlyContinue | Where-Object { 
        $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteProperty" -and 
        $_.IdentityReference -notmatch "Administrators|ENTERPRISE DOMAIN CONTROLLERS|SYSTEM|SELF"
    }
    if ($vulnUsers) {
        Log-Result "UserACLs" "VULN" "Found $(@($vulnUsers).Count) suspicious Write ACLs on Users (Shadow Creds)."
    } else { Log-Result "UserACLs" "SECURE" "No suspicious User ACLs found." }
} catch { Log-Result "UserACLs" "WARN" "Check failed." }

# GPO
try {
    $vulnGPO = Get-DomainObject -LDAPFilter "(objectCategory=groupPolicyContainer)" | Get-ObjectAcl -ResolveGuids -ErrorAction SilentlyContinue | Where-Object { 
        $_.ActiveDirectoryRights -match "GenericAll|WriteProperty" -and $_.IdentityReference -notmatch "Administrators|SYSTEM"
    }
    if ($vulnGPO) {
        Log-Result "GPO ACLs" "VULN" "Found $(@($vulnGPO).Count) suspicious Write ACLs on GPOs."
    } else { Log-Result "GPO ACLs" "SECURE" "No suspicious GPO ACLs found." }
} catch { Log-Result "GPO ACLs" "WARN" "Check failed." }

# DC Sync
try {
    $dcsync = Get-DomainObjectACL -ResolveGuids -ErrorAction Stop | Where-Object { 
        $_.ActiveDirectoryRights -match "Replicating Directory Changes" -and $_.IdentityReference -notmatch "Administrators|ENTERPRISE DOMAIN CONTROLLERS|SYSTEM"
    }
    if ($dcsync) {
        Log-Result "DCSync" "VULN" "Found $(@($dcsync).Count) non-standard accounts with DC Sync rights!"
        foreach ($d in $dcsync) { Log-Item "$($d.IdentityReference)" "Red" }
    } else { Log-Result "DCSync" "SECURE" "No suspicious DC Sync rights detected." }
} catch { Log-Result "DCSync" "WARN" "Check failed." }

# --- 13. ADCS ---
Write-Header "13. ADCS (Certificates)"
try {
    $adcs = Get-DomainObject -LDAPFilter "(objectClass=pKIEnrollmentService)"
    if ($adcs) {
        Log-Result "ADCS" "WARN" "ADCS Detected ($( @($adcs).Count ) servers). Verify for ESC vulnerabilities manually."
    } else { Log-Result "ADCS" "SECURE" "No ADCS Infrastructure found." }
} catch { Log-Result "ADCS" "WARN" "Check failed." }


# --- FINAL SUMMARY ---
Write-Host ""
Write-Host "############################################################" -ForegroundColor DarkCyan
Write-Host "                  SCAN SCORECARD                            " -ForegroundColor White
Write-Host "############################################################" -ForegroundColor DarkCyan
Write-Host ""

# Group by status for better readability logic
$vulns = $Global:ScanResults | Where-Object { $_.Status -eq "VULN" }
$warns = $Global:ScanResults | Where-Object { $_.Status -eq "WARN" }
$secures = $Global:ScanResults | Where-Object { $_.Status -eq "SECURE" }

if ($vulns) {
    Write-Host "CRITICAL FINDINGS:" -ForegroundColor Red
    foreach ($v in $vulns) { Write-Host " [!] $($v.Section): $($v.Message)" -ForegroundColor Red }
    Write-Host ""
}

if ($warns) {
    Write-Host "WARNINGS / MANUAL REVIEW:" -ForegroundColor Yellow
    foreach ($w in $warns) { Write-Host " [-] $($w.Section): $($w.Message)" -ForegroundColor Yellow }
    Write-Host ""
}

Write-Host "SUMMARY STATS:" -ForegroundColor Cyan
Write-Host "  Vulnerable : $(@($vulns).Count)" -ForegroundColor Red
Write-Host "  Warnings   : $(@($warns).Count)" -ForegroundColor Yellow
Write-Host "  Secure     : $(@($secures).Count)" -ForegroundColor Green
Write-Host ""
Write-Host "Scan Complete." -ForegroundColor White
