# 📋 AD Baseline Scanner — Full Check List

## 🏛️ Active Directory Core

* **Active Directory Module Availability**
* **MachineAccountQuota**

---

## 🖨️ Print Spooler / PrintNightmare

* **Print Spooler state on Domain Controllers**

---

## 🔐 NTLM / SMB / LLMNR / WPAD (Relay Surface)

* **NTLM Compatibility Level (LmCompatibilityLevel)**
* **SMB Signing Requirement**
* **LLMNR Status**
* **WPAD AutoConfig Status**

---

## ⚠️ PetitPotam / NTLM Relay Expanded Checks

* **RestrictSendingNTLMTraffic**
* **NoLMHash**
* **NtlmMinClientSec**
* **EFS Service Status on Domain Controllers (EFSRPC)**

---

## 🔥 Kerberos Attack Surface

* **Kerberoastable Accounts (SPN users)**
* **AS-REP Roastable Accounts**

---

## 🎭 Delegation Risks

* **Unconstrained Delegation**
* **Constrained Delegation**
* **Resource-Based Constrained Delegation (RBCD)**

---

## 🔑 Password Hygiene

* **PasswordNotRequired Users**

---

## 🛡️ Privileged Access Protection

* **AdminSDHolder Presence**

---

## 🧬 Domain Replication Risks

* **DC Sync Permissions (Replicating Directory Changes)**

---

## 🎫 Active Directory Certificate Services (ADCS)

* **ADCS Enrollment Services Presence (ESC1–ESC8 surface)**

