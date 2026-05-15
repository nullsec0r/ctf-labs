# Operation Silhouette
---

> **Briefing**
>
> Vaultify Inc. is a 40-person startup in Bengaluru that sells encrypted document storage to law firms and hospitals. Two days ago, an unknown individual was seen on CCTV in the server room — a room only 6 people have keycard access to. Nothing appeared stolen. The CEO thinks it was probably a delivery person who got lost.
>
> Your job is to prove whether it was innocent or not.
>
> You have four evidence files: CCTV + access logs, Active Directory events, endpoint USB forensics, and a staff interview summary. The evidence points in two directions at once — and one of your suspects has a perfect alibi that may itself be fabricated.

---

## The Attack Chain (reconstruct this)

```
[Stage 1: Pretexting] → [Stage 2: Physical Access] → [Stage 3: Internal Recon]
      → [Stage 4: USB Drop / Data Theft] → [Stage 5: Cover Tracks] → [Stage 6: Exfil]
```

Four deliberate traps hidden across the evidence files:

| Trap | Description |
|------|-------------|
| Trap 1 | The CCTV timestamp and keycard log timestamp don't match — one of them was tampered |
| Trap 2 | An internal employee's credentials were used — but were they the insider? |
| Trap 3 | The USB device looks like a charger — it isn't |
| Trap 4 | The "perfect alibi" has one technical flaw that breaks it completely |

---

## Evidence File 1 — Physical Access & CCTV Logs

### Section A: Keycard Access Log — Server Room Door
> **System:** HID keycard reader · **Log timezone: IST (UTC+5:30)**

```
DATE        TIME      CARD_ID    USER              EVENT
2024-04-08  08:44:11  K-0012     Rahul Sharma       ENTRY GRANTED   [DevOps Lead]
2024-04-08  09:02:33  K-0012     Rahul Sharma       EXIT
2024-04-08  11:15:07  K-0019     Divya Menon        ENTRY GRANTED   [CTO]
2024-04-08  11:38:52  K-0019     Divya Menon        EXIT
2024-04-08  13:45:00  K-0031     Aryan Kapoor       ENTRY GRANTED   [Sysadmin]
2024-04-08  14:02:17  K-0031     Aryan Kapoor       EXIT
2024-04-08  14:55:38  K-0031     Aryan Kapoor       ENTRY GRANTED
2024-04-08  15:22:10  K-0031     Aryan Kapoor       EXIT
2024-04-08  16:41:03  K-0009     Preethi Nair       ENTRY GRANTED   [Infra Engineer]
2024-04-08  16:58:44  K-0009     Preethi Nair       EXIT
2024-04-08  19:07:28  K-0031     Aryan Kapoor       ENTRY GRANTED
2024-04-08  19:09:11  K-0031     Aryan Kapoor       EXIT            [1 min 43 sec]
2024-04-08  19:33:47  --------   UNKNOWN            ENTRY GRANTED   ← NO CARD REGISTERED
2024-04-08  19:47:22  --------   UNKNOWN            EXIT            [13 min 46 sec]
2024-04-08  21:14:09  K-0012     Rahul Sharma       ENTRY GRANTED
2024-04-08  21:29:55  K-0012     Rahul Sharma       EXIT
```

### Section B: CCTV Log — Server Room Corridor Camera
> **Camera ID:** CAM-07 · **Note: CCTV system clock is separate from keycard system**

```
DATE        TIME      EVENT
2024-04-08  19:31:12  Motion detected — corridor outside server room
2024-04-08  19:31:58  Individual enters frame — dark jacket, cap, face partially obscured
2024-04-08  19:32:04  Individual approaches server room door
2024-04-08  19:32:09  Door opens — individual enters
2024-04-08  19:45:38  Individual exits server room — carrying same bag as entry
2024-04-08  19:45:55  Individual exits corridor frame toward stairwell B
2024-04-08  21:12:44  Motion detected — Rahul Sharma approaches (recognized, face visible)
```

### Section C: Building Visitor Log — Front Desk (manual register)

```
DATE        TIME IN   NAME              PURPOSE              COMPANY           BADGE
2024-04-08  09:30     Vikram Nair       Deliver stationery   OfficeSupplyCo    V-041
2024-04-08  11:00     Sunita Rao        Interview            N/A               V-042
2024-04-08  14:10     Ravi Kumar        AC maintenance       CoolTech HVAC     V-043
2024-04-08  18:45     [ENTRY TORN OUT]  [TORN]               [TORN]            [TORN]
2024-04-08  21:00     Delivery person   Amazon parcel        Amazon            V-045
```

> **Note:** Badge V-044 was issued but the register entry for it has been physically torn out.
> Front desk CCTV (CAM-01) footage for 18:30–19:00 has been **overwritten** — default
> retention on front desk camera is 24 hours on a rolling loop.

### Challenge Questions — Evidence File 1

**Q1. Keycard vs CCTV Timestamps**

a) The keycard log shows the unknown entry at `19:33:47 IST`. The CCTV shows the door opening at `19:32:09`. That is a **98-second gap** for the same event. Both cannot be correct. Which system is more likely to have been tampered with, and why? What technique would an attacker use to manipulate each one?

b) Aryan Kapoor's `19:07:28` entry lasted only 1 minute 43 seconds. All his other visits were 15–20 minutes. What are two possible innocent explanations and two suspicious explanations for this short visit?

c) The front desk log has a torn entry for badge V-044. The CCTV covering the front desk was conveniently overwritten. Are these two facts connected? What does the combination tell you about the attacker's level of preparation?

**Q2. The Unknown Entry**

a) The unknown entry shows `ENTRY GRANTED` with no card registered. List three technical methods by which an attacker could open a keycard-controlled door without a registered card.

b) The individual spent **13 minutes 46 seconds** in the server room. That is long enough to do real damage but short enough to avoid suspicion. List what an attacker with physical access could accomplish in that time.

c) Rahul Sharma arrived at `21:14:09` — about 87 minutes after the unknown person left. Is Rahul a suspect? What log evidence would you need to either clear or implicate him?

**Q3. Synthesis**

The building visitor log, front desk CCTV, and badge V-044 entry have all been partially destroyed or overwritten. This affects exactly the window of the breach. Is this a coincidence? What does deliberate evidence destruction tell you about the attacker's profile — insider, outsider, or both?

---

## Evidence File 2 — Active Directory & Authentication Logs

### Section A: Active Directory Events — Domain Controller
> **Server:** `dc01.vaultify.internal` · **Timezone: IST**

```
2024-04-08 19:34:02  EventID 4624  Account Logon
                     Account: VAULTIFY\aryan.kapoor
                     Logon Type: 3 (Network)
                     Source IP: 10.0.1.44
                     Workstation: VAULT-WS-014

2024-04-08 19:34:08  EventID 4672  Special Privileges Assigned
                     Account: VAULTIFY\aryan.kapoor
                     Privileges: SeDebugPrivilege, SeImpersonatePrivilege

2024-04-08 19:34:55  EventID 4698  Scheduled Task Created
                     Account: VAULTIFY\aryan.kapoor
                     Task Name: \Microsoft\Windows\WMI\WMIPerformanceAdapter
                     Task Action: powershell.exe -enc JABjAGwAaQBlAG4AdA...
                     [BASE64 ENCODED COMMAND]

2024-04-08 19:35:10  EventID 4663  File Access
                     Account: VAULTIFY\aryan.kapoor
                     Object: \\fileserver01\contracts\client_master_list.xlsx
                     Access: ReadData

2024-04-08 19:35:14  EventID 4663  File Access
                     Account: VAULTIFY\aryan.kapoor
                     Object: \\fileserver01\contracts\NDA_signed_all_clients.zip
                     Access: ReadData

2024-04-08 19:35:21  EventID 4663  File Access
                     Account: VAULTIFY\aryan.kapoor
                     Object: \\fileserver01\hr\salary_bands_2024.xlsx
                     Access: ReadData

2024-04-08 19:41:07  EventID 4663  File Access
                     Account: VAULTIFY\aryan.kapoor
                     Object: \\fileserver01\product\encryption_keys_backup.zip
                     Access: ReadData

2024-04-08 19:44:33  EventID 4647  User Initiated Logoff
                     Account: VAULTIFY\aryan.kapoor
                     Source IP: 10.0.1.44

2024-04-08 19:45:01  EventID 4699  Scheduled Task Deleted
                     Account: VAULTIFY\aryan.kapoor
                     Task Name: \Microsoft\Windows\WMI\WMIPerformanceAdapter
```

### Section B: WORKSTATION VAULT-WS-014 — Local Event Log

```
2024-04-08 19:33:51  System boot — cold start
                     Previous shutdown: 2024-04-05 18:22:07  ← last used 3 DAYS AGO

2024-04-08 19:33:58  User logon: VAULTIFY\aryan.kapoor
                     Logon method: Password (keyboard)

2024-04-08 19:34:44  Windows Defender: Real-time protection DISABLED
                     Disabled by: VAULTIFY\aryan.kapoor

2024-04-08 19:35:02  USB device connected
                     Device class: HID (Human Interface Device)
                     Hardware ID: USB\VID_05AC&PID_0267
                     Friendly name: "Apple USB Keyboard"         ← claims to be a keyboard

2024-04-08 19:35:04  New process: powershell.exe
                     Parent: RuntimeBroker.exe                   ← unusual parent
                     Command: [MATCHES SCHEDULED TASK BASE64 ABOVE]

2024-04-08 19:44:28  USB device disconnected
                     Same Hardware ID as above

2024-04-08 19:44:31  Windows Defender: Real-time protection ENABLED

2024-04-08 19:44:55  System shutdown initiated
                     Initiated by: VAULTIFY\aryan.kapoor
```

### Section C: Aryan Kapoor's Alibi — Submitted to HR next morning

```
"I was not in the office after 15:22 on April 8th. I have proof:

1. My Swiggy order was placed at 18:55 from my home address
   (Koramangala, Bengaluru) and delivered at 19:32.
   Order ID: SWG-20240408-884421

2. I made a phone call to my mother at 19:15 that lasted 34 minutes
   (until 19:49). Phone records available on request.

3. My building society's gate log shows my car entering the housing
   complex at 18:38.

Someone must have stolen my credentials. I have no idea how."
   — Aryan Kapoor, Sysadmin
```

### Challenge Questions — Evidence File 2

**Q1. Active Directory Events**

a) EventID 4624 shows a **Logon Type 3 (Network logon)** from `10.0.1.44` to `VAULT-WS-014`. A network logon means the credentials were provided over the network, not typed locally. But the workstation log at `19:33:58` shows a **keyboard logon**. How can both exist simultaneously? What does this contradiction suggest?

b) EventID 4698 shows a scheduled task created with a **base64-encoded PowerShell command**. The task is named `WMIPerformanceAdapter` — a name designed to blend in with legitimate Windows tasks. What is this technique called? Decode the first few characters `JABjAGwAaQBlAG4AdA` — what do they spell out? *(Hint: this is UTF-16LE base64)*

c) The files accessed in 6 minutes: client master list, all signed NDAs, salary bands, and encryption key backups. Rank these by severity of exposure for a B2B SaaS company. Which single file is the most catastrophic and why?

**Q2. Workstation Forensics**

a) The USB device identifies itself as `"Apple USB Keyboard"` with Hardware ID `USB\VID_05AC&PID_0267`. But `VID_05AC` is Apple's vendor ID and `PID_0267` is assigned to a specific Apple keyboard model. An attacker device is spoofing this ID. What type of USB attack device does this describe? Name a real tool that does this.

b) Windows Defender was disabled at `19:34:44`, PowerShell ran at `19:35:04`, and Defender was re-enabled at `19:44:31`. The attacker re-enabled it on the way out. What does re-enabling AV before leaving tell you about the attacker's intent?

c) The workstation's last use was 3 days ago (`2024-04-05 18:22:07`). The attacker chose this specific machine. Why would an attacker prefer a workstation that hasn't been used recently over an actively used one?

**Q3. The Alibi — this is the hardest question**

Aryan's alibi has three parts: a food delivery, a phone call, and a gate log. All three are real and verifiable. His alibi appears airtight.

But there is **one technical detail** in the AD log that breaks his alibi completely — without needing to challenge any of his three alibi items.

Find it. Explain precisely why it proves his alibi is irrelevant to whether he is the insider threat.

*(Hint: re-read EventID 4624 very carefully. Think about what Logon Type 3 means for physical presence.)*

---

## Evidence File 3 — USB Device Forensics

### Section A: USB Registry Artifacts — recovered from VAULT-WS-014
> **Source:** SYSTEM registry hive, USBSTOR key · **Analyst tool: RegRipper**

```
Key: HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\
     Disk&Ven_SAMSUNG&Prod_Flash_Drive&Rev_1100\
     7&3A2B1C4D&0&0000000000000001

FirstInstall:   2024-04-08 14:01:33 IST    ← installed EARLIER in the day
LastArrival:    2024-04-08 19:35:02 IST
LastRemoval:    2024-04-08 19:44:28 IST
FriendlyName:   Apple USB Keyboard
ParentIdPrefix: 7&3A2B1C4D

NOTE: VEN_SAMSUNG + FriendlyName "Apple USB Keyboard" — vendor mismatch.
The device presents as an HID keyboard but the storage class entry
reveals it also registers as a mass storage device (Disk&Ven_SAMSUNG).
```

### Section B: Prefetch Files — recovered from VAULT-WS-014
> **Prefetch records what executables ran and when**

```
XCOPY.EXE-AB3F1C22.pf
  Last run:    2024-04-08 19:37:14 IST
  Run count:   1
  Files referenced:
    \DEVICE\HARDDISKVOLUME3\WINDOWS\SYSTEM32\XCOPY.EXE
    \DEVICE\HARDDISKVOLUME4\CLIENT_MASTER_LIST.XLSX    ← USB drive = HarddiskVolume4
    \DEVICE\HARDDISKVOLUME4\NDA_SIGNED_ALL_CLIENTS.ZIP
    \DEVICE\HARDDISKVOLUME4\SALARY_BANDS_2024.XLSX
    \DEVICE\HARDDISKVOLUME4\ENCRYPTION_KEYS_BACKUP.ZIP

POWERSHELL.EXE-7F3A2B1D.pf
  Last run:    2024-04-08 19:35:04 IST
  Run count:   1
  Files referenced:
    \DEVICE\HARDDISKVOLUME4\PAYLOAD\STAGER.PS1         ← script came FROM the USB
```

### Section C: $MFT Analysis — Master File Table remnants
> **Deleted files partially recovered from VAULT-WS-014 \$Recycle.Bin and unallocated space**

```
RECOVERED FILE ENTRIES (metadata only — content overwritten):

Filename:    stager.ps1
Created:     2024-03-21 11:44:02 IST    ← created 18 DAYS before the attack
Modified:    2024-04-07 23:15:44 IST    ← modified day BEFORE the attack
Deleted:     2024-04-08 19:44:20 IST
Size:        4,847 bytes
Path:        [USB]\PAYLOAD\stager.ps1

Filename:    exfil_log.txt
Created:     2024-04-08 19:40:11 IST
Modified:    2024-04-08 19:44:18 IST
Deleted:     2024-04-08 19:44:19 IST
Size:        312 bytes
Path:        [USB]\PAYLOAD\exfil_log.txt

Filename:    wipe.bat
Created:     2024-03-21 11:44:05 IST
Deleted:     2024-04-08 19:44:22 IST
Path:        [USB]\PAYLOAD\wipe.bat
```

### Section D: Network Share Access — SMB logs from fileserver01

```
2024-04-08 19:35:09  CONNECT    \\fileserver01\contracts   from 10.0.1.44  user=aryan.kapoor
2024-04-08 19:35:10  READ       client_master_list.xlsx    bytes=248,441
2024-04-08 19:35:14  READ       NDA_signed_all_clients.zip bytes=8,847,221
2024-04-08 19:35:21  READ       salary_bands_2024.xlsx     bytes=184,332
2024-04-08 19:41:07  READ       encryption_keys_backup.zip bytes=2,104,887
2024-04-08 19:41:44  DISCONNECT \\fileserver01\contracts   from 10.0.1.44
```

### Challenge Questions — Evidence File 3

**Q1. USB Device Identity**

a) The registry shows `Ven_SAMSUNG` in the USBSTOR key, but the device presents as `"Apple USB Keyboard"` to the OS. A device that identifies as a keyboard (HID) but also has mass storage capability is a specific type of attack hardware. What is it called? How does presenting as a keyboard help bypass security controls?

b) The `FirstInstall` timestamp is `14:01:33 IST` — nearly **5.5 hours before** the breach at `19:35:02`. The device was connected to this workstation earlier in the day. Cross-reference Evidence File 1's keycard log. Who had server room access between 13:45 and 15:22 IST?

c) `stager.ps1` was **created on March 21st and modified on April 7th** — 18 days and 1 day before the attack respectively. What does this preparation timeline tell you about whether this was opportunistic or planned?

**Q2. Prefetch & File Recovery**

a) Prefetch shows `XCOPY.EXE` ran at `19:37:14` and copied four specific files to `HarddiskVolume4` (the USB drive). The AD log shows those same files were accessed via SMB between `19:35:10` and `19:41:07`. Construct the exact sequence of events between `19:35:02` and `19:44:28` in chronological order.

b) `exfil_log.txt` (312 bytes) was created during the operation and deleted before the USB was removed. Even though the content is overwritten, what might a 312-byte log file have contained? What forensic technique might recover the actual content?

c) `wipe.bat` was created on the same day as `stager.ps1` (March 21st). What does a file called `wipe.bat` on an attack USB most likely do, and why was it prepared weeks in advance alongside the main payload?

**Q3. Data Volume**

The SMB log shows the total bytes read:

| File | Bytes |
|------|-------|
| client_master_list.xlsx | 248,441 |
| NDA_signed_all_clients.zip | 8,847,221 |
| salary_bands_2024.xlsx | 184,332 |
| encryption_keys_backup.zip | 2,104,887 |
| **Total** | **11,384,881** |

a) Convert the total to MB. Given USB 2.0 transfer speeds (~25 MB/s theoretical, ~10 MB/s real-world), how long would this transfer take? Does that fit within the 13-minute 46-second window?

b) `encryption_keys_backup.zip` for a document encryption SaaS is the most sensitive file stolen. What could an attacker do with encryption key backups for a company whose clients include law firms and hospitals?

---

## Evidence File 4 — Staff Interviews & The Twist

### Section A: Interview Summaries — conducted by HR + external investigator

**Aryan Kapoor (Sysadmin) — interviewed 2024-04-09 10:00 IST**
> Denies all involvement. Provided alibi (food delivery, phone call, gate log). Appeared
> nervous when asked about VAULT-WS-014 specifically. Said he "sometimes uses that machine
> when his primary workstation is slow." Could not explain why his credentials were used.
> Suggested a keylogger or credential phishing attack on his account.

**Rahul Sharma (DevOps Lead) — interviewed 2024-04-09 11:00 IST**
> Confirmed he was in the server room at 21:14. Said he noticed nothing unusual.
> When shown the CCTV timestamp of the unknown person (19:32), said he had left
> the office by then. Badge records confirm his last exit before 21:14 was at 09:02.
> **Gap unaccounted: 09:02 to 21:14 — over 12 hours.** Rahul says he "worked from
> home all day and came back to fix a deployment issue."

**Divya Menon (CTO) — interviewed 2024-04-09 11:45 IST**
> Confirmed server room access at 11:15–11:38. Not a suspect for the evening breach.
> Noted that Aryan had asked her two weeks ago about "which workstations had network
> share access to the contracts folder." Said she thought nothing of it at the time.

**Preethi Nair (Infra Engineer) — interviewed 2024-04-09 12:30 IST**
> Confirmed her 16:41–16:58 server room visit. Mentioned she had noticed a
> **USB device left plugged into VAULT-WS-014** during her visit but assumed
> it was someone's charger. Did not remove it or report it.

### Section B: The Alibi — Technical Breakdown

Aryan's alibi proves he was **physically at home** between 18:38 and 19:49 IST.

But look at EventID 4624 again:
```
Logon Type: 3 (Network logon)
Source IP:  10.0.1.44
```

Logon Type 3 is a **network logon** — it does not require the account holder to be
physically present at the workstation. It only requires that someone authenticated
over the network using Aryan's credentials.

**The alibi proves Aryan was home. It does not prove Aryan's credentials weren't used
by someone else who was physically in the office.**

This means two scenarios remain equally valid:
- Aryan is innocent — someone stole his credentials and used them remotely
- Aryan is complicit — he gave credentials to an outside attacker who did the physical work

### Section C: The Real Question — Insider, Outsider, or Both?

**Evidence pointing to Aryan as complicit:**
- The CTO says Aryan asked specifically which workstations had contracts folder access — 2 weeks before the attack
- `stager.ps1` was created March 21st — 18 days pre-attack — requiring insider knowledge of the network share paths (hardcoded in the script)
- The attacker chose VAULT-WS-014 specifically — an obscure, rarely-used workstation Aryan was known to use
- The USB was pre-installed at `14:01:33` during Aryan's `13:45–15:22` visit

**Evidence pointing to Aryan as innocent:**
- His alibi for 18:38–19:49 is verifiable through three independent sources
- A sophisticated attacker could have obtained share paths through other recon methods
- Credential theft via phishing or keylogger is technically plausible

### Challenge Questions — Evidence File 4

**Q1. The Alibi Paradox**

a) Aryan's alibi is real and verifiable. The network logon proves someone used his credentials. Write out both scenarios (innocent vs complicit) as a structured hypothesis with the supporting evidence for each. Which hypothesis has more technical support?

b) The CTO mentioned Aryan asked about contracts folder access "two weeks ago." `stager.ps1` was created on March 21st. The attack was April 8th. Build a timeline of attacker preparation starting from March 21st. What does this planning horizon suggest about motive?

c) If Aryan is complicit, what should the IR team's immediate next steps be regarding his access? List three specific actions — think about accounts, credentials, and access scope — that need to happen before he is formally confronted.

**Q2. The Physical Attacker**

a) Badge V-044 was issued but the register entry was torn out. The front desk CCTV was overwritten. The attacker spent 13 minutes 46 seconds inside. They knew which workstation to use, disabled AV, ran the payload, copied files, re-enabled AV, and left cleanly. Does this level of operational precision fit a random outsider or someone with inside knowledge?

b) Preethi Nair saw a USB device plugged into VAULT-WS-014 at 16:58 but didn't report it. Is Preethi a suspect, a negligent bystander, or a victim of a social engineering setup? What policy failure does her non-action reveal?

c) The physical attacker's face was obscured on CCTV. They knew the front desk camera had a 24-hour rolling overwrite. They tore out the visitor log entry. List three things a social engineer would need to know in advance to execute this level of physical breach. Where would they learn this information?

**Q3. Final Determination**

Based on all four evidence files, answer the following for the CISO briefing:

a) Was the physical attacker the same person as the credential user, or were there two actors?

b) Is Aryan Kapoor an insider threat, a credential theft victim, or both? State your conclusion and the three strongest pieces of evidence that support it.

c) The encryption key backups were stolen. Vaultify's clients include hospitals and law firms. What is the worst-case downstream impact if those keys are used maliciously?

---

## Final Deliverable — CISO Briefing

Write a 1–2 page briefing. All four parts are required.

---

### Part 1: Attack Timeline

Reconstruct every attacker action in chronological order in IST.  
All evidence files use IST already — no conversion needed this time.  
Cite the evidence file for each event.

```
[TIME IST] | [ACTION] | [SOURCE]
```

---

### Part 2: Impact Assessment

**a) Data stolen — calculate total volume**

| File | Bytes | MB |
|------|-------|----|
| client_master_list.xlsx | 248,441 | ? |
| NDA_signed_all_clients.zip | 8,847,221 | ? |
| salary_bands_2024.xlsx | 184,332 | ? |
| encryption_keys_backup.zip | 2,104,887 | ? |
| **Total** | **11,384,881** | **?** |

**b) Worst-case impact**

Vaultify encrypts documents for hospitals and law firms. The stolen `encryption_keys_backup.zip` could decrypt stored client documents. Answer the following:
- What two categories of sensitive client data could now be exposed?
- What is the risk to Vaultify's clients specifically — not Vaultify itself?
- What should the IR team do in the next 24 hours to limit downstream damage?

**c) Containment priority**

Rank these four containment actions in the order you would execute them and explain why:
- Revoke Aryan Kapoor's AD credentials
- Rotate the encryption keys in the stolen backup
- Isolate VAULT-WS-014 from the network
- Notify affected clients

---

### Part 3: Insider Threat Determination

State clearly: is Aryan Kapoor an **insider threat**, a **credential theft victim**, or **both**?

Support your conclusion with exactly three evidence items. Explain why Aryan's alibi does not resolve this question either way.

---

### Part 4: Control Gaps

Identify the **4 core security failures** that made this attack possible.

| Control Gap | Where It Failed | CompTIA Security+ Domain | Specific Fix |
|-------------|----------------|--------------------------|--------------|
| | | | |
| | | | |
| | | | |
| | | | |

---

### Bonus: Social Engineering Anatomy

The attacker demonstrated knowledge of:
- CCTV retention policy (24-hour rolling overwrite)
- Which workstation had network share access
- Aryan's keycard schedule
- The visitor badge system

Answer: How would a social engineer gather each of these four data points without ever entering the building? Be specific — name the technique for each.

---
