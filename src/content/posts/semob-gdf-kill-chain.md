---
title: "Root in Eight Weeks: Reconstructing a Chinese Operator's Kill Chain Through Brazil's Federal District Government Network"
description: "File timestamps preserved inside a 9.1GB archive found on a Chinese threat actor's staging server let us reconstruct a complete intrusion: WordPress web shell to DirtyPipe container escape, socat tunnelling, fscan credential spray across 164 government machines, and 754MB of internal GitLab source code — all in eight weeks."
pubDate: "2026-07-02T22:00:00"
permalink: "/2026/07/02/semob-gdf-kill-chain/"
tags: ["kill-chain", "mitre-attack", "brazil", "gdf", "semob", "dirtypipe", "cve-2022-0847", "fscan", "lateral-movement", "china", "behinder", "gitlab", "credential-spray", "wordpress", "open-directory", "threat-intel"]
---

In a [previous investigation](/2026/07/02/behinder-alibaba-brazil-staging/) we found a 9.1GB archive on a Chinese threat actor's open-directory staging server at `47.237.75.155` (Alibaba Cloud, Singapore). The file was named `semob.df.gov.br.tar.gz` — after Brazil's Federal District transport secretariat. The initial hypothesis was exfiltration or a phishing clone. Streaming the archive's contents without downloading all 9.1GB made the actual answer clear.

The file is the attacker's working directory. They left it on the SEMOB server, packed it up, and staged it thirteen months later. Inside: a DirtyPipe exploit, a statically compiled socat binary, an SSH private key, an RSA key extracted from process memory, fscan network sweep results for four internal government network segments, and 754MB of internal GitLab source code.

Tar preserves file modification timestamps, and the actor kept their working directory organised. That combination lets us reconstruct the intrusion with minute-level precision across its full eight-week active phase.

---

![GDF/SEMOB Kill Chain Diagram](/diagrams/semob-gdf-kill-chain.svg)

---

## Stage 1 — Initial Access: WordPress Web Shell
**ATT&CK: T1190, T1505.003**

The entry point was `semob.df.gov.br`. The site ran WordPress — visible in its content paths — which is an extremely common attack surface for government and NGO websites that lack dedicated web security teams. The exact vulnerability is not in the archive (that evidence lives in the web server access logs, which were not included), but the outcome is: a PHP web shell was placed on the server and the actor connected to it using **Behinder** (冰蝎, "Ice Scorpion"), a Chinese-developed web shell management framework that encrypts all C2 traffic, making it harder to detect in transit.

By December 21 the actor had root on the machine. The evidence is unambiguous: the first artifact they copied was `id_rsa`, a file only readable by root.

---

## Stage 2 — Credential Theft, Phase 1: SSH Private Key
**ATT&CK: T1552.004**
**December 21, 2024 · 14:44**

```
-r-------- root/root  2602  2024-12-21 14:44  semob.df.gov.br/id_rsa
```

The first thing the actor does with root access is copy the server's SSH private key. Permissions are `400` — read-only by root — confirming their privilege level. This key gives them a persistent, authenticated route back to the server that survives web shell removal, and potentially opens doors to other machines the SEMOB server was used to administer.

---

## Stage 3 — Discovery: Internal Network Recon
**ATT&CK: T1046**
**December 23, 2024 · 09:09**

```
-rw-r--r-- root/root  4229  2024-12-23 09:09  semob.df.gov.br/22br.txt
-rw-r--r-- root/root   599  2024-12-23 09:09  semob.df.gov.br/10.230.80-22-br.txt
```

Two days after stealing the SSH key, the actor scans the internal GDF network from inside the SEMOB server. Port 22 (SSH) across `10.230.80.x` — the main government server subnet. 45 hosts respond. The two output files serve different purposes: `22br.txt` is annotated (`10.230.80.212:22 open`) while `10.230.80-22-br.txt` is a clean IP-only list, the format fscan expects as brute-force target input. They already know where this is going.

---

## Stage 4 — Privilege Escalation: DirtyPipe, Container Escape, and Heap Dump
**ATT&CK: T1068, T1611, T1003.007**
**December 24, 2024 · 21:32–23:32**

Three activities on the same day, two hours apart:

**21:32 — CVE-2022-0847 (DirtyPipe).**

```
-rw-r--r-- root/root  6180  2024-12-24 21:32  CVE-2022-0847-Container-Escape/dp.c
-rwxr-xr-x root/root 17152  2024-12-24 21:33  CVE-2022-0847-Container-Escape/a.out
```

`dp.c` was cloned at 21:32. `a.out` — the compiled binary — was written one minute later. 60 seconds on a remote server suggests a scripted, practiced operation. DirtyPipe is a 2022 Linux kernel vulnerability that lets an unprivileged process write to read-only files by abusing the kernel's pipe-splice mechanism. In container environments — which modern web hosting almost universally uses — the canonical exploit path overwrites a SUID binary on the **host** filesystem from inside the container, granting root outside the container boundary. The `slides-zh.pdf` bundled in the same repository is a Chinese-language conference presentation on the technique, confirming the operator sourced this toolkit from Chinese security research communities.

**21:47 — socat.**

```
-rwxr-xr-x root/root 375176  2024-12-24 21:47  CVE-2022-0847-Container-Escape/socat
```

A statically compiled `socat` binary — 367KB, no system dependencies — uploaded 15 minutes after the compile. With container escape achieved, the actor now has a tool for building persistent encrypted tunnels from inside the GDF network to their external infrastructure. The `socat` binary is standard post-exploitation kit; its static compilation is the signature of deliberate operational tradecraft (no dependency on what's installed on the victim).

**23:32 — Heap dump RSA key.**

```
-rw-r--r-- root/root  1685  2024-12-24 23:32  semob.df.gov.br/heapdumprsa
```

Two hours after the container escape, a second RSA private key appears. The name "heapdumprsa" describes the technique: with full host access, the actor reads the memory of a running process — an SSH agent, an HTTPS web server, a certificate manager — via `/proc/PID/mem` or a `ptrace`-based dump, and extracts the raw private key bytes from the process heap. This bypasses disk-level private key protections: the key was never written to a file the attacker could just cat. It only existed in memory, and they went and got it.

---

## Stage 5 — Dwell: 45 Days Silent
**December 25, 2024 → February 6, 2025**

No file activity for 45 days. The actor maintained access — socat tunnels running, web shell persistent — but conducted no noisy scanning operations. **Chinese New Year 2025 (Year of the Snake) fell on January 29.** Chinese operators routinely go quiet over CNY. Activity resumed February 7 — nine days after the holiday — which is about as consistent a CNY break as you will find in a threat actor timeline.

---

## Stage 6 — Lateral Movement: fscan Fleet-Wide Credential Spray
**ATT&CK: T1046, T1110.003, T1021.004, T1021.002**
**February 7–11, 2025**

The actor deployed **fscan** (github.com/shadow1ng/fscan) — a Chinese-developed network scanner written in Go that combines port scanning, service fingerprinting, web vulnerability detection, and SSH/SMB credential brute-forcing in a single binary. Its output files contain inline Chinese-language strings (`跳转url` — "redirect URL") that make it straightforward to attribute. The scans ran from a pivot host at `10.233.44.45`, with results written back to the SEMOB server.

The sweep covered four segments over five days, one subnet at a time with machine-precision intervals:

| Dates | Segment | Scope |
|---|---|---|
| Feb 7–8 | `10.233.x.x` | 10.233.144.0/24, pivot host area |
| Feb 10–11 | `10.230.80–88.x` | 12 × /24 subnets · 279 live hosts · ~20 min per subnet |
| Feb 11 | `172.19.17–31.x` | 15 × /24 Docker/container subnets · ~8 min per subnet |
| Feb 11 | `10.233.35.x` + `172.15.x` | Application server segment + additional ranges |

The credential results collapsed the entire network. A single default support password, provisioned by IT teams and never rotated, worked across most of what fscan touched. A second password got into the Moodle e-learning server specifically.

```
SSH  root          → 41 Linux servers
SSH  suporte       → 36 Linux servers
SSH  moodle        → 1  Moodle e-learning server
SMB  administrator → 62 Windows machines
────────────────────────────────────────
                     164 total
```

The `-poc.txt` files fscan generates for each subnet record not just open ports but confirmed vulnerability triggers — Redis without auth, misconfigured web panels, and anything else fscan's module set can fingerprint. The 10.230.x.x and 172.19.x.x subnets produced substantial `poc.txt` output.

The `10.233.35.x` application server segment mapped a set of internal government systems:

| Host | Service | Notes |
|---|---|---|
| 10.233.35.7 | SIEDF | Sistema de Informações Estatísticas do DF — Federal District statistical data system |
| 10.233.35.11, .55 | RStudio Server Pro | Government data analytics environments — active R sessions with loaded datasets |
| 10.233.35.22 | Apache Tomcat 9.0.54 | 2021-era release; multiple unpatched CVEs |
| 10.233.35.36 | Brasília/DF em Dados | Open government data portal |
| 10.233.35.44 | vwponto | Employee time-tracking application |
| 10.230.86.31 | Apache Solr | Port 8983; fscan output shows Chinese redirect string on probe |

RStudio Server Pro is worth flagging: it hosts live R analytical sessions where government data scientists load, process, and model sensitive datasets. Access to those environments means access to whatever data was in memory at the time.

---

## Stage 7 — Collection: GitLab Source Code
**ATT&CK: T1213, T1560**
**February 12, 2025 · 13:24**

```
-rw-r--r-- root/root  789814227  2025-02-12 13:24  semob.df.gov.br/gitlab_source_code/1.tar.gz
-rw-r--r-- root/root          0  2025-02-12 14:23  semob.df.gov.br/gitlab_source_code/
```

Day six of the lateral movement phase. One day after the final fscan sweeps completed. The actor reached the GDF's internal GitLab instance — identified in the `10.233.35.x` application scan — and archived its repositories. 754MB compressed. The directory was finalised at 14:23, approximately one hour after the archive started writing — consistent with a bulk `git bundle` or GitLab export of all repositories, compressed on the fly.

Internal government GitLab is a high-value target: source code for citizen-facing services, database schemas, hardcoded credentials (common in government dev environments), internal API endpoint maps, authentication and session logic for GDF systems. The 754MB is a significant haul.

---

## Stage 8 — Archive and Anti-Forensics
**ATT&CK: T1560, T1070**
**March 12, 2025 · 23:30**

```
drwxr-xr-x root/root  0  2025-03-12 23:30  semob.df.gov.br/
```

Four weeks after the GitLab exfil, the entire working directory was packed into a single archive. The outer gzip wrapper shows deliberate metadata removal: `MTIME=0` (creation timestamp zeroed), `FNAME` field absent (filename stripped from the gzip header), OS byte = 3 (Linux). This is the equivalent of `gzip --no-name` — the kind of anti-forensics you apply when you don't want the archive's own header to expose when or where it was created.

The 9.1GB outer file is so large because the 754MB `gitlab_source_code/1.tar.gz` is already compressed — the outer gzip gains almost nothing from wrapping it. Pre-compressed data in, near-identical size out.

---

## Stage 9 — Staging and New Operations
**ATT&CK: T1583, T1608**
**April 10, 2026 (13 months later)**

The archive sat dormant for over a year before appearing on `47.237.75.155`. The 13-month gap is notable — it suggests the actor had other priorities, the data moved through an intermediate collection tier, or the GitLab source code was being actively used internally (vulnerability research, credential extraction) before the raw archive was staged for sharing or external access.

On the same server, across the same period:

| Date | Activity |
|---|---|
| 2025-10-02 | `Behinder_v4.1.t00ls.zip` — web shell toolkit staged for new campaigns |
| 2026-02-24 | `9990_072023.pdf` — malicious lure document |
| 2026-04-10 | `semob.df.gov.br.tar.gz` uploaded |
| 2026-05-17 | `tabby-1.0.234-setup-x64.exe` — likely trojanised terminal emulator |
| 2026-06-16 | `gpudrive.exe` — 3-stage .NET dropper, zero detections as of today |

The staging server is operational. The actor is running new campaigns from it right now. All three current files have zero detections.

---

## Attribution Indicators

| Indicator | Significance |
|---|---|
| Behinder (冰蝎) web shell manager | Chinese-developed, widely used by Chinese APT and criminal operators |
| T00ls distribution (`Behinder_v4.1.t00ls.zip`) | Chinese underground hacker forum — confirms Chinese offensive security community provenance |
| fscan (`github.com/shadow1ng/fscan`) | Chinese-developed Go scanner; inline Chinese output (`跳转url`) in result files |
| `slides-zh.pdf` | Chinese-language CVE-2022-0847 conference presentation bundled with exploit |
| Alibaba Cloud staging | AS45102, Chinese commercial cloud |
| Chinese New Year alignment | 45-day dwell period brackets CNY 2025 exactly; operations resume 9 days after Jan 29 |
| No Portuguese indicators | Zero Portuguese-language artifacts in any tooling — the operator's language is not Brazilian Portuguese |

---

## Full Chronology

```
Pre-Dec 21 2024  WordPress RCE → PHP web shell deployed (Behinder C2)
Dec 21  14:44    id_rsa copied (SSH private key, root/root, 400 perms)
Dec 23  09:09    SSH port scan → 45 hosts on 10.230.80.x (22br.txt, 10.230.80-22-br.txt)
Dec 24  21:32    CVE-2022-0847 repo cloned (dp.c)
Dec 24  21:33    a.out compiled (DirtyPipe binary, 17KB, 60 seconds)
Dec 24  21:47    socat uploaded (statically compiled, 367KB)
Dec 24  23:32    heapdumprsa extracted from process memory (RSA key, 1.6KB)
Dec 25 –         ─ ─ ─ ─ ─ ─ ─ ─ ─ 45-day dwell (Chinese New Year Jan 29) ─ ─ ─ ─ ─ ─ ─ ─ ─
Feb 06, 2025
Feb 07  20:00    fscan begins: 10.233.144.0/24 sweep
Feb 07  21:46    172.x.x.x initial sweep
Feb 08  10:29    172.19.16.0/24 Docker segment
Feb 08  17:16    172.19.17.0/24 + 172.15.x
Feb 10  12:04    10.230.80.0/24 main GDF server network
Feb 10  19:51    10.230.81-88.x (one subnet every ~20 minutes)
Feb 11  09:44    First scan set archived (10.233.44.45.tar.gz)
Feb 11  14:52    172.19.17–31.x Docker subnets (one every ~8 minutes)
Feb 11  16:59    10.233.35.x application servers + 172.15.x
                 → 164 confirmed credential hits total
Feb 12  13:24    gitlab_source_code/1.tar.gz written (754MB)
Feb 12  14:23    GitLab directory finalised (~1 hour for full export)
Mar 12  23:30    semob.df.gov.br.tar.gz packed (9.1GB, MTIME=0, FNAME stripped)
                 ─ ─ ─ ─ ─ ─ ─ ─ ─ 13-month gap ─ ─ ─ ─ ─ ─ ─ ─ ─
Apr 10, 2026     Archive staged on 47.237.75.155 (Alibaba Cloud SG)
Jun 16, 2026     gpudrive.exe staged (3-stage dropper, 0 detections)
Jul 02, 2026     This investigation
```

---

## What To Do

**If you are a GDF or SEMOB network defender:**

The timestamps in this archive give you precise dates to anchor your forensic investigation. December 21, 2024 is when root was first confirmed. The active scanning period ran February 7–11, 2025. GitLab access was February 12, 2025.

Specific checks:
- **Web server access logs for December 2024**: look for the initial WordPress exploitation and web shell upload in access logs for `semob.df.gov.br`
- **SSH key audit**: identify any `id_rsa` files with `root/root` ownership and `400` permissions that were not provisioned by your team; rotate all SSH keys
- **GitLab audit logs**: check for bulk export or repository clone operations on February 12, 2025, especially around 13:00–14:30 Brasília time (UTC-3)
- **Credential reset**: any account that shared the GDF default support password — across Linux (`root`, `suporte`, `moodle`) and Windows (`administrator`) — needs immediate rotation
- **socat on Linux servers**: `socat` is not a standard system package; any instance present on GDF Linux servers is a red flag
- **RStudio Server access logs**: Feb 7–11 access to the RStudio instances at `10.233.35.11` and `10.233.35.55` should be reviewed for unauthorised sessions

**If you are running a response:**

Report to CERT.br (`cert.br`) — they coordinate with Brazilian state-level entities including GDF. The archive is publicly accessible at `http://47.237.75.155/semob.df.gov.br.tar.gz` and will remain there until someone takes down the staging server or the actor removes it.

**Detection: fscan on the network:**

fscan produces characteristic output files with the naming convention `<subnet>-poc.txt`. On Linux systems, look for these in unusual directories (e.g., web server document roots, `/tmp`, home directories of web service accounts). fscan binaries are typically named `fscan`, `fscan64`, or similar, and are statically compiled ELF binaries around 6–8MB.

**Detection: DirtyPipe (CVE-2022-0847):**

The compiled `a.out` (17KB ELF) in the archive will match the SHA256 of the public CVE-2022-0847 PoC. Kernel versions 5.8 through 5.16.11, 5.15.25, and 5.10.102 are vulnerable. Check `uname -r` across your Linux fleet and patch.

---

## IOC Summary

```
47.237.75.155   # Alibaba Cloud SG — active staging server
```

| File | SHA256 | Notes |
|---|---|---|
| `semob.df.gov.br.tar.gz` | `dc6f5f7f987d6ce451fab5d86e286fdb88b32ee81de5349b1fc4a8f008514731` | 9.1GB; attacker toolkit + GDF breach evidence |
| `gpudrive.exe` | `ad154d012449a585fe247c20d8503ab6c86d3167ebb3d29698900b46a64c9c44` | 933MB 3-stage dropper; 0 detections |
| `tabby-1.0.234-setup-x64.exe` | `6cb121911cb700c09fff8ea14fb709c7df6d9e69e05ad2909adc0eedac3684fe` | 143MB; likely trojanised |
| `9990_072023.pdf` | `135a23b4eb294cb9e4cb81e2f01031551a6dcc03fed183d95c11afcc0dd72210` | Malicious lure; Criminal IP: malicious |

---

*Passive analysis: VirusTotal file/URL/IP history, Shodan, HTTP Range byte inspection, streaming tar listing. No full archive download. No live C2 contact. No credentials tested or used. Internal GDF IP addresses and specific credentials are withheld from publication.*
