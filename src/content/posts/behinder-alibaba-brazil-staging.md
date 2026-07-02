---
title: "Ice Scorpion on Alibaba: A Chinese Operator's Singapore Staging Server, 164 Compromised Brazilian Government Machines, and a 933MB Fake GPU Driver"
description: "A Shodan hit on an Alibaba Cloud Singapore IP leads to a 9.1GB archive that turns out to be an attacker's working directory from inside a compromised Brazilian government server — containing a DirtyPipe exploit, fscan lateral movement results across the GDF internal network, 164 confirmed credential compromises, and 754MB of exfiltrated GitLab source code."
pubDate: "2026-07-02T20:00:00"
permalink: "/2026/07/02/behinder-alibaba-brazil-staging/"
tags: ["behinder", "bingxie", "ice-scorpion", "china", "alibaba-cloud", "singapore", "open-directory", "brazil", "semob", "staging-server", "threat-intel", "gpudrive", "sfx-dropper", "dirtypipe", "cve-2022-0847", "fscan", "lateral-movement", "brazil-government", "gdf"]
---

Another Singapore open directory. Same Shodan query — `http.title:"Index of /" country:SG http.html:.exe` — different IP: `47.237.75.155`. This one is on Alibaba Cloud, AS45102, running Apache/2.4.52 on Ubuntu. Three files:

```
Index of /

gpudrive.exe               2026-06-16 19:52    933M
semob.df.gov.br.tar.gz     2026-04-10 17:07    9.1G
tabby-1.0.234-setup-x64.exe  2026-05-17 18:27   143M
```

The sizes alone are unusual. A 933MB executable and a 9.1GB archive named after a Brazilian government transportation agency, on a Chinese cloud IP with no hostname, no business purpose, and no Shodan tags beyond `open-dir` and `cloud`. VirusTotal's URL history for the IP explains what the directory listing is a fragment of.

---

## Behinder

The first URL flagged malicious by VirusTotal for this IP is not one of the three current files. It is:

```
http://47.237.75.155/Behinder_v4.1.t00ls.zip
```

Archived by VT on **October 2, 2025**. Criminal IP rated it malicious. The filename is diagnostic on two levels.

**Behinder** (冰蝎, Bingxie — "Ice Scorpion") is a Chinese-language web shell management framework. It provides an operator console for connecting to and managing web shells dropped on compromised servers — Java, PHP, .NET, Python, and others are all supported. It encrypts its traffic by default, making it harder to detect over the wire than older shells like China Chopper. Behinder is open-source and developed primarily by Chinese security researchers, but it has become a fixture in Chinese APT campaigns: APT40, APT41, and a range of financially motivated Chinese threat clusters have all used it.

**T00ls** (stylised `t00ls`, pronounced "tools") is one of China's longest-running underground hacker forums, where Chinese offensive security practitioners, vulnerability researchers, and cybercriminals share tools, exploits, and tradecraft. Software named for T00ls puts the user firmly in Chinese offensive security circles.

`Behinder_v4.1.t00ls.zip` means exactly what it says: version 4.1 of Ice Scorpion, from T00ls. It is a toolkit, not a credential stealer or ransomware — it is what an operator uses to manage machines they have already compromised.

Four months after Behinder appeared on the server, VirusTotal recorded another URL:

```
http://47.237.75.155/9990_072023.pdf
```

**February 24, 2026**. Criminal IP rated it malicious. SHA256: `135a23b4eb294cb9e4cb81e2f01031551a6dcc03fed183d95c11afcc0dd72210`. VT's own engines returned zero detections — only Criminal IP's heuristics caught it. The `9990_072023` pattern suggests an internal tracking number, the kind used in lure documents for government or enterprise phishing chains.

A Behinder operator hosting a suspicious PDF two months after deploying their web shell toolkit, on a server with no legitimate business footprint, is not coincidence. It is workflow.

---

## The 9.1GB Archive

The original hypothesis was exfiltration or phishing clone. Streaming the archive's contents without downloading the full 9.1GB resolves the ambiguity — and the answer is worse.

`semob.df.gov.br.tar.gz` is not a website backup. It is the attacker's working directory from inside a compromised server belonging to the Secretaria de Estado de Mobilidade do Distrito Federal — the Brazilian Federal District's state transport secretariat, the body that manages road and public transport infrastructure in and around Brasília.

```
semob.df.gov.br/
├── id_rsa                           2024-12-21  — server SSH private key
├── 22br.txt                         2024-12-23  — SSH open-port target list
├── 10.230.80-22-br.txt              2024-12-23  — internal network SSH targets
├── heapdumprsa                      2024-12-24  — RSA key extracted from heap dump
├── CVE-2022-0847-Container-Escape/  2024-12-24
│   ├── dp.c                                     — DirtyPipe exploit source
│   ├── a.out                                    — compiled DirtyPipe binary (17KB)
│   ├── socat                                    — tunnel/reverse shell tool (367KB)
│   └── slides-zh.pdf                            — Chinese-language CVE-2022-0847 slides
├── fscan10.233.44.45/               2025-02-07 to 2025-02-11
├── 10.230fscan/                     2025-02-10 to 2025-02-11
├── 172.19fscan/                     2025-02-11
├── 17215and10.233.35/               2025-02-11
└── gitlab_source_code/
    └── 1.tar.gz                     2025-02-12  — 754MB of internal GitLab source
```

The 9.1GB outer file is so large because the 754MB GitLab archive inside it is already compressed — the outer gzip has almost nothing to compress and ends up close to the raw tar size.

### Attack timeline

File timestamps, preserved in the tar metadata, reconstruct the intrusion:

**December 21, 2024 — Initial access.** The attacker has root on the SEMOB server and copies `id_rsa`, the host's SSH private key. Permissions preserved in the archive: `400` (read-only by owner) — this is the private half of the server's SSH keypair.

**December 23, 2024 — Reconnaissance.** SSH port-scan results are written to file: a target list of hosts in the `10.230.80.x` internal GDF subnet responding on port 22.

**December 24, 2024 — Privilege escalation and post-exploitation.** Three things happen on the same day:

CVE-2022-0847 ("DirtyPipe") is deployed. This 2022 Linux kernel vulnerability lets an unprivileged process overwrite the content of read-only files — the canonical exploit path gives a container or restricted user full root on the host. The git repository cloned here includes compiled binary (`a.out`) and `socat`, a networking utility commonly used by attackers for tunnel creation and reverse shells. The `slides-zh.pdf` is a Chinese-language conference presentation on the DirtyPipe technique — this toolkit was sourced from Chinese security research communities.

Alongside the exploit, `heapdumprsa` is written (1.6KB, two hours after the main CVE files). "Heapdump" + RSA key is a technique: with root access, the attacker reads the memory of a running process — an SSH agent, a web server, a certificate manager — and extracts the raw private key bytes from its heap. The result is a private RSA key that was never written to disk in accessible form, bypassing filesystem-level key protection.

**February 7–11, 2025 — Lateral movement across the GDF internal network.** Using fscan (github.com/shadow1ng/fscan, a Chinese-developed scanner written in Go), the attacker sweeps four network segments over five days. The tool's output files contain the Chinese string `跳转url` ("redirect URL") inline — a reliable indicator of the specific tool's provenance.

The four scan targets cover the Governo do Distrito Federal's server estate:

- `10.233.44.45` and `10.233.144.0/24` — an infrastructure segment
- `10.230.80.x` through `10.230.88.x` — twelve /24 subnets (the GDF main server network)
- `172.19.17.x` through `172.19.31.x` — fifteen /24 subnets of Docker/container infrastructure
- `172.15.2.x` and `10.233.35.x` — additional infrastructure segments

The scan results show credential compromise at scale. A single default support credential — one that had been reused across user accounts and machine roles throughout the estate — was valid across most of the network. The fscan output records **over 160 unique confirmed credential successes**:

- SSH `root` access on **41 Linux servers** across multiple subnets
- SSH user access on **61 additional Linux hosts**
- Windows SMB `administrator` access on **62 Windows machines**

Every subnet produced hits. The credential spread suggests an IT support team that provisioned machines with a shared default and did not rotate it. The attacker did not need to exploit vulnerabilities to move laterally — the password opened doors fleet-wide.

Internal web services mapped by the scans include:

| Host segment | Service | Notes |
|---|---|---|
| 10.230.86.x | Apache Solr | Search index platform; exposed on port 8983 |
| 10.230.88.x | Windows IIS | Default IIS page on port 443 |
| 10.233.35.x | RStudio Server Pro | Two hosts; login page accessible |
| 10.233.35.x | Apache Tomcat 9.0.54 | 2021-era release; default welcome page |
| 10.233.35.x | SIEDF | Sistema de Informações Estatísticas do DF |
| 10.233.35.x | Brasília/DF em Dados | Government open data portal |
| 10.233.35.x | vwponto (port 8080) | Employee time-tracking application |

RStudio Server Pro is notable: it hosts R-based analytical environments where government data scientists store, process, and analyse sensitive datasets. Access to those environments means access to whatever data was loaded in active sessions.

SIEDF — the Federal District's Statistical Information System — is a core government data platform for the Brasília metropolitan area.

**February 12, 2025 — Source code exfiltration.** `gitlab_source_code/1.tar.gz` (754MB) is written to the working directory. The actor has reached the GDF's internal GitLab instance and archived its repository contents. Internal source code may contain hardcoded credentials, internal API endpoints, authentication logic, and database schemas for government services.

**March 12, 2025 — Pack and prepare.** The entire working directory is compressed into `semob.df.gov.br.tar.gz`.

**April 10, 2026 — Staging.** Thirteen months after packing, the 9.1GB archive appears on `47.237.75.155`. The gap between collection and staging suggests the actor either had other priorities, was working a longer-term operation, or moved data between infrastructure tiers before centralising it here.

---

## `gpudrive.exe` — A 933MB Staged Dropper

The most recently added file — June 16, 2026 — has the most interesting internal structure.

Magic bytes: `4d 5a 60 00` — a PE executable with a non-standard DOS stub. The `60 00` at offset 2 (`e_cblp`) is not the Windows-standard `90 00` value. That is not how Windows compilers write DOS stubs — it marks a custom packer or SFX builder.

A string buried at offset ~760KB inside the file reveals its outer structure:

```
C:\dvs\p4\build\sw\dev\cm\pfw\dev_a\cm\SFX\Output\Win32\7zSfxMod.pdb
```

This PDB path is from 7-Zip's own self-extracting module source code. The outer layer of `gpudrive.exe` is a 7-Zip SFX stub — a modified extractor that runs first and decompresses payload.

But reading the binary reveals a second PE header at approximately offset 760KB, this time with the standard `4d 5a 90 00` DOS stub. PE header analysis on this inner executable shows:

```
Machine:    x86 (0x014c)
Timestamp:  2025-07-03 13:32:18 UTC
CLR RVA:    0x000bcd90
```

A non-zero CLR runtime header RVA confirms this inner PE is a **.NET assembly** — MSIL bytecode, not native code. The architecture is:

1. **Outer layer**: native x86 7-Zip SFX stub (modified DOS stub, `7zSfxMod.pdb`)
2. **Embedded inner PE** at ~760KB: .NET x86 assembly, compiled July 3, 2025
3. **Encrypted bulk payload**: the remaining hundreds of megabytes, fully encrypted — no readable strings, no recognisable magic bytes anywhere in the last 64KB of the file

This three-stage structure is deliberate. The SFX wrapper provides a plausible installer appearance ("GPU Drive" — a driver or utility). The inner .NET PE handles decryption and execution of the actual payload. The encrypted bulk is whatever the actor wants delivered: a RAT, a miner, a backdoor, a complete legitimate software bundle to sell the disguise.

Zero detections on VirusTotal as of July 2, 2026. The URL scan of `http://47.237.75.155/gpudrive.exe` submitted today returned clean across all engines.

---

## `tabby-1.0.234-setup-x64.exe` — Developer Lure or Legitimate Copy?

The third file — 143MB, May 17, 2026 — matches the version number and approximate size (130–150MB) of a legitimate release of Tabby, the open-source terminal emulator. Tabby is widely used by developers and system administrators.

The legitimate Tabby 1.0.234 installer for Windows x64 is signed by its developers. A trojanized copy would either lack the signature or carry a forged one. Passive analysis via HTTP Range bytes shows the file opens with `4d 5a` (PE), which is expected, but signature verification requires downloading the binary.

No VT records exist for this specific file. It cannot be confirmed as trojanized through passive analysis alone. Given the SEMOB compromise specifically targeted a server running government web infrastructure, a trojanized Tabby — aimed at Linux/Windows sysadmins who use terminal emulators for SSH management — would be a logical follow-on lure against the same target class.

---

## Timeline

| Date | Event |
|---|---|
| 2024-12-21 | Initial access to SEMOB server; SSH private key copied (`id_rsa`) |
| 2024-12-23 | SSH port-scan of GDF 10.230.80.x subnet; target lists written |
| 2024-12-24 | DirtyPipe exploit deployed; socat staged; RSA key extracted from heap dump |
| 2025-02-07 | fscan begins: 10.233.x.x network sweep |
| 2025-02-10 | fscan: 10.230.80.x–88.x twelve-subnet sweep (113+ hosts in .80 alone) |
| 2025-02-11 | fscan: 172.19.x.x Docker network sweep (15 subnets) + 172.15.x.x, 10.233.35.x |
| 2025-02-12 | Internal GitLab source code exfiltrated (754MB) |
| 2025-03-12 | Working directory packed into `semob.df.gov.br.tar.gz` |
| 2025-10-02 | `Behinder_v4.1.t00ls.zip` appears on 47.237.75.155 (VT: Criminal IP malicious) |
| 2026-02-24 | Malicious PDF `9990_072023.pdf` staged on same IP |
| 2026-04-10 | `semob.df.gov.br.tar.gz` uploaded to 47.237.75.155 |
| 2026-05-17 | `tabby-1.0.234-setup-x64.exe` staged |
| 2026-06-16 | `gpudrive.exe` staged |
| 2026-07-02 | *(this investigation)* — 0 detections on all three active files |

---

## Infrastructure

| Property | Value |
|---|---|
| IP | `47.237.75.155` |
| ASN | AS45102 — Alibaba Cloud LLC |
| Hostname | None |
| Country | Singapore |
| OS | Ubuntu Linux |
| Web server | Apache/2.4.52 on port 80 |
| SSH | OpenSSH 8.9p1 on port 22 |
| Port 443 | 404 (not in use) |
| First malicious URL seen | 2025-10-02 |
| Active files | 3 (9.1GB archive + 2 executables) |
| Current detections | 0 |

---

## Attribution Indicators

The Chinese provenance indicators across this investigation are consistent:

- **Behinder + T00ls**: Chinese web shell management framework from a Chinese underground forum
- **fscan**: Chinese-developed network scanner (github.com/shadow1ng/fscan, written in Go); output contains Chinese-language strings inline (`跳转url`)
- **slides-zh.pdf**: Chinese-language CVE-2022-0847 presentation bundled with the exploit toolkit
- **Alibaba Cloud staging**: AS45102 is the commercial arm of an PRC state-adjacent cloud provider
- **No Portuguese indicators in any tooling**: the operator left no Portuguese-language artifacts — the victim network, not the operator's language, is what's in Portuguese

---

## IOC Summary

**Active staging — zero detections:**

| File | Size | SHA256 | Date |
|---|---|---|---|
| `gpudrive.exe` | 933MB | `ad154d012449a585fe247c20d8503ab6c86d3167ebb3d29698900b46a64c9c44` | 2026-06-16 |
| `semob.df.gov.br.tar.gz` | 9.1GB | `dc6f5f7f987d6ce451fab5d86e286fdb88b32ee81de5349b1fc4a8f008514731` | 2026-04-10 |
| `tabby-1.0.234-setup-x64.exe` | 143MB | `6cb121911cb700c09fff8ea14fb709c7df6d9e69e05ad2909adc0eedac3684fe` | 2026-05-17 |

**Historical files (no longer present, confirmed malicious):**

| File | SHA256 | Flagged |
|---|---|---|
| `Behinder_v4.1.t00ls.zip` | (URL hash only; content no longer accessible) | Criminal IP: malicious |
| `9990_072023.pdf` | `135a23b4eb294cb9e4cb81e2f01031551a6dcc03fed183d95c11afcc0dd72210` | Criminal IP: malicious |

**Infrastructure:**
```
47.237.75.155   # Alibaba Cloud SG — active staging, Behinder operator
```

---

## What To Do

**Block at perimeter:**
```
47.237.75.155
```

**Hunt for the GPU driver lure** — look for downloads of `gpudrive.exe` on endpoints:
```powershell
Get-ChildItem -Path C:\Users -Recurse -Include "gpudrive*.exe","GPUDrive*.exe" |
  ForEach-Object { Write-Output "$($_.FullName) — $($_.Length) bytes" }
```

**If you operate government or enterprise infrastructure in the Brasília / Federal District area:**
- Audit SSH key trust — `id_rsa` files with unusual permissions or unknown origin on Linux servers
- Check for `socat` or `fscan` binaries on Linux servers (these are not standard system tools)
- Review Apache Solr, RStudio Server, and Tomcat instances for unauthorized access since December 2024
- Rotate any credential that may have been provisioned with a shared default support password
- Check GitLab (internal or cloud) audit logs for bulk repository downloads in February 2025

**YARA — 7-Zip SFX dropper with non-standard MZ stub:**
```yara
rule SFX_NonStandard_MZ_Dropper {
    meta:
        description = "7-Zip SFX dropper with modified DOS stub (e_cblp != 0x90)"
        reference   = "47.237.75.155 gpudrive.exe 2026-07-02"
    strings:
        $sfx_pdb = "7zSfxMod.pdb" ascii
        $sfx_str = "7zG.exe" ascii
    condition:
        uint16(0) == 0x5A4D and
        uint8(2) != 0x90 and
        1 of ($sfx_*)
}
```

---

The story changed when the archive was opened. What looked like exfiltrated data or a phishing clone turned out to be an operator's working directory — the record of a systematic intrusion that started with a compromised web server in December 2024 and expanded, over eight weeks, to root access on over 100 Linux servers, Windows administrator on 62 machines, and the contents of an internal GitLab instance. All of it sat packaged on an Alibaba Cloud server for thirteen months before we found it.

All three current files on 47.237.75.155 have zero detections. The Behinder and PDF are gone from the server but remain in VirusTotal's URL history. The operator cleaned up their toolkit, left the archived evidence of a major government compromise and a fresh dropper in place, and the server is still serving.

---

*Passive analysis: VirusTotal file/URL/IP history, Shodan, HTTP Range byte inspection, streaming tar listing (no full download). No live C2 contact. No credentials tested or used. Internal GDF network details are summarised at the subnet level only; specific internal IP addresses and credentials are withheld.*
