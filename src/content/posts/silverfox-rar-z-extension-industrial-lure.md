---
title: "Silverfox Dropper Campaign: Three Lures, One C2, Gambling Infrastructure"
description: "A RAR renamed .z to bypass filters drops a Silverfox InnoSetup installer with a spreader payload. Three lures in one campaign: industrial safety training, a Chinese company seal, and an HR recruitment form. The C2 IP hosted Chinese gambling sites from late 2023 into early 2024."
pubDate: "2026-07-01T12:00:00"
permalink: "/2026/07/01/silverfox-rar-z-extension-industrial-lure/"
tags: ["Threat Intel", "Silverfox", "Dropper", "Infrastructure", "InnoSetup", "Spreader"]
draft: false
---

[@smica83](https://x.com/smica83) flagged it as FUD: a RAR archive submitted from Cambodia with one detection on VirusTotal. The filename — `Industrial_Safety_and_Risk_Management_in_the_Industrial_Sector_Online.rar` — is long enough to truncate in most file dialogs. The extension isn't `.rar`.

It's `.z`.

That's not a coincidence. `.z` is the extension for the old Unix `compress` format — nothing to do with RAR. But the archive is RAR v5. Renaming it flips the file association away from WinRAR and kills any security product relying on extension-based filtering. When the victim double-clicks it, Windows either opens it with whatever archive handler is installed or prompts for an app. In a corporate environment where 7-Zip handles everything, it opens fine. The contents look like a document.

---

## The lure

`Industrial Safety and Risk Management in the Industrial Sector Online Training Course docx.exe`

Twenty words. Long enough that the `.exe` extension is off-screen in a standard Windows Explorer column. The file icon would need to be checked explicitly. This isn't a zero-effort campaign.

But this wasn't the first lure. When I queried `qishuiwg.com` — the C2 domain — against VirusTotal's communicating files, three more samples came back:

| Filename | Hash (first 16) | First seen | VT det |
|---|---|---|---|
| `1Employee recruitment application form.z` | `b4d4ab01efb60f51` | 2026-06-23 | 11/74 |
| `Seal of Xinrui Co Ltd.pdf.z` | `50cef8584d913e87` | 2026-06-24 | 17/75 |
| `Industrial_Safety_..._Online.z` | `6b05b09d13cbb81a` | 2026-06-30 | 19/75 |
| unnamed | `db550412b5e80035` | 2026-06-14 | 39/76 |

The unnamed file from June 14 is the oldest, and it has the most detections — because it's had more time to accumulate them. The operator was running this campaign for two weeks before @smica83's tweet.

Three distinct lures, but one actor: every dropper EXE inside these archives shares the same imphash (`40ab50289f7ef5fae60801f88d4541fc`) and the same spoofed PE compile timestamp (`2024-06-10`). Same build, same toolchain, different bait.

The lures tell you who's being targeted:

- **Industrial safety training** — manufacturing floor workers, HSE officers, anyone in a company that does compliance training
- **Employee recruitment form** — job applicants, HR staff, companies hiring
- **Seal of Xinrui Co Ltd** — this one is specifically Chinese business context. A corporate seal (公章) carries legal weight equivalent to a signature in Chinese commercial practice. An accountant, a procurement officer, anyone processing contracts with a Chinese supplier would expect to see a document with this title. "Xinrui" (新锐) is a real Chinese company name pattern.

Cambodia is where the sample came from. Southeast Asia is where the campaign is running. The targets are the kind of workers who get documents from outside the organisation and open them without thinking too hard about it.

---

## Stage one: InnoSetup dropper

The EXE inside the archive is an InnoSetup installer wrapped around the Silverfox dropper. InnoSetup is a legitimate Windows installer framework — the host binary looks like a normal software package, and a lot of endpoint products give it the benefit of the doubt.

Kaspersky identifies the family as `Trojan-Dropper.Win32.Silverfox` across multiple variants. ESET tags all of them `Win64/Kryptik.GXY`. Rising calls the shellcode loader component `Trojan.ShellCodeLoader!1.12EA8`.

Every sample carries the same two sandbox evasion tags: `detect-debug-environment` and `long-sleeps`. The dropper checks if it's in a sandbox before doing anything useful, then sleeps long enough that time-limited analysis gives up and reports nothing. That's why the newest lure was 1/75 when @smica83 flagged it — sandboxes saw a well-behaved installer sit still, most AV products agreed, and only a handful of signature engines caught it.

Dropped artifacts from InnoSetup execution:

```
PrintBrmEng.exe              → 36/75, tagged: spreader, pedll
EaEqxXoi.sys                → alternate name for same file
VUgpmcRwgdh.exe             → 2/75, %LOCALAPPDATA%\Local\assembly\dl3\BvP4Z5\obR2\n4V8h\dsfL3\
_isetup\_setup64.tmp        → InnoSetup helper (clean)
```

`PrintBrmEng.exe` is the standout drop. The name clones a real Windows binary — the Print Branch Migration Engine. VT sandbox tags it as a **spreader**: it propagates laterally across the network. It's a DLL, not a standalone EXE, so it needs to load into another process to run. A spreader DLL masquerading as a print service component is doing SMB share enumeration or credential reuse — moving sideways the moment it gets a foothold.

`VUgpmcRwgdh.exe` drops into a path that mimics the .NET Assembly cache (`%LOCALAPPDATA%\Local\assembly\dl3\...`). Glance at it in a process list and it reads as a legitimate .NET deployment. The random filename doesn't help it stand out either.

---

## The C2: qishuiwg.com

The domain was registered on 2026-06-06 through NameSilo, with nameservers at `NS1.DOMAINNAMENS.COM` and `NS2.DOMAINNAMENS.COM`. It resolved to `154.23.184.251` eight days later, on June 12 — two days before the first known sample.

The IP is in Hong Kong, ASN AS140227 (Hong Kong Communications International Co., Limited), on STARCLOUD GLOBAL PTE. LTD. infrastructure — a Singapore-registered provider with a large IP block that shows up repeatedly across Southeast Asian cybercrime operations.

VirusTotal flags the IP with 2/91 detections, but the TLS certificate cached on the server tells a more interesting story. It's a Cloudflare Origin Certificate — the kind you install on an origin server when the public-facing traffic goes through Cloudflare's CDN — and it's issued for `*.bbpicdance.info` and `bbpicdance.info`.

That domain was registered in 2016 via GoDaddy to a Chinese registrant (WHOIS fields use hashed privacy values, but registrant country is China). It expired in April 2021 and was never renewed. The Cloudflare Origin Cert on this server is a leftover — at some point before this campaign, the same physical server was used for `bbpicdance.info`, pointing traffic through Cloudflare. The operator recycled the infrastructure but left the old cert in place.

---

## The IP's previous life: Chinese gambling infrastructure

VT's resolution history for `154.23.184.251` goes back to late 2023. Every domain on that IP before `qishuiwg.com` is a Chinese online gambling site. The full list runs to 40 entries:

```
2023-11-19  99348ag.com / www.8550111.com
2023-11-21  318588ag.com / 77348pk.com / 77348ag.com / 99348bg.com
2023-11-26  hg348org0003k99348k.com / 508vip77348y99348w.com / 159000yhesunqingbetter.com
2023-11-28  855a1.app / 855a2.app / 855a3.app / 318588.xyz  (+ www. variants)
2023-11-29  855a6.app
2023-12-06  348a.app
2023-12-09  gg12322.com
2023-12-10  99348pk.com
2023-12-13  hg3800.cc
2023-12-14  855a666.com
2023-12-29  mgm118.xyz / m1377.com
2024-01-14  hg348bet-855a77-855a7.com
2024-01-22  855a.xyz
2024-03-17  2.easydream.bet
2026-06-12  qishuiwg.com          ← current C2
```

The patterns are recognisable. The `855a` cluster — eight variants from `855a1.app` to `855a666.com` — is one betting platform rotating through domains as they get blocked. The `99348` / `77348` / `hg348` group suffix their domains `ag`, `bg`, and `pk` — Asia Gaming, BG Gaming, poker. `mgm118` clones the MGM casino brand. The concatenated `508vip77348y99348w.com` encodes multiple brand codes in a single URL, which is what affiliate redirect links look like in this ecosystem.

The account ran Chinese online gambling infrastructure from November 2023 to March 2024, then sat quiet for over two years before the Silverfox C2 domain showed up in June 2026. That gap isn't unusual — hosting accounts in this space get resold, passed between operators, or parked until someone needs a server with an established IP.

The /24 neighbourhood fills in the rest. Shodan returns 210 results for `154.23.184.0/24`. The node at `.61` is running over a dozen Ncat proxies on non-standard ports, each one fronting a different gambling domain:

```
154.23.184.61  :8443 988033.com  :443 3637365.com  :8605 866vip8.vip
               :8467 394394.cc   :8023 qt.b6oi2u8y.com
               :9090 b90app2.cc  :8899 wap.3637365.com
               :8906 haoke696a124u9789.app  :8819 befi77.org  …
```

The node at `.117` hosts `bilibili.accountuserhub.com` — a credential-phishing domain targeting users of Bilibili, China's dominant video platform.

The C2 at `.251` isn't a dedicated actor server. It's one slot in a shared operation where gambling proxies, Bilibili phishing, and a Silverfox C2 all live on the same /24.

---

## Putting it together

The campaign started on or before June 14, when the first unnamed sample appeared on VT. The domain was fresh — eight days old. The operator ran three separate lures over the following two weeks before one of them surfaced publicly via a threat researcher's tweet.

The `.z` rename is a simple trick. The InnoSetup wrapper keeps signature detection quiet. The sandbox evasion means dynamic analysis comes back clean. By the time someone double-clicks the file, the chain is designed to clear every automated layer between delivery and execution.

The spreader component means one infection isn't the end goal. A workstation that runs `PrintBrmEng.exe` is a foothold, not a destination.

The targets follow from the lures: manufacturing workers, HR staff, business contacts handling Chinese supplier documents. These are people who receive files from outside the organisation and open them as part of their job. They're also the people who sit inside networks with access to OT systems, HR databases, and finance records once they're compromised.

Two years of gambling infrastructure, then a switch to malware C2. The server moves on, the hosting account persists, and whatever operator needed cheap infrastructure found one with a long history and zero reputation flags. That's the ecosystem in play here.

---

## IOCs

### Hashes — Stage 1 (RAR archives, extension .z)
```
6b05b09d13cbb81ab4246b98f35b49f6915d31f140acacf6d42e260066fed543  Industrial_Safety_...Online.z
50cef8584d913e87586d8ccfbc0a2858926faebedcfb6defb1e40a4ea4e05206  Seal of Xinrui Co Ltd.pdf.z
b4d4ab01efb60f51f3a799085511847007b1a49aa5248c756e1544261dc408e9  1Employee recruitment application form.z
```

### Hashes — Stage 2 (dropper EXEs, imphash 40ab50289f7ef5fae60801f88d4541fc)
```
765bfb5d7829184a23f615b871baebf893563d911dddd1d1c1a34604e5456cce  Industrial Safety...docx.exe
afbb03825856a497418ce316d731a5d40e17fc86654852bfd3527ef0367da101  Seal of Xinrui Co Ltd.pdf.exe
e10a2c99fc7fcf94ba2d35e494d4f498cf03e905e9e3c4335a04a235891e1a34  1Employee recruitment application form.exe
db550412b5e80035dab717424a2b22bcef92fb0a381997648d2c2e4e382d311d  unnamed (oldest)
```

### Network
```
qishuiwg.com          C2 domain
154.23.184.251        C2 IP (HK, AS140227, STARCLOUD GLOBAL)
```

### Shared build fingerprint
```
Imphash:      40ab50289f7ef5fae60801f88d4541fc
PE timestamp: 2024-06-10 (spoofed)
ESET sig:     Win64/Kryptik.GXY
```

---

## Detection notes

- Block `.z` attachments or inspect archive MIME type regardless of extension. RAR v5 magic bytes: `52 61 72 21 1A 07 01 00`.
- Flag InnoSetup installers arriving as email attachments or from web downloads — legitimate software distribution via email is rare in most corporate environments.
- The imphash `40ab50289f7ef5fae60801f88d4541fc` covers all known dropper EXEs in this campaign.
- Sandbox evasion means dynamic analysis will be clean. Rely on static indicators.
- Lateral movement: monitor for `PrintBrmEng.exe` processes, unexpected DLL loads from random-named DLLs in `%LOCALAPPDATA%\Local\assembly\dl3\` paths.
- Block `qishuiwg.com` and `154.23.184.251`. The IP has a long tail of prior gambling domains — if your network hit any of the pre-2026 domains listed above, the infrastructure is the same.
