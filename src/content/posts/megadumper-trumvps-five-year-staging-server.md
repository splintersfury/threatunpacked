---
title: "MegaDumper: One Staging Server, Five Years, Zero Detections"
description: "A Shodan scan for Singapore open directories surfaces a TRUMVPS server that has been quietly hosting the same .NET credential stealer — under the same filename — since 2021. The current build has zero detections."
pubDate: "2026-07-02T18:00:00"
permalink: "/2026/07/02/megadumper-trumvps-five-year-staging-server/"
tags: ["megadumper", "credential-stealer", "trumvps", "singapore", "open-directory", "infostealer", "threat-intel", "dotnet"]
thumb: "/images/megadumper-trumvps-five-year-staging-server-thumb.svg"
---

Routine infrastructure scan, Singapore range. Shodan query for open directories, HTTP title "Index of". Most results are misconfigured personal NAS boxes or forgotten test servers. `103.68.109.59` — ASN 136557, Host Universal Pty Ltd, TRUMVPS — is neither. It is hosting eight files with no identifying context and no detections.

```
Index of /

1.bin           2026-06-23 02:45    378K
1.exe           2026-06-22 23:11    175K
123.bin         2026-06-23 02:52    175K
Clients123.bin  2026-06-24 19:10    377K
dcaat.bin       2026-06-25 23:40    377K
dcaat1.bin      2026-06-24 22:39    379K
dcap91.bin      2026-06-26 11:33    412K
dcaptk1.bin     2026-06-26 11:34    412K
```

The server tells you more than the files do. Apache/2.4.58 on **Win64**, OpenSSL/3.1.3, PHP/8.2.12 — XAMPP, running on Windows. That is not what a clean staging host normally looks like. SMB port 445 is also open, authentication required. The clock is misconfigured several days ahead of UTC, which is why some filenames show future timestamps.

---

## What's in `1.exe`

Only one of the eight files has a standard magic signature. `1.exe` opens with `4d5a` — a PE32 executable. The rest: random-looking bytes, no recognisable header, fully encrypted.

The PE has three sections — `.text`, `.rsrc`, `.reloc` — and a single import: `_CorExeMain` from `mscoree.dll`. This is not a native binary. It is a **.NET assembly**, where all logic runs as MSIL bytecode and the native PE is just a CLR host stub.

Reading the metadata string heap confirms the runtime target:

```
BSJB
v2.0.50727
Copyright 2011
```

**.NET Framework 2.0** — a runtime first shipped in 2005 and end-of-life long before the staging server even appeared. The `Copyright 2011` date either marks when the codebase was originally written or was frozen there on purpose to mess with timelines.

Deeper into the metadata string heap, the purpose becomes clear:

```
Thread32First / Thread32Next
Process32First / Process32Next
Module32First / Module32Next
GetModuleFileNameEx
VirtualAllocEx / VirtualFreeEx / VirtualQueryEx
CreateRemoteThread
VMRead / GenericRead / ExecuteRead
```

This is a process enumerator and remote memory reader. The binary can walk every running process, enumerate its modules, and read and write memory in external processes via `CreateRemoteThread` + `VirtualAllocEx` — the standard pattern for process injection.

The UI fingerprints are equally specific. Form names `MainFormLoad`, `Form2Load`, `Form3Load`; controls `CheckBox`, `ComboBox`, `ListView`, `TextBox`; a named view `VirtualMemoryView` alongside a `HeapView`. This is a **Windows Forms application with a built-in process memory inspector** — a credential stealer with an operator GUI.

One string stands out: `CheckStatut`. French. "Check status." The developer, or the code they borrowed from, wrote in French.

Another: `LinkSourceforgeLinkClicked` — a SourceForge URL embedded in the GUI, likely pointing to the public project page or credits.

And buried in the strings: `Spotify`.

---

## The Historical Record

VirusTotal records files being downloaded from `103.68.109.59` going back to **December 20, 2021**. The file at that time was also named `1.exe`, but it appeared in the platform under a second name: `Spotfy.exe`. Misspelled Spotify. A social-engineering lure.

That 2021 binary carried a version resource:

```
ProductName:    MegaDumper
OriginalFileName: MegaDumper.exe
FileVersion:    1.0.7870.28972
LegalCopyright: Copyright 2011
```

**MegaDumper.** The name is the whole pitch. A credential dumper, built on a Windows Forms UI, with its own process memory reader and a SourceForge project link baked into the GUI — presumably for the original author's credits, left intact across every rebuild since.

The VT family tree of similar files shows the binary has been active since at least April 2019 — this actor did not just appear in 2021. The staging server did.

| First Seen | SHA256 | ProductName | Dets |
|---|---|---|---|
| 2019-04-01 | `843827b2dd460aa90ce208736a365594193b061fd81a050b83bf97f078ab9757` | MegaDumper | — |
| 2020-08-10 | `66a44a466015e3996f62d80263d15c136be718e3fdd4dbf0b3785b1ee27f5fc6` | MegaDumper | — |
| 2021-09-10 | `a52612f0586ec413ab3501e667251fb9d264f8469fbaff3a8720e5aad2074066` | `Microsoft® Windows® Operating System` | 37 |
| 2021-09-15 | `440c354463590243075797c7bd1abf4713c7365ce96ee1c36959aaca800fdcde` | `Microsoft® Windows® Operating System` | 42 |
| 2021-11-08 | `3005c9ef39e309dc5a0c51f2ad6ed4b6ba04aa02ea0ef31afec8ca252f3f72cc` | MegaDumper | 22 |
| 2021-12-20 | `8c7f9ec84782eac067ec0c97a307ad21b6283c2800c02293d2cc4bc789df95e0` | MegaDumper | 28 |
| 2022-01-03 | `d2915c8cbf50b9a555d7ef63b45141ece0f622dc020f33f378b0e92eee2e69b2` | MegaDumper | 29 |
| 2022-03-23 | `f58d6ac2678c164a972e2d60a658d3e0a7834293b10e8a412f57653ae65b2b07` | MegaDumper | 48 |
| 2023-01-17 | `03c381ed488688702083667ff6c5dcbeea6fb9a43afcf7602c329f2b95edbd91` | MegaDumper | 23 |
| 2023-09-20 | `9c47f88bb79e137acf53b755f76d5eeec05fbd093c425052395fac4735bed9f0` | MegaDumper | 26 |
| 2024-03-18 | `4896ccea5dd6b6487bbcec6d6d46ac0c797d09effeaa2b212b904094c36c22a4` | `M*3*G*4**D*u*m*p*3*R*` | 11 |
| 2026-04-02 | `66ad02669fbe79a9042f3f1be5c2c16603c8a5009d74b8641529e5555e1e1277` | MegaDumper | 17 |
| 2026-06-22 | `a39bb8a5f205d4cf2b64a042f486df22578505aeede352ca46f72d70d20e758d` *(current)* | — | **0** |

A few patterns are worth calling out.

The Spotify lure has not changed in four years. `Spotfy.exe` — the same misspelling — appeared as a submission alias for the December 2021 binary, and `Spotify` sits in the strings of the current one. That is the delivery vehicle: a pirated Spotify installer, probably, or something close to it. The typo is sloppy enough to be real but subtle enough that a victim hurrying to install music software might not notice.

September 2021 saw a different approach. Before the MegaDumper branding solidified, the actor pushed two variants claiming to be `Microsoft® Windows® Operating System` with `OriginalFileName: smartscreen.exe`. Both are tagged by VirusTotal as **spreaders** — observed propagating to additional files or locations. One carries an `overlay` tag, meaning data was appended after the last PE section, a common way to attach config or a second stage without changing the hash of the main code. Once MegaDumper's explicit branding took over, the Microsoft impersonation stopped. Distinct phases, distinct objectives.

The detection cycle is the most operationally interesting part. The March 2022 build peaked at 48 detections — that is a lot of AV coverage for a credential stealer trying to stay quiet. The actor responded in March 2024 by rebuilding with leet-speak obfuscation across the product name (`M*3*G*4**D*u*m*p*3*R*`), dropping the count to 11. By April 2026 they dropped the obfuscation and were back at 17 plain `MegaDumper`. The June 22 build — staged ten days ago — sits at **zero detections**. The actor treats the VT detection count as a KPI and rebuilds accordingly.

---

## The Encrypted Payloads

The seven `.bin` files have fully random first bytes — no standard magic signature. They are encrypted. The sizes cluster into two groups: six files near 377–412K, and `123.bin` matching the `1.exe` size of 175K exactly — same size, different hash, suggesting a renamed copy of the loader for testing or variant tracking.

`Clients123.bin` is the most telling filename. In remote-access tooling, a `Clients.bin` is conventionally the operator's database of active connections — the list of infected machines, their addresses, connection times, and harvested credentials. The presence of ADO/OLEDB COM interface GUIDs embedded in `1.exe` (`9613A0E7-5A68-11D3-8F84-00A0C9B4D50C` series) confirms the binary uses embedded database functionality to persist and query that client list.

The other named binaries — `dcaat.bin`, `dcaat1.bin`, `dcap91.bin`, `dcaptk1.bin` — follow a naming pattern suggesting internal versioning or target-specific configurations. Without the decryption key, the contents cannot be read passively.

---

## Infrastructure

| Property | Value |
|---|---|
| IP | `103.68.109.59` |
| ASN | AS136557 — Host Universal Pty Ltd |
| Branded as | TRUMVPS |
| Country | Singapore |
| OS | Windows (XAMPP — Apache/2.4.58 Win64, PHP/8.2.12) |
| Port 80 | Apache HTTP open directory |
| Port 445 | SMB, authentication enabled |
| First malicious file seen | 2021-12-20 |
| Current files | 8 (1 PE + 7 encrypted blobs) |
| Current PE detections | 0 |

SMB with authentication on a staging server is unusual. The most likely explanation is the actor connects to the machine over SMB to push new builds — which fits the pattern of frequent rebuilds. It is also consistent with the lateral propagation behaviour seen in the September 2021 variants, where the binary actively spread to other files.

---

## IOC Summary

**Current staging — zero detections, not yet blocked:**

| File | SHA256 | Size |
|---|---|---|
| `1.exe` | `a39bb8a5f205d4cf2b64a042f486df22578505aeede352ca46f72d70d20e758d` | 175K |
| `1.bin` | `fcec08fcc3cc4711531189d8e9b9f7409c2ccde838dcafe1798e40bafb15ed3d` | 378K |
| `123.bin` | `1a4373323b2411164af1ec2c103446c2f02eb128707285b24695effba6cf429b` | 175K |
| `Clients123.bin` | `155421631f69ef0327b26611da9b28ad4fef82d1d758a257fef71496d8141a9f` | 377K |
| `dcaat.bin` | `823f2406f01baeecfa131bd10c43e5f97847e47643f54e6dd5ef8e5b3e97048f` | 377K |
| `dcaat1.bin` | `1adaa0692dba2d20ce38752ceaa172b964cff39991a079748f67714886134c2a` | 379K |
| `dcap91.bin` | `ee3951c830957a65b26c04f78935fdd9888d31041872705f7c98b45c12e90c78` | 412K |
| `dcaptk1.bin` | `350835a4371d81d2d18c590fe4cf1b71e7f5f7ef8c56441d657a61cf468a2c00` | 412K |

**Historical MegaDumper variants (documented):**

| First Seen | SHA256 | Notes |
|---|---|---|
| 2019-04-01 | `843827b2dd460aa90ce208736a365594193b061fd81a050b83bf97f078ab9757` | `MegaDumper.exe` — earliest known |
| 2020-08-10 | `66a44a466015e3996f62d80263d15c136be718e3fdd4dbf0b3785b1ee27f5fc6` | `MegaDumper.exe` |
| 2021-09-10 | `a52612f0586ec413ab3501e667251fb9d264f8469fbaff3a8720e5aad2074066` | `smartscreen.exe` spoofing, spreader |
| 2021-09-15 | `440c354463590243075797c7bd1abf4713c7365ce96ee1c36959aaca800fdcde` | `smartscreen.exe` spoofing, spreader + overlay |
| 2021-11-08 | `3005c9ef39e309dc5a0c51f2ad6ed4b6ba04aa02ea0ef31afec8ca252f3f72cc` | `MegaDumper.exe` |
| 2021-12-20 | `8c7f9ec84782eac067ec0c97a307ad21b6283c2800c02293d2cc4bc789df95e0` | `MegaDumper.exe` / `Spotfy.exe` / `1.exe` |
| 2022-01-03 | `d2915c8cbf50b9a555d7ef63b45141ece0f622dc020f33f378b0e92eee2e69b2` | `MegaDumper.exe` |
| 2022-03-23 | `f58d6ac2678c164a972e2d60a658d3e0a7834293b10e8a412f57653ae65b2b07` | `MegaDumper.exe` (48 dets peak) |
| 2023-01-17 | `03c381ed488688702083667ff6c5dcbeea6fb9a43afcf7602c329f2b95edbd91` | `MegaDumper.exe` |
| 2023-09-20 | `9c47f88bb79e137acf53b755f76d5eeec05fbd093c425052395fac4735bed9f0` | `MegaDumper.exe` |
| 2024-03-18 | `4896ccea5dd6b6487bbcec6d6d46ac0c797d09effeaa2b212b904094c36c22a4` | `M*3*G*4**D*u*m*p*3*R*` (leet evasion) |
| 2026-04-02 | `66ad02669fbe79a9042f3f1be5c2c16603c8a5009d74b8641529e5555e1e1277` | `MegaDumper.exe` |

**Infrastructure:**
```
103.68.109.59   # TRUMVPS Singapore — active staging
```

---

## What To Do

**Block at perimeter:**
```
103.68.109.59
```

**Hunt for the Spotify lure:**
```powershell
Get-ChildItem -Path C:\Users -Recurse -Include "Spotfy*.exe","Spotify*.exe" |
  ForEach-Object {
    $v = (Get-Item $_).VersionInfo
    if ($v.ProductName -like "*MegaDumper*" -or $v.ProductName -like "*Dump*") {
      Write-Output "$($_.FullName) — ProductName: $($v.ProductName)"
    }
  }
```

**YARA:**
```yara
rule MegaDumper {
    strings:
        $pname  = "MegaDumper" wide ascii
        $copy   = "Copyright 2011" wide ascii
        $french = "CheckStatut" wide ascii
        $sf     = "Sourceforge" wide ascii nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
```

**ESET classification:** `MSIL/HackTool.Agent.EP`

---

The current build is ten days old and completely undetected. The staging server has been up for five years with no sign of disruption. Binaries get rebuilt; infrastructure does not. That is the underlying bet this actor is making, and so far it is paying off. One thing even a complete rebuild cannot fix: the `Spotfy` typo has been in the lure since at least 2021, and it is still there.

---

*Passive analysis: VirusTotal file/URL/behavior, Shodan, PE string extraction via HTTP Range requests. No live C2 contact. No credentials tested or used. Encrypted `.bin` files not decrypted.*
