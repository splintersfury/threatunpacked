---
title: "CHM Lure, Nuitka Python Backdoor, CDN Fronting: APT Targets Pakistan Military"
description: "A CHM file themed around restricted Pakistani defense exhibitions drops a Nuitka-compiled Python backdoor named after the country's annual military budget document. The C2 routes through a G-Core CDN edge node shared with Microsoft Windows Update traffic — designed to disappear into network telemetry."
pubDate: "2026-07-01T14:00:00"
permalink: "/2026/07/01/chm-nuitka-python-pakistan-military-apt/"
tags: ["Threat Intel", "APT", "Pakistan", "CHM", "Nuitka", "Python", "CDN Fronting", "Sidewinder"]
draft: false
---

[@askardyuss](https://x.com/askardyuss) flagged the sample via [ANY.RUN](https://any.run) this morning. A CHM file disguised as a restricted Pakistani defense document. The payload inside was compiled with Nuitka — a framework that translates Python into native C/C++, making the resulting binary look nothing like Python to standard analysis tools. The C2 is behind G-Core CDN, on an edge node that also proxies Microsoft Windows Update traffic.

Three layers of evasion, carefully chosen targets.

---

## The lure

The CHM file (MD5 `9CBE5D435F63E16B85BCA1F8C6EA4A9B`) hasn't appeared on VirusTotal yet — it was submitted directly to ANY.RUN and this is its first public mention. Inside, it renders a document claiming to show a restricted international defense exhibition schedule and military planning materials for Pakistani defense establishments.

The execution technique is a CHM classic: an ActiveX shortcut embedded in the compiled help document triggers `HHCTRL.OCX`, the Windows HTML Help ActiveX control, which silently spawns an executable sitting in the same directory. No download, no UAC prompt, no obvious shell pop. The EXE runs with the privileges of whoever opened the document.

The dropped EXE is `DPEs_2026-27-Final.exe.bin`.

The DPE name is specific. DPEs — Defence Planning Estimates — are Pakistan's annual military budget planning documents. The fiscal year `2026-27` runs from July 2026 to June 2027. A file called `DPEs_2026-27-Final` would be of immediate interest to anyone in the Pakistani MoD or armed forces involved in budget, procurement, or planning. The `.bin` extension on the end does the same job as the `.z` trick in other campaigns: it's there to flip the file type away from `.exe` in email security policies that block executable attachments.

The lure isn't spray-and-pray. The combination of a restricted defense exhibition theme in the CHM and a named-document EXE with the exact format Pakistani military budget files use says the operator knows what they're targeting and who opens these things.

---

## Stage one: Nuitka OneFile

The EXE (SHA256 `3cc47f9c96b9591cb9adc69a207e063c74fc416c61ed74c35aaf814b6136cc22`, 16.1 MB) is a Nuitka OneFile package. Nuitka compiles Python source into C extension code, then links the result as a standalone executable. The OneFile variant bundles the entire Python runtime, all dependencies, and the application logic into a single binary. On execution, it self-extracts to a uniquely named temp directory (`%TEMP%\onefile_XXXX_YYYYYYY\`) and runs from there.

What this means for analysis: traditional Python decompilers are useless. There's no `.pyc` bytecode to reverse. The logic is compiled C code backed by a Python runtime, and the entry point is `client_exe.dll` — the core payload, extracted alongside the rest of the bundle.

ESET identifies the family as `Python/Packed.Nuitka_AGen.EW`. CrowdStrike gives it 90% malicious confidence. Rising calls it `Backdoor.Agent/PYC!1.13CF5`. VirIT goes further: `Trojan.Win64.StealerT.DXX`. The PE timestamp on both the EXE and the DLL is `2026-02-16` — consistent, not spoofed, meaning the operator built this around five months before the campaign started.

The bundle Nuitka extracts to `%TEMP%\onefile_XXXX\` tells a lot about what the payload does:

```
client_exe.dll        core Python application (6.9 MB, Nuitka-compiled)
python312.dll         CPython 3.12 runtime
_wmi.pyd              Windows Management Instrumentation
_ctypes.pyd           low-level Windows API calls
_socket.pyd           raw networking
_bz2.pyd / _lzma.pyd  compression
libffi-8.dll          Foreign Function Interface
vcruntime140.dll

Crypto/Cipher/
  _raw_aes.pyd        AES (software implementation)
  _raw_aesni.pyd      AES-NI (hardware-accelerated)
  _raw_ofb.pyd / _raw_ecb.pyd
  _Salsa20.pyd
  _raw_eksblowfish.pyd

Crypto/Hash/
  _SHA256.pyd / _SHA384.pyd / _SHA224.pyd / _SHA1.pyd
  _keccak.pyd / _ghash_clmul.pyd

Crypto/Protocol/
  _scrypt.pyd         scrypt key derivation
```

This is [PyCryptodome](https://pycryptodome.readthedocs.io/) — a complete Python cryptography library. AES with hardware acceleration. Salsa20. SHA variants. Keccak. Scrypt key derivation. That's not a payload that encrypts one file and moves on. It's a C2 agent built to encrypt everything it sends and receives, with enough cipher options to rotate algorithms.

`_wmi.pyd` is for the system reconnaissance and anti-VM checks noted in the initial report. Python's WMI bindings let the payload query hardware details — hypervisor flags, CPU count, disk size, running processes — without touching the command line. `_ctypes.pyd` gives it direct Windows API access without going through Python's standard library wrappers.

---

## The C2: G-Core CDN fronting

The payload contacts `cl-glcb907925.gcdn.co`, which resolves to `92.223.96.6`.

That IP is a G-Core Labs CDN edge node in Luxembourg (AS199524). Shodan shows only port 443 open, running nginx, requiring HTTPS. The TLS certificate is G-Core's wildcard `*.gcdn.co`.

The `cl-glcb907925` subdomain is a G-Core CDN customer ID. The actor registered as a G-Core CDN customer, got assigned the identifier `glcb907925`, and pointed their content delivery configuration at a backend server. G-Core then routes requests matching `cl-glcb907925.gcdn.co` through the edge at `92.223.96.6` to wherever the actual C2 backend is sitting. That backend IP is hidden behind the CDN — we don't see it.

The catch is that `92.223.96.6` isn't a dedicated malware server. VT's resolution history for that IP shows it resolving to Microsoft Windows Update delivery domains, Xbox Live, MSEdge update endpoints, and Azure traffic manager domains going back months:

```
star.f.tlu.dl.delivery.mp.microsoft.com
wu-b-net.trafficmanager.net
au.download.windowsupdate.com.delivery.microsoft.com
d1.xboxlive.com.delivery.microsoft.com
192.81.131.122msedge.b.tlu.dl.delivery.mp.microsoft.com
```

G-Core is a real CDN. Microsoft uses it for content delivery. So does this C2. To a network monitor looking at DNS queries or IP-based firewall rules, traffic to `92.223.96.6` on port 443 is indistinguishable from a machine downloading a Windows update — or any other client pulling content from G-Core's edge.

This is deliberate. The operator picked a CDN that carries legitimate Microsoft traffic, registered a customer account, and put their C2 behind it. The Nuitka bundle does its WMI anti-VM check first — if the environment looks like a sandbox, it stays quiet. If it doesn't, it connects to `cl-glcb907925.gcdn.co:443` over TLS, behind the CDN, and the backend server never surfaces in a simple port scan or IP block.

---

## Attribution context

The TTP set here has a well-documented signature:

- CHM delivery targeting Pakistan military and government — used extensively by Sidewinder (also tracked as RattleSnake, APT-C-17, T-APT-04, Razor Tiger) since at least 2018
- HHCTRL.OCX ActiveX bypass in compiled help documents — a documented Sidewinder technique
- Pakistani military establishment as the primary target audience — core Sidewinder focus
- Python-based backdoor as final payload — seen in Sidewinder campaigns throughout 2024 and 2025, including Nuitka-compiled variants

Sidewinder is assessed with moderate-to-high confidence as India-attributed, active since at least 2012, and has run persistent campaigns against Pakistan, Bangladesh, Nepal, and Afghanistan. The shift to Nuitka compilation is a newer adaptation — earlier Sidewinder Python payloads used PyInstaller — but it fits the pattern of the group updating its toolchain to stay ahead of detection.

I'm not making a definitive attribution call here. Multiple actors have replicated Sidewinder's CHM delivery TTP. But the combination of the specific document lure (correct Pakistani government budget document format), the correct fiscal year, the HHCTRL.OCX bypass, and the Python backdoor with WMI anti-VM checks sits squarely in the Sidewinder playbook.

---

## IOCs

```
CHM lure
  MD5:    9CBE5D435F63E16B85BCA1F8C6EA4A9B
  (not yet in VT as of 2026-07-01)

Dropped EXE: DPEs_2026-27-Final.exe.bin
  MD5:    37B7AABFAD89345AACE02C294AB940EC
  SHA256: 3cc47f9c96b9591cb9adc69a207e063c74fc416c61ed74c35aaf814b6136cc22
  Size:   16,184,832 bytes
  Imphash: 254bc68f13467887f90e72a94dbc6b01
  PE ts:  2026-02-16

Core DLL: client_exe.dll
  MD5:    422E4A3F1C69FF834DFC4688E8893716
  SHA256: d4e54222260092b8017a393db70f201e7d9222d91b48982f409c0328c14810d6
  Size:   6,921,216 bytes
  PE ts:  2026-02-16

Network
  cl-glcb907925.gcdn.co   C2 domain (G-Core CDN customer)
  92.223.96.6              G-Core CDN edge (AS199524)
```

---

## Detection notes

- **CHM files from untrusted sources** should be treated as hostile. Windows will open `.chm` files by default; most users have no reason to receive them as attachments. Consider blocking `.chm` at email gateways.
- **HHCTRL.OCX spawning child processes** is an immediate detection opportunity. Any process tree where `hh.exe` or `HHCTRL.OCX` spawns an executable from the same directory as a `.chm` file is malicious by definition.
- **Nuitka OneFile self-extraction**: monitor for processes creating large numbers of `.pyd` files under `%TEMP%\onefile_*\` paths. Legitimate software using Nuitka OneFile does this too, but it's uncommon enough to warrant review. The specific combination of `client_exe.dll` + PyCryptodome `.pyd` files in the same temp directory is campaign-specific.
- **G-Core CDN**: `cl-glcb907925.gcdn.co` and `92.223.96.6` for blocking. The G-Core domain pattern `cl-[customer_id].gcdn.co` / `.globalcdn.co` may appear in other campaigns using the same CDN fronting technique.
- **WMI for anti-VM**: a Python process invoking `_wmi.pyd` during early execution before any user interaction is a sign of environment fingerprinting. CAPE sandbox caught this; time-limited sandboxes running less than the sleep threshold won't.
- The PE timestamp `2026-02-16` on both the EXE and DLL is a shared build fingerprint — if other samples from the same operator surface, expect to see it.
