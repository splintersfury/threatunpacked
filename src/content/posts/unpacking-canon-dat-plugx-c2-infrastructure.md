---
title: "Unpacking Canon.dat: PlugX, a Config Extractor, and the C2 Infrastructure Behind It"
description: "A single XOR'd Canon.dat turned into a campaign map: reversing the CanonStager loader, writing a memory-based config extractor, pulling the related samples, and walking nine builds out to their CloudFlare-fronted C2 origins."
pubDate: "2026-06-27T12:00:00"
permalink: "/2026/06/27/unpacking-canon-dat-plugx-c2-infrastructure/"
heroImage: "/images/unpacking-canon-dat-plugx-c2-infrastructure-c2map.png"
tags: ["PlugX", "CanonStager", "UNC6384", "Reverse Engineering", "Threat Intel"]
draft: false
---

This started the way a lot of these do: a hash on X. [@mopisec](https://x.com/mopisec) posted a `Canon.dat`, tagged `#PlugX`, listed a C2 of `202.61.72[.]198:443`, and called it FUD (3/60 on VirusTotal). That's enough to be worth an afternoon. The afternoon turned into a week, and the single sample turned into a small campaign.

I want to be upfront about what this is and isn't. The actor is **UNC6384** (overlaps RedDelta / TA416 / Mustang Panda), and the loader already has a name. Arctic Wolf called it **CanonStager** back in late 2025. None of the tradecraft is new. What's worth writing down is the *method*: how you get from one encrypted blob to a config extractor, then to the related samples, then to the C2 origins. Plus the spots where my first read was wrong and I had to walk it back.

### The sample

`Canon.dat` is not a PE. It's a 275,004-byte blob, and the whole point is that it never touches disk as a PE so static AV stays quiet.

```text
SHA-256 (Canon.dat)        c74d70892fc2193790bedc8c08539b390ea460bc0ef72cb568568943016c35f0
SHA-256 (payload DLL)      1d98ef4f875f70ca0dfeb9a509ab0ca4d2f015e33bd955ed6ebec6c10590e7cf
```

The outer layer is the easy part: a single-byte XOR with a 13-byte stub prefix. You don't even have to guess the key. There's a long run of `0x3C` in the ciphertext (null padding in the plaintext), so it falls out:

```python
def crack(data):
    for off in range(64):
        key = data[off] ^ 0x4D                  # so first byte -> 'M'
        if data[off+1] ^ key != 0x5A: continue  # 'Z'
        pe = bytes(b ^ key for b in data[off:])
        e = int.from_bytes(pe[0x3c:0x40], 'little')
        if 0 < e < len(pe)-4 and pe[e:e+4] == b'PE\x00\x00':
            return off, key, pe   # here: offset 13, key 0x3C
```

That gives a 32-bit PE32 DLL with one export, `JrdlwuiHVkO`, and almost no static imports (just kernel32 and user32). Everything else is resolved at runtime by hashing PEB module names. Standard PlugX.

### The loader that actually matters

Here's the thing the first pass got wrong. The interesting file isn't `Canon.dat` at all. It's the *third* file in the kit. This is a classic sideloading triplet:

| Role | File | Notes |
|------|------|-------|
| Signed host | `CNMNSST2.exe` | Legit **Canon IJ Network Scanner Selector EX2**. Valid signature, 0 detections. |
| Loader | `CNCLID.dll` | Malicious. Export `GetLangID`. This is CanonStager. |
| Payload | `Canon.dat` | The XOR'd PlugX from above. |

![CanonStager kill chain](/images/unpacking-canon-dat-plugx-c2-infrastructure-killchain.png)

`GetLangID` is where the loader hides. It calls `FindFirstFileW("C:\windows\*.*")`, counts directories, and only when it hits the *third* one does it call the real loader. That's an execution gate dressed up as a localization routine. `C:\windows` always has at least three folders, so it always fires.

The real loader does the part that mattered for everything afterward. It calls `GetModuleFileNameW(NULL)` to get the **host EXE's** path, takes that directory, builds `\??\<dir>\Canon.dat`, opens it with `NtCreateFile`/`NtCreateSection`, and **runs it as shellcode**. There is no XOR loop anywhere in the loader.

Two facts come straight out of that, and both cost me real time:

1. **The XOR key lives in `Canon.dat`, not the loader.** I'd assumed the key was in `CNCLID.dll` and went looking for it across loader variants. It isn't there. The loader is key-agnostic and interchangeable. I pulled 35 loaders later; 24 distinct code variants, not one carries a key.
2. **The host EXE has to sit next to `Canon.dat`.** Because the path comes from `GetModuleFileName(NULL)`, you can't just `rundll32` the loader and expect it to find the payload. `rundll32` lives in System32, so it looks for `Canon.dat` there and comes up empty. I burned a bunch of detonation attempts before that clicked.

### Why the config won't fall out statically

The payload is PlugX: it self-maps, calls its own `DllMain` with the magic reason `0x1ff`, and spins up a beacon worker. The config, the part you actually want, is built into runtime memory and reached through an obfuscated computed pointer. It is **not present in the file**. I confirmed that the hard way: a memory dump of the running implant has the C2; the payload on disk does not.

So a file-only extractor can't recover the C2. You need a memory image of the implant while it's running. That means detonation, and detonating *this* thing has a few sharp edges:

- Clean Windows VM with the **NIC removed**, so the implant never reaches the real C2.
- The full triplet, together, with the host EXE next to `Canon.dat` (see above).
- A reliable trigger. VNC keystroke injection and `RunOnce` both flaked on me; an **all-users Startup-folder `.bat`** was the thing that fired every time.
- Capture from the **host side** with `virsh dump --memory-only`, so nothing in the guest has to cooperate.
- Extract with a **binary anchor**, not a text grep. The config C2 is a struct: `flag:u16, port:u16, host`. Searching for that `[flag][port][host]` shape cuts straight through the analyst VM's pre-existing IOC noise, which a `grep https://` drowns in.

Once that worked, the seed sample gave up `202.61.72[.]198:443` and a stream of randomly-generated beacon URIs like `https://202.61.72.198/DBe4KJbFH2U117A?QF3h=...`. The C2 matched the tweet, but now I had a repeatable way to get it out of *any* build.

### From one sample to nine

With the extractor working, the question becomes: how many of these are there? VirusTotal pivots on the name, the loader export, the payload imphash, and compressed parents returned 63 related files: payloads, loaders, decrypted DLLs, and lure archives.

Cracking every `Canon.dat` settled the key question for good. Nine distinct payloads, nine distinct `(offset, key)` pairs. Each build is fresh:

| Canon.dat | stub offset | XOR key | payload export |
|-----------|------------:|--------:|----------------|
| `c74d7089` (seed) | 13 | 0x3C | JrdlwuiHVkO |
| `1e05e5ec` | 12 | 0xE9 | uEnBXnfDNIj |
| `2889ac58` | 7 | 0x8B | GetLangInit |
| `418ad90f` | 12 | 0x09 | VADnOYgWyvm |
| `542aaae7` | 9 | 0x40 | dHRytafCiJD |
| `58101378` | 7 | 0xC6 | uisiXjwMCAf |
| `6af60f9a` | 10 | 0x94 | uXkwjJJsLeZ |
| `7e825f86` | 10 | 0x20 | qjkyOodMGlk |
| `f982474f` | 8 | 0xCF | ZBEPBDTmLkK |

The reusable parts (a dozen copies of the legit Canon host, 35 loader variants) are shared scaffolding. What changes per build is the payload and its key. The same handful of payloads then get **repackaged into many lure archives** (167 distinct archives across the cluster), one decoy per target. So the C2 set is small and bounded, which means it's mappable.

### Mapping the C2s to targets

There are two ways to tie a C2 to a sample. The slow way is detonation: run the build, dump RAM, extract. The fast way is a VT pivot: a C2 domain's `communicating_files` points back to the triplet ZIP, and the ZIP carries both the `Canon.dat` *and* the decoy document. The decoy is what tells you who the target was.

![C2 to target map](/images/unpacking-canon-dat-plugx-c2-infrastructure-c2map.png)

| C2 (HTTPS/443) | build(s) | decoy / target |
|----------------|----------|----------------|
| `202.61.72[.]198` | seed | Mongolia: National Security Council (ҮАБЗ) regional-security report |
| `dalerocks[.]com` | px1/px3/px4 | Cambodia: "Hun Sen courtesy call" `.lnk` |
| `concreteinportland[.]com` | px8 | NATO / France: Alice Rufo / Ankara Summit briefing PDF |
| `neurosurgeryx[.]com` | px7 | (decoy not yet recovered) |
| `rhonline[.]net` | px2/px5/px6 | (decoy not yet recovered) |

So this isn't one target. It's a spread of governments and defense bodies: Mongolia's national-security apparatus, Cambodian diplomacy, French/NATO defense, and probably Lithuania (more on that below). That lines up with the documented UNC6384 swing back toward EU/NATO in mid-2025.

The delivery deserves a note. The lure is a ZIP with a disguised `.lnk`. The `.lnk` runs PowerShell that finds the ZIP, carves a TAR appended to the end of it, `tar -xvf`s that into a GUID-named folder under `%LocalAppData%`, and runs the Canon host from there. The GUID folders (`T80A20NS-…`, `QV95SH6B-…`) are exactly the path prefixes you see on the `Canon.dat` filenames in VT.

### The infrastructure

Every C2 is CloudFlare-fronted, and the domains aren't freshly-coined nonsense. They're **drop-caught expired domains**. DNS history runs back to 2014–2020 (a real Portland concrete company, a real neurosurgery site), but they were re-registered in 2025–2026 with privacy-redacted whois. They look aged and legitimate, and they're entirely the operator's.

The one origin that leaked did so because the seed build used a **bare IP** instead of a domain. `202.61.72[.]198` is a Windows VPS at **GPK Group / AS9749 in Australia**: nginx on 443 serving a CloudFlare Origin certificate for `dreamresin[.]com`, plus RDP (3389) and WinRM (5985).

![C2 infrastructure](/images/unpacking-canon-dat-plugx-c2-infrastructure-infra.png)

Pivoting on the hosting (`asn:AS9749` plus a CloudFlare-Origin cert) turned up a sibling with the *identical* fingerprint. `202.61.72[.]99` fronts `techlietuva[.]com`, same Windows-VPS + CF-cert + RDP/WinRM profile, with a fake "Tech Lietuva" corporate front and a probable Lithuania target. The rest of that `/24` is co-tenant Chinese cybercrime (gambling, streaming, Telegram-account shops), which is its own small attribution signal: shared bulletproof hosting.

This section is also where I have to show my work, because a couple of my early conclusions didn't survive:

- **VT verdicts lag.** The VT *API* told me `dalerocks[.]com` was 0/91. The web UI said 18/92. Trust the API number as a floor, not as the truth.
- **Registrant clustering was a dead end.** Three of the domains shared registrant hash `c6523241936df1ba`, and for a minute I thought that was the operator's fingerprint. It isn't. It's a generic privacy-redaction value shared by 30+ unrelated domains. Reverse-whois on it is noise.
- **JA3S/JARM didn't isolate anything.** The seed origin's TLS fingerprints match 15k–127k hosts, because it's a stock nginx+CloudFlare stack. Fingerprint pivots only help when the stack is unusual; here, the hosting-plus-cert pivot is what worked.

### What you can't get from the malware

The question everyone asks is "how many victims?" Honestly, you can't answer that from the binaries. The number lives on the C2 side. You'd need to sinkhole the domains or get CloudFlare or law enforcement to enumerate connections, which is how the *other* PlugX botnets got counted. What the samples tell you is the *targeting*, not the *hit list*. Given the gov/defense decoys and only 2–4 VT submissions per sample, this reads as targeted: dozens of high-value victims, not thousands.

A couple of honest loose ends. Two builds (px2/px5) are stubborn to trigger inside the dump window, so `rhonline[.]net`'s exact build is still pending a longer-wait retry. And `techlietuva[.]com` is verified by infrastructure, not by a captured beacon. FUD payloads don't detonate in sandboxes, so VT has no communicating sample for it. The link rests on co-location and an identical origin profile. That's strong, but I'd rather call it what it is.

### Indicators

```text
# C2 (all HTTPS/443)
202.61.72[.]198                  IP C2 (Mongolia); origin: GPK Group / AS9749 (AU)
dalerocks[.]com                  domain C2 (Cambodia); CloudFlare-fronted
concreteinportland[.]com         domain C2 (NATO/France); CloudFlare-fronted
neurosurgeryx[.]com              domain C2; CloudFlare-fronted
rhonline[.]net                   domain C2; CloudFlare-fronted

# Origins / decoy fronts
202.61.72[.]198   202.61.72[.]99    Windows-VPS origins (CF Origin cert + RDP + WinRM), GPK Group/AS9749
dreamresin[.]com  techlietuva[.]com decoy front sites on the origins

# Triplet
CNMNSST2.exe / CNMNSST.exe        signed Canon host (legit, abused)
CNCLID.dll (export GetLangID)     CanonStager loader
Canon.dat                         XOR'd PlugX payload (9 builds; keys 09 20 3c 40 8b 94 c6 cf e9)

# Delivery
*.lnk -> carves appended TAR -> %LocalAppData%\<GUID>\CNMNSST.exe
GUID folders: T80A20NS-  QV95SH6B-  DHJ0I9RK-  VD1B12N4-  43OZ1LSA-
```

### Detection

Per-build keys and per-build export names make fixed-string signatures brittle. The robust move is to *unpack* generically: brute the stub offset and single-byte key and validate the result is a PE. That's key-agnostic, so it survives the per-build rotation:

```python
def is_canon_dat(data):
    for off in range(64):
        key = data[off] ^ 0x4D                       # assume first byte decodes to 'M'
        if data[off+1] ^ key != 0x5A: continue       # 'Z'
        hdr = bytes(b ^ key for b in data[off:off+0x400])
        e = int.from_bytes(hdr[0x3c:0x40], 'little')
        if 0 < e < len(hdr)-4 and hdr[e:e+4] == b'PE\x00\x00':
            return off, key
    return None
```

For hunting at rest, the strongest signal is the *combination*, not any one file: a signed Canon `CNMNSST2.exe` / `CNMNSST.exe`, a `CNCLID.dll` that exports `GetLangID` but isn't Canon's, and a sibling `Canon.dat` blob, all sitting together in a user-writable or `%LocalAppData%` GUID folder. None of the three is malicious alone. The triplet is.

### Where this fits

This is a newer (2026) cut of CanonStager. The 2025 reporting describes an RC4-with-16-byte-key loader using `cnmpaui.exe` / `cnmpaui.dll` / `cnmplog.dat` against Hungarian and Belgian diplomats. This variant swaps in single-byte XOR, a different Canon host (`CNMNSST2.exe`, the IJ Network Scanner), and a fresh set of C2s, none of which return any OSINT hits. Same actor, same playbook, new build and new infrastructure.

The reusable part is the tooling: a `Canon.dat` decryptor, a memory config extractor, an XOR-key cracker. If another `Canon.dat` shows up, the path from blob to C2 is now a known quantity.

*References: [Arctic Wolf — UNC6384 / CanonStager](https://arcticwolf.com/resources/blog/unc6384-weaponizes-zdi-can-25373-vulnerability-to-deploy-plugx/), [The Hacker News](https://thehackernews.com/2025/10/china-linked-hackers-exploit-windows.html), [Recorded Future — RedDelta](https://www.recordedfuture.com/research/reddelta-chinese-state-sponsored-group-targets-mongolia-taiwan-southeast-asia). Original sample via [@mopisec](https://x.com/mopisec).*
