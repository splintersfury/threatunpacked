---
title: "DragonForce: Deep Reverse Engineering of the Ransomware Behind M&S and Co-op UK"
description: "Full technical analysis of DragonForce's Windows x86 encryptor: MinGW C++ with Salsa20 multi-mode encryption, BYOVD kernel driver EDR bypass (rentdrv2.sys + truesight.sys), WMI shadow copy deletion, Restart Manager file handle killing, IOCP network scanning, and COM-based scheduled task persistence."
pubDate: "2026-07-07T12:00:00"
permalink: "/2026/07/07/dragonforce-ransomware-deep-re/"
tags: ["Ransomware", "Reverse Engineering", "DragonForce", "BYOVD", "Malware Analysis"]
thumb: "/images/dragonforce-win32-deep-re-thumb.svg"
draft: false
---

In April 2025, Marks & Spencer — one of Britain's most recognisable retailers — started losing hundreds of millions of pounds to a ransomware intrusion that locked online orders for weeks. Co-op UK and Harrods followed in May. The group behind all three was DragonForce, a RaaS operation that had been quietly building since late 2023 and chose 2025 to make the biggest retail disruption Britain had seen in years.

I wanted to know what the encryptor actually does. Not the affiliate TTPs, not the ransom note prose — the binary. What encryption scheme, how the EDR bypass works, what the lateral movement looks like at the socket level. The sample I'm working from (`f58af71e542c67fbacf7acc53a43243a5301d115eb41e26e4d5932d8555510d0`, first seen September 2025, last submitted May 2026) is named `DragonForce.exe` by VT and carries 49 detections from major vendors, all consistent: `Ransom.DragonForce`, `Win32/Filecoder.DragonForce.B`, `Ransom:Win32/DragonForce.C!MTB`.

## Binary Snapshot

```
File:       DragonForce.exe
Size:       1,724,416 bytes (1.69 MB)
Type:       PE32 executable (GUI) Intel 80386
Compiler:   MinGW-w64 / GCC (C++)
ImageBase:  0x00400000
ASLR:       disabled
Timestamp:  0x001B0820 → 1970-01-21 (intentionally corrupted)
SHA-256:    f58af71e542c67fbacf7acc53a43243a5301d115eb41e26e4d5932d8555510d0
```

No ambiguity on the compiler: `msvcrt.dll` provides the C runtime, and `.CRT`, `.tls`, and `.bss` sections together mark this as MinGW/GCC output — not MSVC. The timestamp sits at 0x001B0820 — roughly twenty days past the Unix epoch, January 21, 1970 — a deliberately junk value.

No PE resources section. No debug symbols. No ASLR. The binary was built to run at `0x400000` and stay there; the developers were not worried about ASLR bypass complexity.

### Section Layout

```
Section     VA          VSize      RawSize    Entropy
.text       0x001000    1,630,260  1,630,720  6.37
.data       0x190000       13,096     13,312  3.62
.rdata      0x194000       70,940     71,168  5.53
.bss        0x1a6000       37,184          0  0.00
.idata      0x1b0000        6,996      7,168  5.26
.CRT        0x1b2000           52        512  0.28
.tls        0x1b3000            8        512  0.00
```

`.text` takes up nearly the entire binary at 1.6 MB. Entropy of 6.37 is typical for compiled code with no packing. The `.rdata` section at 5.53 carries string tables, vtables, and cryptographic constants — including the Salsa20 sigma/tau initialization strings that anchor the encryption scheme.

## Import Table: Reading the Capability Map

236 APIs across 10 DLLs. Rather than listing them all, I'll walk through each DLL and say what the import group tells you.

**`KERNEL32.dll` — 90 APIs**

The largest import group. Everything here is expected for a file-encrypting process manager: `FindFirstFileW`/`FindNextFileW` for directory traversal, `CreateIoCompletionPort`/`GetQueuedCompletionStatus`/`PostQueuedCompletionStatus` for IOCP parallel encryption, `CreateToolhelp32Snapshot`/`Process32FirstW`/`Process32NextW` for process enumeration, `MapViewOfFile` for file-mapping encryption, and `TerminateProcess` for killing file holders. `Wow64DisableWow64FsRedirection` + `IsWow64Process` tell you this 32-bit binary knows it runs under WoW64 on 64-bit targets and disables filesystem redirection before accessing `System32`.

**`ADVAPI32.dll` — 28 APIs**

Four sub-groups: Windows CryptoAPI (`CryptAcquireContextA`, `CryptGenRandom`, `CryptImportKey`, `CryptEncrypt`) for the asymmetric key wrapper; service management (`OpenSCManagerW`, `CreateServiceW`, `StartServiceW`, `ControlService`, `DeleteService`) for the kernel driver loader; token manipulation (`OpenProcessToken`, `DuplicateTokenEx`, `GetTokenInformation`, `LookupAccountSidW`, `CreateProcessWithTokenW`) for privilege escalation; and registry operations (`RegCreateKeyExW`, `RegSetValueExW`, `RegDeleteValueW`, etc.) for persistence and icon registration.

**`RstrtMgr.DLL` — 5 APIs**

`RmStartSession`, `RmRegisterResources`, `RmGetList`, `RmShutdown`, `RmEndSession` — the complete Windows Restart Manager interface. DragonForce uses this to find which process holds a locked file, then terminates that process rather than skipping the file.

**`NETAPI32.dll` — 2 APIs**

`NetShareEnum` + `NetApiBufferFree`. These two calls enumerate all SMB shares on a remote host, feeding the lateral movement engine.

**`IPHLPAPI.DLL` — 1 API**

`GetIpNetTable` — one API, one purpose: read the ARP table to find every host that has communicated with this machine recently.

**`ole32.dll` + `OLEAUT32.dll` — 9 APIs combined**

`CoInitializeEx`, `CoInitializeSecurity`, `CoSetProxyBlanket`, `CoCreateInstance`, `CoUninitialize` from ole32 plus `SysAllocString`, `SysFreeString`, `VariantClear`, `VariantInit` from OLEAUT32. This is the standard COM/WMI invocation pattern for querying `Win32_ShadowCopy`. The specific combination of `CoInitializeSecurity` and `CoSetProxyBlanket` is the signature of impersonated WMI calls that bypass namespace-level security.

**`WS2_32.dll` — 15 APIs**

Full socket stack including `WSAIoctl` (for `SIO_GET_EXTENSION_FUNCTION_POINTER` to retrieve `ConnectEx`), `WSASocketW`, `bind`, `getsockopt`/`setsockopt`. The `ConnectEx` retrieval pattern combined with `CreateIoCompletionPort` is how high-performance IOCP-based port scanners work. DragonForce is scanning for live hosts directly from the encryptor process.

**`USER32.dll` — 2 APIs**

`SystemParametersInfoW` (wallpaper change) and `wsprintfW` (string formatting). The victim's desktop gets the ransomware wallpaper before note delivery.

## Encryption Engine

### Cipher: Salsa20

The clearest static evidence for the encryption scheme is in `.rdata`. At file offset `0x1936fc`, two adjacent 16-byte ASCII constants sit side by side:

```
0x1936e8: 65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b  "expand 16-byte k"
0x1936fc: 65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b  "expand 32-byte k"
```

These are the **tau** and **sigma** constants from the Salsa20 (and ChaCha20) stream cipher specification. Both Salsa20 and ChaCha20 use these exact strings for key expansion — `sigma` for 256-bit keys, `tau` for 128-bit keys. Present together, they indicate a Salsa20 or ChaCha20 implementation that supports both key lengths. The quarter-round operations are not recognisable from simple string analysis, but the presence of these constants is sufficient to confirm the cipher family.

For key material generation, the binary calls both `CryptGenRandom` (Windows CSPRNG) and uses a single `RDRAND` instruction at VA `0x4816a5`, accessed via `random_device::__x86_rdrand` — the C++ standard library's direct hardware RNG path. Per-file keys are logged as `build_key: %016llX` and `instance_key: %016llX`, confirming 64-bit key derivation values.

### Multi-Mode Encryption

DragonForce doesn't encrypt everything the same way. The debug strings embedded in the binary log four distinct modes:

```
%s: Full encrypt
%s: Header encrypt
%s: 20%% encrypt
%s: %d%% encrypt
%s: Custom encrypt %02x %d
```

Three thresholds control which mode applies to a given file:

```
full_encrypt_threshold: %d      → files below this: encrypt everything
header_encrypt_threshold: %d    → files between thresholds: encrypt header only
header_encrypt_size: %d         → how many bytes of header to encrypt
other_encrypt_chunk_percent: %d → for large files: encrypt N% of content
```

A small file gets fully encrypted. A medium file gets its header encrypted — enough to corrupt it but fast enough to process thousands of files quickly. Large files get a percentage of their chunks encrypted. The `20%` mode and the custom percentage mode are both logged separately, suggesting the operator can tune this at build time. Affiliates who need to process a 100TB file server in under an hour will set lower percentages; operations targeting smaller environments get full encryption by default.

### Windows CryptoAPI Wrapper

The Salsa20 key is protected by an asymmetric scheme built on Windows CryptoAPI:

1. `CryptAcquireContextA` — acquire a crypto provider context
2. `CryptGenRandom` — generate the per-file Salsa20 session key
3. `CryptImportKey` — import the operator's embedded RSA public key
4. `CryptEncrypt` — RSA-encrypt the Salsa20 key before writing it to the file header

The encrypted key header is written to each file alongside the ciphertext. Without the operator's RSA private key, the Salsa20 key is unrecoverable, which is why paying for the decryptor is the only practical path for victims who haven't maintained offline backups.

### File Extension

Encrypted files receive the extension `.df_win` (as seen from sandbox drops: `kz465if45i47msxc2iug.df_win`, etc.). The config field `custom_extension: %s` shows affiliates can override this — DragonForce sells per-deployment customisation, so extension and note filename vary by victim.

Filename encryption is optional: `encrypt_file_names: %d`. When enabled, the original filename becomes unreadable, giving victim directories names like `3pdx6ox4zstv.df_win`.

## Shadow Copy Deletion

DragonForce uses a two-step approach to destroy VSS snapshots: enumerate via WMI API, delete via WMIC command line.

**Step 1 — Enumerate via WMI:**

```
CoInitializeEx(NULL, COINIT_MULTITHREADED)
CoInitializeSecurity(..., RPC_C_IMP_LEVEL_IMPERSONATE, ...)
CoCreateInstance(CLSID_WbemLocator, ...)
ConnectServer(L"ROOT\\CIMV2", ...)
CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, 
                  NULL, RPC_C_AUTHN_LEVEL_CALL, 
                  RPC_C_IMP_LEVEL_IMPERSONATE, ...)
ExecQuery(L"SELECT * FROM Win32_ShadowCopy")
→ iterate results, extract each ID GUID
```

**Step 2 — Delete each shadow by GUID:**

```
cmd.exe /c C:\Windows\System32\wbem\WMIC.exe shadowcopy 
  where "ID='{ACE3F27F-40E7-46F0-9D5F-B60845C4AA79}'" delete
```

WMI query for the GUID, WMIC CLI delete per-GUID — this pattern shows up across ransomware families because it works: the WMI API gives structured results without output parsing, and `WMIC.exe` handles deletion without hitting the same detection signatures as direct `IVssBackupComponents` calls.

CAPE sandbox confirmed both shadow copies in the test environment were deleted before encryption completed.

## File Handle Management: Restart Manager + KillFileOwner

Ransomware fails silently when a target file is held open by another process. DragonForce handles this with two layers.

**Layer 1 — Windows Restart Manager:**

```
RmStartSession(phSession, 0, szSessionKey)
RmRegisterResources(dwSessionHandle, 1, &pstrFilenames, ...)
RmGetList(dwSessionHandle, &nProcInfoNeeded, &nProcInfo, rgAffectedApps, ...)
RmShutdown(dwSessionHandle, 0, ...)
RmEndSession(dwSessionHandle)
```

Restart Manager was designed to let Windows Update close files gracefully before patching. Ransomware repurposes it to find which process has a file open, then shut it down. The Restart Manager registry keys (`HKCU\SOFTWARE\Microsoft\RestartManager\Session0000`) are visible in all three sandboxes that captured this execution.

**Layer 2 — KillFileOwner:**

When Restart Manager's `RmShutdown` succeeds, the holding process is dead. When it fails — protected processes, kernel-held handles — DragonForce has a fallback logged as `KillFileOwner for file %s`. This function walks the process list with `CreateToolhelp32Snapshot` + `Process32NextW`, identifies the PID holding the file, and calls `TerminateProcess` directly. The driver is a third option: `[-] DeviceIoControl failed for PID: %d` shows kernel-level termination attempts when usermode fails.

## BYOVD: Killing EDR from the Kernel

Two signed but vulnerable kernel drivers are embedded by name in the binary:

```
rentdrv2    (wide string in .rdata)
trueSight   (wide string in .rdata)
```

`rentdrv2.sys` is the RentDrv2 driver from AuKill and similar BYOVD toolkits — a legitimate signed driver with an IOCTL interface that allows usermode code to terminate arbitrary kernel processes including those protected by PPL (Protected Process Light). `truesight.sys` is the Truesight driver, another signed kernel component with exploitable IOCTLs.

The loading sequence follows the standard BYOVD pattern, as seen from the debug strings:

```
[+] Creating service: %s
[+] Driver loaded successfully!
[-] DeviceIoControl failed for PID: %d
```

1. Drop the driver to disk
2. `OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE)`
3. `CreateServiceW(SERVICE_KERNEL_DRIVER, ...path_to_.sys...)`
4. `StartServiceW`
5. `CreateFileW` to open the driver device object
6. `DeviceIoControl` with the termination IOCTL and target PID

The config field `use_sys: %d` lets the operator disable the driver entirely — for deployments where the EDR has already been killed by the access broker's toolchain before the encryptor runs.

The debug log `ERunning under: %s` tracks the integrity level — DragonForce checks whether it's already elevated before deciding whether to load the driver or proceed directly to encryption.

## Privilege Escalation: Token Impersonation → SYSTEM

The encryptor doesn't require SYSTEM to encrypt files, but it does need elevated privileges to install kernel services and manipulate protected processes. The escalation path uses token duplication:

```
OpenProcessToken(explorer.exe_handle, TOKEN_DUPLICATE, &hToken)
DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, 
                 SecurityImpersonation, TokenPrimary, &hNewToken)
GetTokenInformation(hNewToken, TokenUser, ...)
LookupAccountSidW(NULL, pSid, szName, ...)  → confirm "NT AUTHORITY\SYSTEM" or user SID
CreateProcessWithTokenW(hNewToken, 0, NULL, szCommandLine, 0, NULL, NULL, &si, &pi)
```

The debug string `Restarting as SYSTEM` confirms the binary restarts itself with the duplicated token when the current token isn't privileged enough. The WoW64 layer is aware: `IsWow64Process` + `Wow64DisableWow64FsRedirection` ensure the 32-bit process accesses `C:\Windows\System32` rather than the redirected `SysWOW64`.

## Scheduled Task Persistence

DragonForce registers a scheduled task via COM to survive reboots. The full COM task creation chain:

```cpp
CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                 IID_ITaskService, (void**)&pService)
pService->Connect(...)
pService->GetFolder(L"\\", &pRootFolder)
pService->NewTask(0, &pTask)
pTask->get_RegistrationInfo(&pRegInfo)
pRegInfo->put_Description(L"<job_description>")  // configurable
pRegInfo->put_Author(...)
pTask->get_Triggers(&pTriggerCollection)
pTriggerCollection->Create(TASK_TRIGGER_TIME, &pTrigger)
pTimeTrigger->put_Id(...)
pTimeTrigger->put_StartBoundary(L"<job_start>")    // HH:MM format
pTimeTrigger->put_EndBoundary(...)
pTask->get_Actions(&pActionCollection)
pActionCollection->Create(TASK_ACTION_EXEC, &pAction)
pExecAction->put_Path(L"<job_executable>")          // path to self
pRootFolder->RegisterTaskDefinition(L"<job_title>", ...)
```

Config fields `job_title`, `job_description`, `job_executable`, and `job_start` are all affiliate-customisable, meaning the task name and timing vary by deployment.

## Network Discovery and Lateral Movement

DragonForce doesn't rely on the deployment team to have already mapped the network. It discovers live targets itself.

**ARP table scan:**

```cpp
GetIpNetTable(pIpNetTable, &dwSize, false)
// iterate pIpNetTable->table[i].dwAddr for each neighbour
```

Every host that has an ARP entry on the infected machine's network is a candidate. This covers the local subnet without generating any network probe traffic — the ARP table is already populated from normal traffic.

**SMB share enumeration:**

```cpp
NetShareEnum(szServer, 1, &pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, 
             &dwTotalEntries, NULL)
// SHARE_INFO_1.shi1_type == STYPE_DISKTREE → file share
```

For each host discovered via ARP, `NetShareEnum` retrieves all accessible file shares. Shares of type `STYPE_DISKTREE` are added to the encryption work queue.

**IOCP port scanner:**

```
Can't get ConnectEx.
Can't create io completion port.
Can't create port scan thread.
Starting search on share %s.
```

The binary uses `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, WSAID_CONNECTEX)` to retrieve the `ConnectEx` function pointer, then builds an IOCP-backed TCP scanner. Multiple threads post connection completion packets to a completion port; the main thread harvests results. This is the same IOCP pattern the encryption engine uses for file I/O — the same event-driven concurrency model applied to network scanning.

## Desktop Modification

Before the note appears, the victim's desktop changes. DragonForce reads an embedded wallpaper image from the binary (`Reading wallpaper @ %d size %d`) and writes it to a temporary path, then:

```cpp
SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, szWallpaperPath, 
                      SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)
RegSetValueExW(HKCU\\Control Panel\\Desktop, L"WallpaperStyle", ...)
```

The file association for `.df_win` is also registered so encrypted files display a custom icon:

```cpp
RegCreateKeyExW(HKCU, L"Software\\Classes\\.df_win\\DefaultIcon", ...)
RegSetValueExW(hKey, L"", 0, REG_SZ, szIconPath, ...)
```

When the victim opens Explorer, every encrypted file shows the DragonForce icon. The visual impact is intentional — it raises the psychological pressure before the victim opens `readme.txt`.

## Ransom Note Analysis

`readme.txt` is dropped in every directory. The note drops the cartel branding immediately:

> *"Good afternoon. As you can see you have been attacked by a ransomware program! We The DragonForce Ransomware Cartel offer you to make a deal with us."*

The note offers the usual negotiation package: test decryption of a few files, a list of what was exfiltrated, and a price the operator will set "based on your income/your insurance." The deletion date is hardcoded in each deployed build (`02/09/2025 00:00 UTC` in this sample, consistent with the September 2025 first-seen date).

Contact is through Tor:
- **Negotiation room:** `3pktcrcbmssvrnwe5skburdwe2h3v6ibdnn5kbjqihsg6eu6s6b7ryqd.onion`
- **Leak blog / DragonNews:** `z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid.onion`
- **Tox:** `1C054B722BCBF41A918EF3C485712742088F5C3E81B2FDD91ADEA6BA55F4A856D90A65E99D20`

The victim ID embedded in this sample is `F744871F84DDF60CF744871F84DDF60C` — 32 hex characters (16 bytes, 128-bit) uniquely identifying this deployment to the operator's Tor panel.

## Execution Timeline

The execution order, reconstructed from the debug log sequence and import dependencies:

1. **Mutex check** — `CreateMutexA("hsfjuukjzloqu28oajh727190")` prevents double-execution (bypassed with `-nomutex`)
2. **Elevation check** — `GetTokenInformation` + `LookupAccountSidW`, logs `Process is elevated: %d`
3. **Token escalation** — if not SYSTEM: `DuplicateTokenEx(explorer.exe)` → `CreateProcessWithTokenW` → restart
4. **Driver load** — if `use_sys=1`: drop + load `rentdrv2.sys`/`truesight.sys` via service creation
5. **Process enumeration** — `CreateToolhelp32Snapshot` to build kill list
6. **Shadow copy deletion** — WMI query → WMIC CLI delete per GUID
7. **Network discovery** — `GetIpNetTable` → `NetShareEnum` + IOCP port scan
8. **IOCP thread pool** — `CreateIoCompletionPort` + thread pool (sized to logical CPU count)
9. **Directory walk** — `GetLogicalDriveStringsW` → recursion through all drives + network shares
10. **Per-file** — Restart Manager → KillFileOwner if needed → gen key → Salsa20 encrypt → rename to `.df_win`
11. **Wallpaper + icon** — `SystemParametersInfoW` + registry icon registration
12. **Note drop** — write `readme.txt` to every encrypted directory
13. **Scheduled task** — COM task scheduler → persistence for next reboot

## YARA Detection Rule

```yara
rule DragonForce_Win32_Encryptor {
    meta:
        description = "DragonForce ransomware Win32 encryptor - MinGW C++, Salsa20, BYOVD"
        hash = "f58af71e542c67fbacf7acc53a43243a5301d115eb41e26e4d5932d8555510d0"
        author = "ThreatUnpacked"
        date = "2026-07-07"
    strings:
        // Salsa20 cipher constants in .rdata
        $salsa20_sigma = "expand 32-byte k" ascii
        $salsa20_tau   = "expand 16-byte k" ascii

        // BYOVD driver names (wide string, no .sys suffix internally)
        $byovd_rent   = "rentdrv2" wide
        $byovd_sight  = "trueSight" wide

        // Mutex (wide string in memory)
        $mutex = "hsfjuukjzloqu28oajh727190" wide

        // Shadow copy deletion
        $shadow_query = "SELECT * FROM Win32_ShadowCopy" wide
        $shadow_wmic  = {73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00
                         20 00 77 00 68 00 65 00 72 00 65 00}  // "shadowcopy where" wide

        // File handle killer
        $kill_owner = "KillFileOwner" wide

        // Encrypted file extension
        $df_ext = ".df_win" wide

        // WoW64 bypass (32-bit process on 64-bit OS)
        $wow64 = "Wow64DisableWow64FsRedirection" ascii

        // Note filename
        $note = "readme.txt" wide

    condition:
        uint16(0) == 0x5A4D and
        filesize > 1MB and filesize < 3MB and
        $salsa20_sigma and ($byovd_rent or $byovd_sight) and
        3 of ($mutex, $shadow_query, $shadow_wmic, $kill_owner, $df_ext, $note)
}
```

## IOCs

| Type | Value |
|------|-------|
| SHA-256 | `f58af71e542c67fbacf7acc53a43243a5301d115eb41e26e4d5932d8555510d0` |
| Mutex | `hsfjuukjzloqu28oajh727190` |
| File extension | `.df_win` |
| Ransom note | `readme.txt` |
| Note hash (SHA-256) | `04b14ead49adea9431147c145a89c07fea2c6f1cb515d9d38906c7696d9c91d5` |
| Driver (BYOVD) | `rentdrv2.sys` |
| Driver (BYOVD) | `truesight.sys` |
| Scheduled task | job_title/description configurable per affiliate |
| Tox contact | `1C054B722BCBF41A918EF3C485712742088F5C3E81B2FDD91ADEA6BA55F4A856D90A65E99D20` |
| Tor panel | `3pktcrcbmssvrnwe5skburdwe2h3v6ibdnn5kbjqihsg6eu6s6b7ryqd.onion` |
| Leak blog | `z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid.onion` |

## Wrap-Up

DragonForce's encryptor is a well-engineered C++ binary that goes significantly beyond commodity ransomware. The combination of Salsa20 multi-mode encryption, BYOVD kernel driver EDR bypass, Restart Manager-backed file handle killing, and an embedded IOCP port scanner makes this a tool built by people who understood what was going to stand between them and a fully encrypted enterprise network.

The M&S and Co-op UK attacks got the headlines. The binary explains the rest: 1.7MB of 32-bit C++, a timestamp set to 1970, 236 imported APIs across ten DLLs, and two kernel driver names that have no business appearing in a ransomware process list.
