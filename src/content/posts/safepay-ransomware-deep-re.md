---
title: "SafePay Ransomware: Deep Reverse Engineering of a LockBit 3.0 Fork"
description: "Assembly-level analysis of SafePay ransomware — a LockBit 3.0 derivative with a custom CRC-32 import resolver, triple-XOR string obfuscation, IOCP-driven parallel encryption, and NT-layer privilege escalation. Full API inventory recovered by cracking 130+ export hashes."
pubDate: "2026-07-05T12:00:00"
permalink: "/2026/07/05/safepay-ransomware-lockbit-fork-deep-re/"
tags: ["Ransomware", "Reverse Engineering", "SafePay", "LockBit", "Malware Analysis"]
thumb: "/images/safepay-ransomware-deep-re-thumb.svg"
draft: false
---

SafePay first surfaced in November 2024. Blackpoint Cyber confirmed it publicly as a LockBit 3.0 fork — built from the leaked builder that went public in 2022. The group has since been linked to attacks across healthcare, manufacturing, and financial services, claiming roughly 40 victims through early 2026 before going quiet.

The sample I analysed (`a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526`) is a Win32 PE DLL, 110,592 bytes, x86. It arrives as `locker.dll` and requires invocation via `rundll32.exe`:

```
rundll32.exe locker.dll,DllInstall -pass=<32-byte-key>
```

That `-pass=` flag is where I expected the story to begin. It ended up being a red herring.

## The Encryptor at a Glance

Nearly every import in this DLL is resolved by hand at runtime rather than declared in the PE header, so before the assembly-level walkthrough, here's the shape of what actually happens between `DllInstall` being called and the first file being encrypted.

```mermaid
flowchart TD
  A["1 · Resolve own imports<br/><i>custom CRC-32 hash walk of the PEB — no import table to read</i>"] --> B["2 · Decrypt strings<br/><i>triple-XOR keyed off the running kernel32 image</i>"]
  B --> C["3 · Anti-analysis gates<br/><i>PEB.BeingDebugged check · CIS keyboard-layout exit</i>"]
  C --> D["4 · Escalate privilege<br/><i>CMSTPLUA COM UAC bypass — no prompt shown</i>"]
  D --> E["5 · Destroy recovery<br/><i>kill processes/services · direct-IOCTL shadow copy delete</i>"]
  E --> F["6 · Encrypt<br/><i>IOCP thread pool, local + network shares</i>"]
```
<span class="fig-cap">Fig 1 — nothing here is unique to SafePay individually; the LockBit 3.0 lineage shows in exactly this sequence, mirrored step for step.</span>

---

## The Binary

```
File      locker.dll
MD5       28c2c55b9bf0db5f22a0b48d47cd44e4
SHA-256   a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526
Size      110,592 bytes
Type      Win32 PE DLL, x86
Exports   DllInstall (ord 1), DllRegisterServer (ord 2)
```

Section layout:

```
Section   VA       VSize    Entropy
.text     0x1000   47943    6.82    ← code
.data     0xd000   25568    0.56    ← almost entirely zeros at rest
.idata    0x14000  584      3.34    ← only 21 imports
.debug    0x15000  32768    3.97    ← NOT debug symbols — config storage
.reloc    0x1d000  1980     6.60    ← relocations
```

The `.data` section has 0.56 entropy at rest — nearly flat zeros. Everything initialises at runtime. The `.debug` section is 32KB of non-debug data at 3.97 entropy: almost certainly encrypted configuration. The `.idata` has only 21 imports, split between KERNEL32 and USER32. The binary calls fewer than five of them directly. Everything else is resolved dynamically at startup.

**Static imports** (the only ones visible without execution):

```
KERNEL32:  HeapCreate HeapDestroy HeapAlloc HeapReAlloc HeapFree GetProcessHeap
           GetLastError CloseHandle FormatMessageW MapViewOfFile TlsFree
           OpenSemaphoreW GetCommandLineW MultiByteToWideChar
USER32:    DefDlgProcW MessageBoxA GetCursor LoadCursorW CreateCursor
           GetCursorInfo wsprintfW
```

`GetCommandLineW` in the static import list is telling. It means the binary reads its command line before the dynamic loader runs.

---

## Entry Points

`DllRegisterServer` (ordinal 2) is a one-liner: it calls `DllInstall(0, 0)`. Everything runs through `DllInstall`.

`DllInstall` (RVA `0x3450`) opens with a 808-byte stack frame, saves `bInstall`, then immediately calls the import resolver:

```asm
0x10003462: call    0x10001390      ; import resolver — returns 0 on failure
0x10003467: test    eax, eax
0x10003469: jne     0x10003472
0x1000346b: push    eax
0x1000346c: call    dword ptr [0x1000d3f4]  ; ExitProcess(0)
```

If the resolver returns zero — which it will if it cannot walk the PEB correctly — the binary exits cleanly. No crash, no error box. Sandbox evasion by design.

---

## Import Resolution: Custom CRC-32, Not ror13

<aside class="callout">
<span class="lead">Concept — why resolve imports by hand at all</span>
A PE's import table is a plaintext list: "this binary calls <code>CreateFileW</code>, <code>WriteFile</code>, ..." — exactly the list a defender or scanner reads first. Malware authors avoid that list by leaving the import table nearly empty and instead <i>finding</i> the functions themselves at runtime: walk the Process Environment Block (a structure every process has, listing its own loaded modules) to locate a DLL by name, then walk that DLL's export table to locate a function by name — without ever writing the plaintext name <code>CreateFileW</code> anywhere in the file. Comparing a <b>hash</b> of the name instead of the name itself hides the target from static string scanning too. The only "leak" is the hash constant itself, which is meaningless without the algorithm and seed used to produce it.
</aside>

Most shellcode and custom loaders use a **ror13** (rotate-right-13) hash to identify exports. SafePay does not. It uses a **CRC-32/POSIX** hash with polynomial `0x04C11DB7` — the non-reflected, big-endian form. The table is generated at runtime (not stored in the PE) by function `0x100017c0`:

```asm
; Generate CRC-32/POSIX table into .data at 0x1000d588
0x100017c0: xor     ecx, ecx            ; i = 0
0x100017c2: mov     eax, ecx
0x100017c4: shl     eax, 0x18           ; crc = i << 24
; 8 iterations (unrolled):
0x100017c9: jns     0x100017d4          ; if MSB clear, skip XOR
0x100017cb: add     eax, eax            ; crc <<= 1
0x100017cd: xor     eax, 0x4c11db7     ; crc ^= polynomial
...
0x1000183f: mov     dword ptr [ecx*4 + 0x1000d588], eax  ; table[i] = crc
0x10001846: inc     ecx
0x10001847: cmp     ecx, 0x100
0x1000184d: jb      0x100017c2
```

The **hash function** (`0x10001300`) takes a byte string, lowercases it, then runs CRC-32/POSIX:

```python
def safepay_hash(name: str) -> int:
    # Lowercase: same as XOR 0x20 for A-Z bytes
    data = bytes(c | 0x20 if 0x41 <= c <= 0x5a else c for c in name.encode())
    crc = 0xFF                    # non-standard initial value
    for byte in data:
        idx = ((crc >> 24) ^ byte) & 0xFF
        crc = ((crc << 8) & 0xFFFFFFFF) ^ CRC_TABLE[idx]
    return crc
```

The initial value is `0xFF` (not the standard `0xFFFFFFFF`). That alone breaks any generic ror13 decoder and makes the hashes opaque to signature-based tools.

**DLL discovery** uses the same hash against the PEB's `InMemoryOrderModuleList`. The PEB walk (`0x100011e0`) iterates loaded modules, hashes each `BaseDllName` (as raw UTF-16LE bytes), and returns the base address when it finds a match:

```asm
0x100011e0: mov     eax, dword ptr fs:[0x30]   ; PEB
0x100011e8: mov     eax, dword ptr [eax + 0xc] ; PEB.Ldr
0x100011eb: mov     edi, dword ptr [eax + 0x14] ; list head
0x10001200: movzx   eax, word ptr [esi + 0x24] ; BaseDllName.Length
0x1000120a: push    dword ptr [esi + 0x28]     ; BaseDllName.Buffer
0x1000120d: call    0x10001300                 ; hash it
0x10001215: cmp     eax, 0xcab3c8c9            ; target hash
0x1000121a: je      0x10001227                 ; found!
```

Hash `0xcab3c8c9` is `hash("kernel32.dll")` in UTF-16LE — confirmed by running the function against all loaded DLL names. The hash for `"ntdll.dll"` is `0xb48a6847`.

The **export resolver** (`0x10001240`) takes a DLL base and a target hash, walks the PE export directory, hashes each function name, and returns the matching function pointer. This is applied to 130+ API hashes stored across eight hash tables in `.data`.

```mermaid
flowchart TD
  PEB["TEB → PEB<br/>fs:[0x30]"] --> LDR["PEB.Ldr.InMemoryOrderModuleList"]
  LDR --> ITER["for each loaded module:<br/>hash(BaseDllName)"]
  ITER -->|"hash == 0xcab3c8c9"| K32["found: kernel32.dll base"]
  K32 --> EXP["walk kernel32's export directory"]
  EXP --> ITER2["for each exported name:<br/>hash(name)"]
  ITER2 -->|"hash == target from .data table"| FN["resolved function pointer<br/>e.g. CreateFileW"]
```
<span class="fig-cap">Fig 2 — the same hash-and-walk pattern runs twice: once to find a DLL by name among loaded modules, once to find a function by name inside that DLL's own export table. Neither "kernel32.dll" nor "CreateFileW" ever appears as a readable string.</span>

---

## String Obfuscation: Triple-XOR with a Structural Key

Strings are stored inline on the stack as encrypted byte sequences and decrypted immediately before use. The decryption:

```asm
; Example: 22-byte encrypted string, constant 0xda
0x100034d0: mov     edx, dword ptr [0x1000d3c8] ; edx = kernel32 base address
0x100034d6: xor     ecx, ecx                    ; i = 0
0x100034d8: mov     dword ptr [ebp - 0x16], 0x94fa96db
; ... push remaining encrypted bytes onto stack ...
0x10003501: mov     al, byte ptr [ebp + ecx - 0x16]  ; load encrypted byte
0x10003505: xor     al, byte ptr [edx]               ; XOR with kernel32_base[0]
0x10003507: xor     al, cl                            ; XOR with loop counter
0x10003509: xor     al, 0xda                          ; XOR with per-string constant
0x1000350b: mov     byte ptr [ebp + ecx - 0x16], al  ; store plaintext
0x1000350f: inc     ecx
0x10003510: cmp     ecx, 0x16                        ; loop 22 times
0x10003513: jb      0x10003501
```

The formula: `plaintext[i] = encrypted[i] ^ kernel32_base[0] ^ i ^ constant`

```mermaid
flowchart LR
  E["encrypted byte<br/>[i]"] --> X1["XOR kernel32_base[0]<br/>always 0x4D ('M', the MZ header)"]
  X1 --> X2["XOR i<br/>(loop counter)"]
  X2 --> X3["XOR constant<br/>(unique per string)"]
  X3 --> P["plaintext byte"]
```
<span class="fig-cap">Fig 3 — three XORs, none of which need an operator-supplied secret. The "key" is a byte that's already sitting in memory the moment kernel32 is loaded — every SafePay sample decrypts the same way regardless of build.</span>

`[edx]` — the first byte at `kernel32_base` — is always `0x4D` ('M' from the MZ header). This means the "key" is structural: it comes from the runtime PE layout, not from any operator-supplied argument. The per-string `constant` varies (observed values: `0xda`, `0x68`, `0x48`, `0x95`, `0x26`, `0x19`, `0xf1`, `0xac`, `0x4b`). Different constants produce different-looking ciphertext for strings with similar content.

The deobfuscator in Python:

```python
def decrypt_string(enc_bytes: bytes, constant: int) -> bytes:
    KEY_BYTE = 0x4D   # kernel32.dll MZ header first byte
    return bytes(b ^ i ^ KEY_BYTE ^ constant
                 for i, b in enumerate(enc_bytes))
```

Applying this to recover all DLL names loaded at startup:

| Constant | Length | Decrypted |
|---|---|---|
| `0x68` | 13 | `advapi32.dll` |
| `0x95` | 13 | `kernel32.dll` (via LoadLibraryA for HMODULE) |
| `0x26` | 10 | `ole32.dll` |
| `0x19` | 12 | `shell32.dll` |
| `0xf1` | 10 | `ntdll.dll` |
| `0xac` | 8  | `mpr.dll` |
| `0x4b` | 11 | `user32.dll` |

---

## Full API Inventory

The import resolver runs seven DLL loading loops in sequence, totalling approximately 130 resolved API pointers. All entries below were recovered by running the CRC-32/POSIX cracker against each hash table.

### kernel32.dll (59 APIs)

File I/O and encryption pipeline:
```
CreateFileW       ReadFile          WriteFile         FlushFileBuffers
SetFileAttributesW  GetFileAttributesW  DeleteFileW     SetFileInformationByHandle
FindFirstFileExW  FindNextFileW     FindClose
```

IOCP-based parallel encryption engine:
```
CreateIoCompletionPort  GetQueuedCompletionStatus  PostQueuedCompletionStatus
CreateThread            WaitForSingleObject         CancelIo
```

Thread synchronisation:
```
InitializeCriticalSection  EnterCriticalSection  LeaveCriticalSection  DeleteCriticalSection
CreateMutexW
```

Process and service termination:
```
CreateToolhelp32Snapshot  Process32FirstW  Process32NextW
OpenProcess               TerminateProcess  GetProcessId
```

Volume enumeration and shadow copy deletion:
```
GetLogicalDrives   GetDriveTypeW      FindFirstVolumeW   FindNextVolumeW
FindVolumeClose    DeviceIoControl    GetVolumePathNamesForVolumeNameW
SetVolumeMountPointW
```

Heap and loader:
```
HeapAlloc  HeapFree  LoadLibraryA
```

Miscellaneous:
```
ExitProcess  Sleep  GetTickCount  GetSystemTime  GetSystemDirectoryW
GetCommandLineW  FreeConsole  SetUnhandledExceptionFilter
lstrcatW  lstrcpyW  lstrlenW  lstrcmpiW  lstrcmpW
```

### advapi32.dll (21 APIs)

Cryptography (key material generation):
```
CryptGenRandom    CryptAcquireContextW    CryptReleaseContext
```

Service control (hardcoded kill list):
```
OpenSCManagerW    OpenServiceW    ControlService    QueryServiceStatusEx
EnumDependentServicesW    CloseServiceHandle
```

Token and privilege:
```
AdjustTokenPrivileges  LookupPrivilegeValueA  CheckTokenMembership
CreateWellKnownSid     DuplicateToken         GetSecurityInfo  SetSecurityInfo
```

Registry (persistence/config):
```
RegCreateKeyExW  RegSetValueExW  RegCloseKey  RegDeleteValueW
```

### ole32.dll (3 APIs)

```
CoCreateInstance    CoInitializeEx    CoUninitialize
```

These three are the CMSTPLUA COM UAC bypass triad — the same pattern used by LockBit 3.0. `CoCreateInstance` instantiates the `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` (CMSTPLUA) class object, which allows elevation without a UAC prompt when run from a medium-integrity context.

### shell32.dll (3 APIs)

```
ShellExecuteW    CommandLineToArgvW    [1 uncracked]
```

`ShellExecuteW` is the elevation trigger: the elevated process is re-launched with `ShellExecute(..., "runas", ...)` after CMSTPLUA produces an elevated COM object.

### ntdll.dll (19 APIs)

NT-layer memory and threading:
```
NtAllocateVirtualMemory    NtFreeVirtualMemory
NtSetInformationThread     NtResumeThread    NtTerminateThread
NtSetInformationProcess
```

NT-layer token manipulation (bypasses some API monitoring):
```
NtOpenProcessToken    NtQueryInformationToken
```

Privilege adjustment (direct NT call, bypasses advapi32 logging):
```
RtlAdjustPrivilege
```

Process:
```
NtOpenProcess    NtClose
```

### mpr.dll (3 APIs)

Network share enumeration:
```
WNetOpenEnumW    WNetEnumResourceW    WNetCloseEnum
```

These three map directly to SafePay's `-network` flag behaviour: enumerate all reachable network resources and add them to the encryption work queue.

### user32.dll (2 APIs — uncracked)

Two hashes from user32.dll that did not match any standard export list. Likely `GetSystemMetrics` (checking display/session state) and one of the `SendMessage`/`PostMessage` family.

---

## Anti-Analysis

### Anti-debug: PEB.BeingDebugged

Between loading ntdll and mpr, the init routine checks the PEB `BeingDebugged` byte directly:

```asm
0x100016b5: mov     eax, dword ptr fs:[0x30]    ; PEB
0x100016bb: cmp     byte ptr [eax + 2], 0       ; PEB.BeingDebugged
0x100016bf: je      0x100016c9                  ; not debugged, continue
0x100016c1: push    0
0x100016c3: call    dword ptr [0x1000d3f4]      ; ExitProcess(0)
```

Classic but effective. Placed mid-init (not at entry point) to catch debuggers that attach after the initial PEB walk completes.

### CIS keyboard layout kill switch

The CIS exclusion runs early in `DllInstall`, before encryption starts. It checks the active keyboard layout:

```
GetKeyboardLayout → HKL
LOWORD(HKL) checks against: RU, UA, BY, KZ, KY, TJ, UZ, TM, GE, AM, AZ
```

If any CIS layout is active, the binary calls `ExitProcess(0)`.

### PE timestamp erasure

`TimeDateStamp` is `0x00000000` — not a plausible build date, not `0xFFFFFFFF`. Deliberately zeroed.

---

## Encryption Architecture

### Parallel I/O with IOCP

SafePay uses Windows I/O Completion Ports for parallel file encryption — same architecture as LockBit 3.0:

1. A **director thread** walks the file system (FindFirstFileExW / FindNextFileW), posting work items to the completion port.
2. **N worker threads** (N = logical CPU count) call `GetQueuedCompletionStatus` in a loop. Each dequeued item is a file path. The worker opens it, reads blocks, encrypts, and writes back.
3. `CancelIo` is called on handles where the previous operation was interrupted, to prevent stalls.

The IOCP model allows SafePay to maintain maximum disk throughput: while one worker is blocked waiting on a read, others continue processing. The `-enc=1-9` intermittent encryption flag (parsed from `GetCommandLineW`) adjusts what fraction of each file is encrypted — lower values complete faster but leave more plaintext recoverable.

### Key material: CryptGenRandom, not BCrypt

Key generation uses `CryptGenRandom` from advapi32 rather than the BCrypt* family. This is simpler and adequate for generating a per-session symmetric key, but it means the ransomware is NOT using the `BCryptSecretAgreement` path that some LockBit variants use for x25519 ECDH. The actual per-file key derivation and ChaCha20 encryption are implemented as custom code in `.text` — no Windows crypto API is called for the actual cipher operations.

---

## Privilege Escalation

### SeDebugPrivilege and SeBackupPrivilege

Before process and service termination, the binary enables elevated privileges using two paths:

**advapi32 path** (for medium-integrity processes):
```
OpenProcessToken → current process token
AdjustTokenPrivileges → enable SeDebugPrivilege, SeBackupPrivilege, SeTakeOwnershipPrivilege
```

**ntdll direct path** (bypasses advapi32 hook points):
```
NtOpenProcessToken + NtQueryInformationToken → get token info
RtlAdjustPrivilege(20, TRUE, FALSE, &prev)   ; 20 = SeDebugPrivilege
```

The dual-path approach means that security products hooking advapi32's `AdjustTokenPrivileges` will miss the ntdll direct call.

### CMSTPLUA UAC bypass

<aside class="callout">
<span class="lead">Concept — a UAC bypass that isn't an exploit</span>
UAC's prompt exists to stop a program from silently gaining admin rights. But Windows ships a handful of COM objects that are pre-registered to run <b>elevated</b> and are trusted not to need a prompt themselves — CMSTPLUA (used by the legitimate Connection Manager) is one. If a medium-integrity process instantiates that COM object and calls its exposed method to run a command, the command inherits the COM object's elevated context. No prompt appears because, as far as UAC's bookkeeping is concerned, nothing asked for elevation — an already-elevated, already-trusted component just did something on the caller's behalf. This is an auto-elevate design flaw class, not a memory-corruption bug, which is why it has survived across so many Windows versions and so many ransomware families.
</aside>

The CMSTPLUA bypass is used when the process runs at medium integrity:

1. `CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)`
2. `CoCreateInstance` with CLSID `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` → `ICMLuaUtil` interface
3. `ICMLuaUtil::ShellExec` to run a high-integrity copy of `locker.dll`

```mermaid
sequenceDiagram
  participant M as SafePay (medium integrity)
  participant C as CMSTPLUA COM object<br/>(auto-elevate, trusted)
  participant O as OS
  M->>O: CoCreateInstance(CLSID_CMSTPLUA)
  O-->>M: ICMLuaUtil interface<br/>(already running elevated — no prompt)
  M->>C: ICMLuaUtil::ShellExec("rundll32 locker.dll ...")
  C->>O: launch process
  Note over O: new process inherits<br/>CMSTPLUA's elevated integrity level
```
<span class="fig-cap">Fig 4 — the malware never asks Windows for elevation; it asks an already-elevated component to run something for it.</span>

This is identical to the LockBit 3.0 UAC bypass chain — confirming the lineage without needing the builder.

---

## Process and Service Termination

### Process kill list

Process enumeration: `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)`, then `Process32FirstW` / `Process32NextW`. Each process name is compared against an encrypted inline list. The list is decrypted at runtime using the same triple-XOR scheme.

Process kill targets (decrypted from inline encrypted list, corroborated by prior public analysis):

```
sql.exe  sqlservr.exe  oracle.exe  mysqld.exe  firefox.exe  chrome.exe
msedge.exe  excel.exe  winword.exe  outlook.exe
sagent.exe  SavService.exe  VeeamAgent.exe  beserver.exe
```

`TerminateProcess` is called on each match after `OpenProcess(PROCESS_TERMINATE, ...)`.

### Service kill list

The service stop sequence uses dependency-aware ordering:

1. `OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS)` → hSCM
2. For each target service name (decrypted inline): `OpenServiceW` → hSvc
3. `EnumDependentServicesW` to find dependent services
4. Stop dependents first: `ControlService(hSvc, SERVICE_CONTROL_STOP, &status)`
5. `QueryServiceStatusEx` to confirm stopped state
6. Stop the target service

Services targeted include backup and security products (Veeam, Sophos, Acronis, Windows Backup Service).

---

## Volume Shadow Copy Deletion

Shadow copy deletion goes through `DeviceIoControl` rather than the more easily monitored `vssvc` / `vssadmin` path:

```
FindFirstVolumeW / FindNextVolumeW  → enumerate all volumes
GetVolumePathNamesForVolumeNameW    → resolve volume paths
DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY) → find VSS snapshot IDs
SetVolumeMountPointW               → manipulate mount points
```

This mirrors the LockBit 3.0 direct-IOCTL VSS deletion technique, bypassing `CreateVssBackupComponents`.

Recovery prevention also uses bcdedit, run via `ShellExecuteW`:
```
bcdedit /set {default} recoveryenabled no
bcdedit /set {default} bootstatuspolicy ignoreallfailures
```

---

## Network Propagation

When launched with `-network`, SafePay enumerates network shares via:

```
WNetOpenEnumW(RESOURCE_GLOBALNET, RESOURCETYPE_DISK, ...)
WNetEnumResourceW → iterate entries
WNetCloseEnum
```

Each discovered UNC path is added to the file encryption work queue alongside local volumes. If the share is accessible with current credentials, it gets encrypted. No lateral movement credential spraying is performed — this relies entirely on whatever permissions the compromised account already has.

---

## Timeline and Connections

| | |
|---|---|
| **First seen** | November 2024 |
| **Sample analysed** | November 2024 |
| **Builder** | LockBit 3.0 leaked (September 2022) |
| **Confirmed by** | Blackpoint Cyber, Huntress |
| **Connection** | BlackSuit (QDoor backdoor), Conti TTPs |
| **Active period** | November 2024 — early 2026 |

SafePay is one of several groups that spun up using the leaked LockBit 3.0 builder. The custom CRC-32/POSIX hash and the dual-path privilege escalation (advapi32 + ntdll direct) tell you these aren't people who grabbed the builder without reading the source — they understood what they were modifying.

---

## Detection Notes

### YARA — import hash table

```yara
rule SafePay_ImportHashTable {
    meta:
        description = "SafePay ransomware - CRC-32/POSIX import hash table signature"
        hash = "a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526"
    strings:
        // First 4 DWORDs of kernel32.dll hash table
        $hash_table = { 86 51 76 67 BE 88 59 EA 01 CD A2 EE FD 76 21 62 }
        // DllInstall export name
        $export = "DllInstall" ascii
        // CRC-32 polynomial constant (0x04C11DB7) in CRC table generator
        $crc_poly = { B7 1D C1 04 }
    condition:
        uint16(0) == 0x5A4D and
        all of them
}
```

### YARA — string decryption loop

```yara
rule SafePay_StringDecrypt {
    meta:
        description = "SafePay triple-XOR string decryption loop"
    strings:
        // xor al, [edx] / xor al, cl / xor al, 0xNN pattern
        $decrypt_loop = { 32 02 32 C1 34 ?? }
    condition:
        uint16(0) == 0x5A4D and
        pe.characteristics & pe.DLL and
        #decrypt_loop > 5
}
```

### Behaviour

- `rundll32.exe` spawned with DllInstall export — unusual for legitimate DLLs
- `bcdedit /set {default} recoveryenabled no` via ShellExecuteW
- Process creates IOCP (`NtCreateIoCompletion`) and spawns thread pool immediately
- PEB.BeingDebugged check causes silent clean exit under a debugger — monitor for immediate `ExitProcess` calls in `rundll32`
- advapi32 `CryptAcquireContextW` with `PROV_RSA_AES` provider at startup (key generation phase)
- No network C2 observed in this sample — static configuration only

---

## IOCs

```
# Sample
a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526  locker.dll

# Import hash constants (CRC-32/POSIX, initial value 0xFF)
LoadLibraryA      0x67765186
CreateFileW       0x16869a35
WriteFile         0x94e921ac
ReadFile          0xcae458a0
CryptGenRandom    0x6d3a664a
ExitProcess       0xa53d1f6a
DeviceIoControl   0x2f472fb9
OpenSCManagerW    0xea3efb42
ControlService    0xe8cb7ce9

# String XOR constants
advapi32.dll constant: 0x68
ntdll.dll constant:    0xf1
ole32.dll constant:    0x26
shell32.dll constant:  0x19
mpr.dll constant:      0xac
user32.dll constant:   0x4b

# Kernel32 hash (for PEB walk detection)
0xcab3c8c9  →  kernel32.dll
```
