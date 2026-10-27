---
title: "Cloudflare, Wiz, ELB, and Still No Hostname: Building a Domain Coverage Census"
description: "An IR census of hundreds of company domains sorted into a four-quadrant coverage matrix: Cloudflare versus Falcon, cloud origins versus our own environment. Where every log source died during the incident, what the Cloudflare API does and does not solve (enumeration is easy, hostnames are not), and the census pipeline that turns the manual grind into a weekly diff with a dark-quadrant alert."
pubDate: "2026-10-28T22:00:00"
permalink: "/2026/10/28/domain-coverage-census/"
tags: ["Incident Response", "Cloud", "Attack Surface", "Detection Engineering"]
draft: false
---

An incident question that sounds trivial: does this host have our EDR on it? The host in question was behind a domain we owned. Answering it took a walk through Cloudflare logs, Zscaler logs, Wiz, and an ELB, and the hostname still only came out at the end by pattern-matching our own server naming conventions against the domain each box served. Every tool in the stack had seen the answer. None of them stored the join.

It got worse when the question stopped being about one domain. The follow-up ask was a census: hundreds of domains, some origins in cloud accounts, some in our own environment, and protection in every combination. Cloudflare and Falcon. Cloudflare only. Falcon only. Neither. That grid is the real artifact, and once you see it as a four-quadrant matrix, the whole problem changes shape.

## Four quadrants, four different risk stories

| | Falcon on | Falcon off |
|---|---|---|
| **Cloudflare on** | the quadrant you want | edge filtered, host blind |
| **Cloudflare off** | host watched, origin exposed raw | the dark quadrant |

Cloudflare-only domains are the sneaky ones. The team added the CDN, felt protected, and the origin behind it has no sensor. An origin-side compromise, an exposed admin panel, an origin-pull misconfiguration, anything the CDN does not filter, generates zero endpoint telemetry. Falcon-only domains are the classic forgotten origin: somebody pointed DNS at the CDN years ago, a stray record still resolves straight to the box, and every scanner on the internet is knocking on it directly. And the dark quadrant is the one that gets leadership attention, because those domains are unmonitored at both ends.

## The audit of a dead trail

The incident walk is worth recording precisely, because every IR reader has stood on it. Cloudflare saw the external name and the edge, and hides the origin by design. Zscaler saw who asked for which name from inside, and nothing about what served it. Wiz knew the cloud workloads and their exposures, in cloud-native names. The ELB knew its target group, and its access logs record which backend IP served each request, which is quietly the strongest single join key in the entire chain, and is disabled on most fleets. The last hop from IP to hostname came down to a human who knew that our web boxes are named after the domain slugs they serve.

That is the finding underneath the finding: five products, each holding eighty percent of the answer, and the missing twenty percent different in every one. The join table between the external graph of names and the internal graph of hosts was not in any tool. It was a person.

## What the Cloudflare API gives you, and what it does not

With API access to the company's own Cloudflare account, the hiding stops: the API enumerates every zone, every DNS record with its proxied or DNS-only flag, and wherever load balancing is in play, the origin pools with their server addresses. I want to be precise about what that bought, because it is less than it sounds. It gave me an authoritative inventory of names and next hops. It did not give me a single hostname.

Look at what a record actually contains. A proxied A record's content is the origin address, and in a real fleet that address is an ELB, a CNAME that chains through two more aliases, a shared box hosting five different domains, or an IP that was recycled last quarter. The DNS-only records are worse: no CDN in the path means the record points straight at whatever it points at, and if that whatever is a load balancer you are back to target groups, and if it is on-prem you are back to NAT rules and a CMDB that has not been touched since the migration. The hostname question survived the API completely untouched. What the API ended was a different, smaller misery: not knowing what we owned. Names and next hops in an afternoon, hostnames still one grind per domain.

And that is the half of the fleet the API cannot even see. Domains registered by marketing on their own accounts. Zones still living at the registrar from before the Cloudflare migration. Domains with no CDN anywhere in the path. For those, the inventory problem starts earlier: pull the registrar lists, sweep certificate transparency for our names, walk the internal DNS zones, and then ask the business what else they own, because the honest answer is that some domains only surface when someone says "oh, that one".

So the census pipeline is two halves, and they are not equally hard:

1. Enumeration, easy now: Cloudflare API for zones and records with proxied flags; registrar exports and CT logs for the rest; internal DNS zones for the names that never went outside. An afternoon, or an agent session.
2. Origin to host, the actual work: DNS-only records pointing at ELBs mean access logs or target group walks. Shared origins mean one host, five domains, and a decision about what "the host" even means. Cloud IPs mean a Wiz graph walk per address. On-prem IPs mean firewall NAT rules and a CMDB lookup that will miss. This step is per-domain analyst work, and the naming-convention match at the end is not a hack. In most fleets, the naming convention *is* the join key; the tooling just automates the guess.

The core of the enumeration half is small enough to read in one sitting:

```python
import re, urllib.request, urllib.parse, json

CF = "https://api.cloudflare.com/client/v4"
UA = {"User-Agent": "cf-census/1.0"}

def cf(path, token, params=None):
    q = f"?{urllib.parse.urlencode(params)}" if params else ""
    r = urllib.request.Request(CF + path + q,
        headers={"Authorization": f"Bearer {token}", **UA})
    return json.load(urllib.request.urlopen(r, timeout=30))

def norm(name):  # 'Meta-Web-01.corp' -> 'metaweb01' so Falcon names match
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())

def census(token, falcon_norm_names):
    out = []
    for zone in cf("/zones", token)["result"]:
        for rec in cf(f"/zones/{zone['id']}/dns_records", token)["result"]:
            origin, proxied = rec["content"], bool(rec.get("proxied"))
            hit = any(n in falcon_norm_names for n in
                      (norm(origin), norm(origin.split(".")[0]))) \
                  if not proxied else None
            if proxied:
                v = "edge only, host unknown: resolve via LB pools"
            elif hit:
                v = "host covered, no edge: origin exposed raw"
            else:
                v = "dark: no edge, no sensor found"
            out.append((rec["name"], proxied, origin, v))
    return out
```

The full version adds the CrowdStrike OAuth host pull, the load-balancer origin pools for proxied records, a CMDB mapping file for on-prem origins, and writes the quadrant CSV. It runs on standard library alone; point `CF_API_TOKEN` at a read-only token and it enumerates the whole account in minutes. I ran it against mock data across all four quadrants before trusting the classification logic, which is the same advice I would give anyone running this against a live account: validate the quadrant logic on synthetic records first, because the embarrassing failure mode is reporting a covered domain as dark and triggering a fire drill.

There is also a shorter road for the enumeration half. Cloudflare ships official MCP servers, so an AI agent with a read-only token can have the zones, records and proxied flags in a conversation instead of a script. For the first half of the census that is genuinely faster, and during an incident it is the difference between a table now and a table after someone writes the client. Keep the celebration bounded though: the agent enumerates. It does not know your naming conventions, it cannot see the ELB target behind the CNAME, and it will confidently hand you a list where a shared origin is three separate hosts. Collection by agent, resolution by analyst, classification and drift by script. That split held up everywhere I pushed it.

The census also runs in reverse, and IR asks it that way around: I am standing on a host, what is it serving, does it even know? Four artifacts answer it, in order of authority. The vhost config is the host's own claim: nginx `server_name` directives, Apache `ServerAlias`, IIS bindings, Kubernetes ingresses, which is literally a domain-to-service table. The certificate SANs on disk are what the box is certified to serve, and they routinely remember domains that DNS has already forgotten. The Host header distribution in the access logs is ground truth for what the box is *actually* serving, as opposed to configured to serve. And DNS records pointing at its addresses catch the case the host cannot know about by itself, a CDN rule routing to it from above. Configured, certified, actually served: three different claims, and the gaps between them are where the findings live.

That is fine for one host during an incident. For a fleet of thousands it is unusable, and the fix is an inversion: stop walking hosts, walk aggregation points. Nearly every domain-to-host mapping in a fleet is recorded somewhere above the host, in a handful of places that one API call each covers. CDN zones and rules. Load balancer listener rules with their host-header conditions and target groups. Kubernetes ingresses, one per cluster. Two or three API calls per aggregation point collapses thousands of hosts into a handful of configs, and the census script from earlier is already half of this.

What remains after the aggregation points are walked is the interesting residue: hosts listening on 80 or 443 that appear in no listener rule, no target group, no ingress. Those are the direct-serving stragglers, and they are exactly the machines nobody remembered when the CDN migration happened. Finding them needs endpoint data, and this is where the EDR fleet you already have pays for itself twice: Falcon's Host Insights reports listening ports and applications per host without touching a terminal, so the direct-server candidate list is an inventory query, not a thousand SSH sessions. For the candidates, one read-only response script sweeps the stragglers for vhost names, certificate SANs and listeners:

```sh
#!/bin/sh
# read-only collector for direct-serving hosts (agent remote response)
h=$(hostname -f 2>/dev/null || hostname)
echo "host=$h"
grep -rhE 'server_name|ServerAlias' /etc/nginx /etc/httpd /etc/apache2 2>/dev/null
find /etc/letsencrypt/live /etc/ssl -name '*.crt' 2>/dev/null \
  | xargs -r -n1 openssl x509 -noout -ext subjectAltName 2>/dev/null
ss -tlnp 2>/dev/null | awk '$4 ~ /:(80|443)$/'
```

Shipped through the agent's remote response to the candidate list only, this is minutes of work across a fleet, and its output merges into the same census CSV the domain walk produces. The standing version is one scheduled ingest: aggregation-point APIs daily, collector sweep on new listening hosts, diff on write. The dark quadrant stops growing because the census is watching it grow.

## What the census says out loud

Two sentences survive every leadership review. How many domains sit in each quadrant. And what changed since last week. The first turns an argument about security posture into a number. The second turns the census from a project into a control, because fleets drift: someone registers a domain, points it at a test box, forgets it, and the dark quadrant quietly grows one row.

For the tooling gaps that remain, two integrations close most of the distance that the manual walk covered. Wiz carries a CrowdStrike sensor-status attribute on workloads once the integration is on, which turns "does this host have Falcon" into a column in the exposure graph. And ELB access logging, which most fleets never enable, records the backend target that served every request; it is the missing hop between the edge name and the host, captured at the moment it matters.

The incident taught me where the trail dies. The census is what the next incident gets instead.

---

The census script runs on Python standard library with no dependencies beyond the two APIs. Review the quadrant logic on mock records before the live run, and expect the first real pass to surface a handful of origins nobody can name. That list is not a failure of the tool. That list is the finding.
