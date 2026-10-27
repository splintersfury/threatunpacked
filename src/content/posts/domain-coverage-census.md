---
title: "Cloudflare, Wiz, ELB, and Still No Hostname: Building a Domain Coverage Census"
description: "An IR census of hundreds of company domains sorted into a four-quadrant coverage matrix: Cloudflare versus Falcon, cloud origins versus our own environment. Where every log source died during the incident, why the Cloudflare account turned out to be the join table, and the API pipeline that turns the manual grind into a weekly diff with a dark-quadrant alert."
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

## The unlock: the account is the join table

The origin-hiding problem only exists when you look from outside. With API access to the company's own Cloudflare account, hiding stops: the API enumerates every zone, every DNS record with its proxied or DNS-only flag, and wherever load balancing is in play, the origin pools with their actual server addresses. The external graph turns out to have an owner, and the owner has an API.

From there the census is mechanical:

1. Cloudflare API: every zone, every record, proxied flag set. This alone splits the fleet into edge-visible and origin-exposed-today.
2. Origin per record: DNS-only records resolve directly. Proxied records pull their real origin from record content and the load balancer pools. Stragglers get historical DNS.
3. Origin to host: cloud IPs into Wiz's inventory, on-prem IPs into internal DNS, CMDB and firewall NAT rules.
4. Host to Falcon: the CrowdStrike API queried by hostname, normalized short name, local IP and MAC, because Falcon stores the OS computer name in its own dialect and the literal match always fails.
5. One CSV out: domain, origin, host, quadrant. Plus a weekly rerun and a diff, so a domain appearing in the dark quadrant is an alert instead of the next incident's opening act.

The core of it is small enough to read in one sitting:

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

There is also a shorter road than scripting it. Cloudflare ships official MCP servers, which means an AI agent with a read-only token to your account can walk the same pipeline as a conversation: list the zones, pull the records with their proxied flags, name the origins. For a one-off census during an incident, that is a perfectly good way to get the raw table in minutes instead of writing the client. Two boundaries keep it honest. The quadrant logic and the Falcon join stay yours, because no Cloudflare tool knows what your coverage policy means, and bulk enumeration is exactly where agents get sloppy, so treat the agent's table as a draft and the CSV diff as the record. The same pattern, agent through MCP for collection, script for classification and drift, is reusable well past this census.

## What the census says out loud

Two sentences survive every leadership review. How many domains sit in each quadrant. And what changed since last week. The first turns an argument about security posture into a number. The second turns the census from a project into a control, because fleets drift: someone registers a domain, points it at a test box, forgets it, and the dark quadrant quietly grows one row.

For the tooling gaps that remain, two integrations close most of the distance that the manual walk covered. Wiz carries a CrowdStrike sensor-status attribute on workloads once the integration is on, which turns "does this host have Falcon" into a column in the exposure graph. And ELB access logging, which most fleets never enable, records the backend target that served every request; it is the missing hop between the edge name and the host, captured at the moment it matters.

The incident taught me where the trail dies. The census is what the next incident gets instead.

---

The census script runs on Python standard library with no dependencies beyond the two APIs. Review the quadrant logic on mock records before the live run, and expect the first real pass to surface a handful of origins nobody can name. That list is not a failure of the tool. That list is the finding.
