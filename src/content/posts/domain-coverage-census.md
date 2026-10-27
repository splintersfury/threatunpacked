---
title: "Cloudflare, Wiz, ELB, and Still No Hostname: Auditing Domain Coverage Across the Fleet"
description: "An IR audit of hundreds of company domains sorted into a four-quadrant coverage matrix: Cloudflare versus Falcon, cloud origins versus our own environment. The dead trail through four log sources, what the Cloudflare API does and does not solve, how red teams find the same gaps from outside, and the audit pipeline that turns the manual grind into a weekly diff with a dark-quadrant alert."
pubDate: "2026-10-28T22:00:00"
updatedDate: "2026-10-28T23:30:00"
permalink: "/2026/10/28/domain-coverage-census/"
tags: ["Incident Response", "Cloud", "Attack Surface", "Detection Engineering"]
draft: false
---

An incident question that sounds trivial: does this host have our EDR on it? The host in question was behind a domain we owned. Answering it took a walk through Cloudflare logs, Zscaler logs, Wiz, and an ELB, and the hostname still only came out at the end by pattern-matching our own server naming conventions against the domain each box served. Every tool in the stack had seen the answer. None of them stored the join.

It got worse when the question stopped being about one domain. The follow-up ask was a sweep: hundreds of domains, some origins in cloud accounts, some in our own environment, and protection in every combination. Cloudflare and Falcon. Cloudflare only. Falcon only. Neither. That grid is the real artifact, and once you see it as a four-quadrant matrix, the whole problem changes shape.

This post is the full autopsy of that grind: where each log source died, what the Cloudflare API does and does not solve, how the same audit looks from a red team's side of the wire, and the pipeline that turned the manual grind into a repeating check. Everything here is also the argument for why CISA had to mandate asset enumeration by directive.

## Four quadrants, four different risk stories

| | Falcon on | Falcon off |
|---|---|---|
| **Cloudflare on** | the quadrant you want | edge filtered, host blind |
| **Cloudflare off** | host watched, origin exposed raw | the dark quadrant |

Cloudflare-only domains are the sneaky ones. The team added the CDN, felt protected, and the origin behind it has no sensor. An origin-side compromise, an exposed admin panel, an origin-pull misconfiguration, anything the CDN does not filter, generates zero endpoint telemetry. Falcon-only domains are the classic forgotten origin: a stray record still resolves straight to the box, and every scanner on the internet is knocking on it directly. The dark quadrant is the one that gets leadership attention, because those domains are unmonitored at both ends.

If the numbers feel abstract, they are not. Unit 42's [Attack Surface Threat Report](https://em360tech.com/whitepapers/palo-alto-networks-2023-unit-42-attack-surface-threat-report) measured organizations adding more than 300 new internet-facing services per month, with roughly a fifth of the entire attack surface changing every month. Their [incident response report](https://cybersecurityasia.net/unit-42-ai-threats-expand-attack-surfaces) attributed about 40 percent of cloud incidents to unmonitored assets and shadow IT. The dark quadrant is not an edge case. It is the average condition of a fleet nobody maps.

## The audit of a dead trail

The incident walk is worth recording precisely, because every IR reader has stood on it. Cloudflare saw the external name and the edge, and hides the origin by design. Zscaler saw who asked for which name from inside, and nothing about what served it. Wiz knew the cloud workloads and their exposures, in cloud-native names. The ELB knew its target group, and its access logs record which backend target served each request, the `backend:port` field documented in [AWS's own log format reference](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html). That field is quietly the strongest single join key in the entire chain, and access logging is disabled on most fleets. The last hop from IP to hostname came down to a human who knew that our web boxes are named after the domain slugs they serve.

That is the finding underneath the finding: five products, each holding eighty percent of the answer, and the missing twenty percent different in every one. The join table between the external graph of names and the internal graph of hosts was not in any tool. It was a person.

## What the Cloudflare API gives you, and what it does not

With API access to the company's own Cloudflare account, the hiding stops: the API enumerates every zone, every DNS record with its proxied or DNS-only flag, and wherever load balancing is in play, the origin pools with their server addresses. I want to be precise about what that bought, because it is less than it sounds. It gave me an authoritative inventory of names and next hops. It did not give me a single hostname.

Look at what a record actually contains. A proxied A record's content is the origin address, and in a real fleet that address is an ELB, a CNAME that chains through two more aliases, a shared box hosting five different domains, or an IP that was recycled last quarter. The DNS-only records are worse: no CDN in the path means the record points straight at whatever it points at, and if that whatever is a load balancer you are back to target groups, and if it is on-prem you are back to NAT rules and a CMDB that has not been touched since the migration. The hostname question survived the API completely untouched. What the API ended was a different, smaller misery: not knowing what we owned. Names and next hops in an afternoon, hostnames still one grind per domain.

And that is the half of the fleet the API cannot even see. Domains registered by marketing on their own accounts. Zones still living at the registrar from before the Cloudflare migration. Domains with no CDN anywhere in the path. For those, the inventory problem starts earlier: pull the registrar lists, sweep [certificate transparency](https://crt.sh) for our names, walk the internal DNS zones, and then ask the business what else they own, because the honest answer is that some domains only surface when someone says "oh, that one".

So the audit pipeline is two halves, and they are not equally hard:

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

There is also a shorter road for the enumeration half. Cloudflare ships official MCP servers, so an AI agent with a read-only token can have the zones, records and proxied flags in a conversation instead of a script. For the first half of the audit that is genuinely faster, and during an incident it is the difference between a table now and a table after someone writes the client. Keep the celebration bounded though: the agent enumerates. It does not know your naming conventions, it cannot see the ELB target behind the CNAME, and it will confidently hand you a list where a shared origin is three separate hosts. Collection by agent, resolution by analyst, classification and drift by script. That split held up everywhere I pushed it.

## The red team runs the same audit

Here is the uncomfortable symmetry: everything above, an attacker calls reconnaissance, and the industry has catalogued it. MITRE ATT&CK tracks the passive half as [T1590, Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/) (domains, DNS, network ranges) and [T1592, Gather Victim Host Information](https://attack.mitre.org/techniques/T1592/) (roles, configurations, and yes, which hosts look unprotected), with active enumeration as [T1595, Active Scanning](https://attack.mitre.org/techniques/T1595/). Your coverage audit and an attacker's pre-operation recon are the same queries pointed at the same infrastructure. The only difference is who gets to authenticate.

The origin-discovery half has a decade of public literature. A study covered by [SecurityWeek](https://www.securityweek.com/websites-fail-hide-origin-ip-ddos-attackers/) found that more than 70 percent of sites behind DDoS-protection services leaked their origin IPs, and the playbook has only grown since: [historical DNS](https://osintteam.blog) from before the CDN was switched on, certificate transparency entries for the origin host, Shodan's favicon hash to find the same server on an unproxied address, unproxied dev and mail subdomains, and the MX and SPF records that name infrastructure nobody remembered to hide. If your origin is exposed raw (the Falcon-only quadrant), assume the red team found it before lunch. If your origin is dark (no sensor), assume they found it and moved in without your endpoint ever logging.

This is why the audit matters in both directions. Walking it yourself finds the rows before an attacker does. And the reverse check, standing on a host during IR and asking what it serves, has its own four artifacts: the vhost config as the host's own claim (`server_name`, `ServerAlias`, IIS bindings, Kubernetes ingresses), the certificate SANs on disk, the Host header distribution in the access logs as ground truth for what is actually served, and reverse DNS for the routing the box cannot see. Configured, certified, actually served: three different claims, and the gaps between them are where the findings live.

## The fleet-scale inversion

One host during an incident is fine by hand. For thousands it is unusable, and the fix is an inversion: stop walking hosts, walk aggregation points. Nearly every domain-to-host mapping in a fleet is recorded somewhere above the host, in a handful of places that one API call each covers. CDN zones and rules. Load balancer listener rules with their host-header conditions and target groups. Kubernetes ingresses, one per cluster. Two or three API calls per aggregation point collapses thousands of hosts into a handful of configs, and the enumeration script from earlier is already half of this.

What remains after the aggregation points are walked is the interesting residue: hosts listening on 80 or 443 that appear in no listener rule, no target group, no ingress. Those are the direct-serving stragglers, and they are exactly the machines nobody remembered when the CDN migration happened. Finding them needs endpoint data, and this is where the EDR fleet pays for itself twice. Falcon's Host Insights reports listening ports and applications per host without touching a terminal; the events flow through the [Falcon SIEM connector](https://docs.rapid7.com/insightidr/crowdstrike-falcon-event-source) into Splunk as `NetworkListenActivity`, and [Panther's monitoring walkthrough](https://panther.com/blog/security-monitoring-crowdstrike-falcon) shows the shape of the query. The direct-server candidate list becomes an inventory search, not a thousand SSH sessions. For the candidates, one read-only response script sweeps the stragglers for vhost names, certificate SANs and listeners:

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

Shipped through the agent's remote response to the candidate list only, this is minutes of work across a fleet, and its output merges into the same coverage CSV the domain walk produces. The standing version is one scheduled ingest: aggregation-point APIs daily, collector sweep on new listening hosts, diff on write. The dark quadrant stops growing because the audit is watching it grow.

The sensor half closes the same way, inside the tools you already run. Falcon's host inventory in Splunk left-joined against the listening-host candidates answers "web port open and no sensor" in one query. Wiz's integration catalog carries CrowdStrike enrichment, so sensor coverage shows up as a workload attribute in the security graph and uncovered machines become a standing query instead of an investigation. Neither integration existed in my incident's toolkit. Both would have collapsed it.

## Mandated by directive, ignored by default

If it still reads like a nice-to-have: CISA's [Binding Operational Directive 23-01](https://www.darkreading.com/cyber-risk/cisa-bod-23-01-what-agencies-need-to-know-about-compliance) ordered every federal civilian agency to run recurring automated asset discovery and vulnerability enumeration, explicitly because agency records miss assets, and [recommended unauthenticated scanning](https://attaxion.com/blog/how-bod-23-01-can-enhance-federal-network-asset-visibility-and-vulnerability-detection) precisely to find the machines the records do not know about. When the national cybersecurity agency has to force its own departments to count their servers, the join-table problem is not a maturity gap. It is the default state of every large organization, and the audit is how you opt out.

The incident taught me where the trail dies. The audit is what the next incident gets instead, and the red team has been running it against us the whole time.
