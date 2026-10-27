---
title: "The Patch You Cannot See in the Logs: A Lab Autopsy of php2shell"
description: "Three days in a lab with CVE-2026-109618 and CVE-2026-109619: what the upload-progress bug actually does to a PHP server, the six exploit flavors it enables, the four walls exploit developers hit on the way to RCE, an independent failure to reproduce the loudest public chain, and a one-request worker deadlock that the patched and unpatched servers log identically."
pubDate: "2026-10-28T20:30:00"
permalink: "/2026/10/28/php2shell-lab-autopsy/"
tags: ["Vulnerability Research", "PHP", "Exploit Analysis", "Detection"]
draft: false
---

Two PHP servers get the same malicious upload request. Both log the same line: `Fatal error: Allowed memory size of 4194304 bytes exhausted in Unknown on line 0`. Both return a 500. One of them now has a worker that will never serve another request, and the only place that fact exists is a kernel lock table that nobody watches.

That asymmetry is where a week of php2shell coverage kept losing me, so I spent three days pulling the bug apart in a lab: the mod_php chain that everyone retweets, the fpm crash nobody wrote up, and the quiet resource-exhaustion family sitting underneath both. This post is the autopsy. What the bug is, what its six exploit flavors need, why the RCE claims do not survive independent testing, and what you can actually detect.

## The bug: a progress bar that runs before your code

Since PHP 5.4, every install ships with `session.upload_progress`. During a file upload, PHP updates a "you are 43% through" record inside the user's session so the application can render a progress bar. Two design details make this feature attackable.

It runs before the application. The bookkeeping happens inside the upload parser at engine startup, before one line of site code executes. A site with no vulnerabilities, no login, and no session usage is still exposed, because the visitor writes `PHPSESSID=<anything>` as a form field in the upload itself and PHP invents the session on their behalf. Strict mode, which would reject invented ids, is off by default.

And it caches raw C pointers. At the first file part, the handler builds a progress array and stores direct pointers into it: one to the bytes-processed counter, one per file. On every progress tick the handler re-initializes the session, which can destroy and rebuild the memory those pointers point into. When that happens cleanly, reference counting saves everyone. When it happens through a fatal error, PHP unwinds with a `longjmp()`, and a longjmp skips every cleanup function on the way out. The pointers survive, pointing at memory that is now free.

That is the pair: CVE-2026-109618 and CVE-2026-109619, fixed October 21 in 8.2.35, 8.3.36, 8.4.27 and 8.5.12. The attacker controls the session id, the progress key, the size and content of every upload part, and, because the session file itself is attacker-writable through normal requests, the data PHP decodes mid-parse. The trigger is a single multipart POST. CVSS 9.2.

## Three gates between crash and shell

Every exploit flavor clears the same three gates, and the difficulty lives in the differences.

Gate one is placing the abort. The cleanup-skipping jump fires on `memory_limit`, and the attacker controls memory pressure from both sides. A session file planted at any chosen size (a normal request writes session data; thirty requests of a megabyte each plant thirty megabytes) plus an upload padded with a few hundred filler fields lets the attacker decide whether PHP dies at the file read, partway through decoding, or inside the progress bookkeeping itself. In my lab the fatal always produced the same signature: "in Unknown on line 0", which means inside the upload handler, before the site's code existed.

Gate two is reclaiming the freed memory. A dangling pointer matters only if attacker bytes land at its target. This part is old-fashioned heap grooming: the follow-up upload carries 149 to 880 repeated form fields sized to the freed block, and PHP's allocator, which is deterministic within a request, hands them back filled. Easiest gate by far.

Gate three is the write itself. The primitive is a single 64-bit integer, the byte counter, fully attacker-chosen, written once through the stale pointer. The public chains turn that into execution without a ROP chain: they forge a PHP array whose destructor pointer aims at `system()`. At request shutdown, PHP destroys the array and calls the destructor, which is now the attacker's command. The command string travels in a forged header beside it. One function pointer of coincidentally matching signature, no gadget hunting.

## The flavors

| Flavor | SAPI | Precondition | Status |
|---|---|---|---|
| OOM stale state (Chain D) | Apache mod_php | none | claimed, fails independent testing |
| Session OOM, stale engine state (Chain E) | php-fpm | any `session_start()` page | crash verified in my lab, 3/3 |
| Serializer mismatch (Chain C) | php-fpm | per-directory handler misconfig | free exploit, niche |
| Session injection + LFI (Chain A) | any | app has an LFI bug | needs the app broken first |
| `var_destroy` UAF (Chain B) | any | app calls `unserialize()` | needs the app broken first |
| Lock leak, self-deadlock, worker death | all | none | verified in my lab |

Chain D is the headline everyone repeated: pre-auth RCE with no application prerequisites. Chain E is its fpm sibling, and its producer is simply any page that starts a session, which means every WordPress and Laravel install on the internet. The DoS family at the bottom came out of my own testing and I have not seen it written up anywhere.

## The four walls

Turning the crash into a shell means solving four problems, and this is where the public effort actually went.

ASLR with no leak. The final write needs real addresses and the binary is randomized. Brute force shows up instantly in logs and worker respawns. Spraying solves placement, never addresses. The better chains solve it with the bug itself: the stale session-id pointer gets URL-encoded into a `Set-Cookie` header, and with the right spray that header becomes an 800 KB read of raw worker memory. The response cookie dumps the heap. Parse it, take the most common pointer (one chain plants over a thousand identical copies to make the mode unmistakable), subtract a known offset, and the binary base falls out. The exploit defeats address randomization using the same request that caused it. It is the smartest idea in the whole literature.

Worker identity. The crash and the follow-up must hit the same Apache child, because that child owns the corrupted state. Two fixes exist publicly: flood all workers but one so the chain pins itself, or fire and probe, sending follow-ups until one lands on the poisoned worker at roughly one chance in five per attempt.

Calibration. `system` sits at a different offset in every distro build of the same PHP version, groom sizes scale with the memory limit, and a 2 MB session and a 30 MB session are different exploits. This is why every public chain ships build tables, fingerprint flags, and calibration scripts, and it sets the honest ceiling on "works anywhere" claims.

Stability. The last write passes attacker bytes through code that expects real PHP values. One wrong refcount and the engine aborts before the destructor. The polished chains engineer a crash-free variant so the worker survives, keeps serving, and returns command output inside the HTTP response between two marker strings. That detail separates a tool from a demo.

## What my lab said

I rebuilt PHP with sanitizers, stood up the official Docker images, and drove all of it with a small FastCGI and multipart harness. Three findings.

The loud chain does not reproduce. The most-starred research repo claims a verified five-out-of-five chain on stock `php:8.4.26-apache`, so I ran its exploit script on exactly that image, exactly its lab setup, with its own build table selecting the correct offsets. Its first stage never produced a memory fatal at any limit over either transport. Its leak stage then sent over ninety follow-ups and got back ninety ordinary forty-byte session cookies. The 800 KB heap dump its documentation describes never happened once. A separate auditor had already failed to reproduce the other loud framework. I am now the second.

The fpm crash does reproduce, three out of three. The fpm story is the one nobody told. In the fpm case the fatal happens while the application decodes an attacker-planted session file, not during the upload parse, so the worker survives it with the engine's internals left dirty. The next upload request, any upload request, pre-auth, consumes that state and dies: `child exited on signal 11 (SIGSEGV - core dumped)`. Same recipe on 8.4.27: identical fatal logged, consumer runs clean, worker healthy. The fix holds. What the crash is worth beyond a hard remote DoS is unresolved; the repo behind it gates its RCE claims behind a paid subscription, which I treat as a claim not yet in evidence.

The quiet family is real and unpublished. On mod_php, the abort leaks the session file's advisory lock, and every later request that touches that session id queues on it forever. Five workers, one poisoned sid, done. On `php -S`, the same class of abort deadlocks the server against its own lock; I pulled the process apart and found it holding two descriptors on the session file, waiting on itself. One request, permanent wedge, no log line beyond the ordinary memory fatal.

## The patch you cannot see

PHP 8.5.12 stopped aborting through the handler at all. The engine now records the exhaustion and defers the fatal to the next safe point, after cleanup. The operational catch: a patched and an unpatched server log the identical fatal for the identical malicious request, and both return 500. I ran the differential. The only observable difference on the box is the kernel lock table and the worker that never comes back.

So the detection surface is on the wire, not in your logs. Multipart POSTs that carry both a `PHPSESSID` form field and the progress field. Set-Cookie headers measuring in hundreds of kilobytes. Workers sitting in flock wait. Requests that re-seed session data at megabyte scale from no authenticated user. And patch, because the exploited and the unexploited look the same right up until a worker stops coming back.

---

Lab notes and the harness live in my working notes; the fpm verification script I ran is public in the repository named above, and I changed none of its logic. I did not publish exploit code, offsets, or a repeatable end-to-end RCE, because the honest state of the art is: the crash is easy, the shell is not, and the difference is the story.
