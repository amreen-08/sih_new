# CatchPhish — Project Explainer & PPT Brief

Problem Statement 26106 · Theme: Blockchain & Cybersecurity · Team CodeX

This is a study reference, not a new deliverable — everything below describes code that
already exists in this project. Use it to prep for judge questions.

---

## 1. What your PPT pitches

Your deck (`CodeX_26106_IdeaPPT.pptx`) promises six components:

1. **Header and authentication verification** — SPF/DKIM/DMARC to catch spoofed senders.
2. **Geolocation and infrastructure intelligence** — trace the real sending infrastructure.
3. **Attachment forensics** — static analysis of attachments, no execution.
4. **Campaign correlation and flag propagation** — one flagged email drags the rest of its
   campaign along with it.
5. **AI-driven fraud scoring engine** — one explainable 0–100 score.
6. **Blockchain-based evidence ledger** — hash-chains every report into a tamper-proof,
   court-admissible audit trail. This is the slide that explicitly ties the project to the
   "Blockchain & Cybersecurity" theme.

The Feasibility slide is upfront that scoring starts **rule-based** and can move to
ML (PyCaret/Scikit-learn) later — that's honest and matches what's built.

## 2. Reality check — built vs. pitched

Read this before your demo, not during it.

| PPT component | Status | Notes |
|---|---|---|
| SPF/DKIM/DMARC verification | ✅ Built | `auth_checker.py` |
| Geolocation + ASN + infrastructure | ✅ Built | `geolocation.py`, `asn_lookup.py`, `dns_lookup.py`, `infrastructure.py` |
| Attachment forensics | ✅ Built | 6-module subsystem, see §4 |
| Campaign correlation + flag propagation | ✅ Built | `campaign_correlation.py` — both an anchor-propagation mode and a general clustering mode |
| Fraud scoring engine | ⚠️ Built, but **rule-based**, not AI | `fraud_score.py`. Calling it "AI-driven" on the title slide is a stretch — say "rule-based today, ML-upgradeable" if asked, matching your own Feasibility slide |
| Risk categories | ⚠️ Mismatch | PPT slide 2 says "Safe / Suspicious / High Risk" (3 categories). The code actually outputs **Low / Medium / High / Critical Risk** (4 categories) via `classify_risk()`. Not a big deal, but be ready to explain the real category names if a judge reads both |
| **Blockchain-based evidence ledger** | ❌ **Not built** | No `blockchain_ledger.py` exists in this codebase. This is the slide that explicitly connects your project to the hackathon's own theme name — if a judge asks to see it, you currently don't have anything to show. You told me earlier not to add it; that's your call, but you should walk in knowing this gap exists rather than being surprised on stage. (I can build a lightweight SHA-256 hash-chain version quickly if you change your mind before the demo — it's a self-contained module, wouldn't touch anything that already works.) |

Everything else in the PPT (Streamlit-style rapid detection, campaign-level attribution,
explainable scoring) is accurately represented by what's built.

## 3. The pipeline, end to end

`main.py` → `run_pipeline(eml_path, campaign_dir=None)` is the single entry point. It runs
these steps in order, every time:

```
.eml file
  → email_parser.py        parse headers (From, Received, Subject, DKIM-Signature, ...)
  → ip_extractor.py         pull an IP out of every Received: header
  → ip_validator.py         drop private/loopback IPs, keep only public ones ("traceable")
  → geolocation.py          for each traceable IP: country/city/ISP        \
  → asn_lookup.py           for each traceable IP: who owns this network?    > independent
  → dns_lookup.py           for each traceable IP: reverse-DNS hostname    /   lookups
  → infrastructure.py       combine the three lookups per hop into red-flag indicators
  → auth_checker.py         SPF / DKIM / DMARC verdicts (header-based, DNS fallback)
  → attachment_analyzer.py  static forensics on every attachment (no execution, ever)
  → fraud_score.py          weighted 0-100 score from all of the above
  → result dict             everything the UI/report renders
```

Two things worth saying out loud to judges: nothing in this pipeline ever executes an
attachment or clicks a link, and every network call (geolocation, ASN, DNS, live SPF/DKIM
checks) is wrapped so a failure degrades to "unknown," never a crash.

## 4. Module by module

### `email_parser.py` — turns raw .eml text into structured data
Reads `From`, `Return-Path`, `Subject`, `Message-ID`, every `Received:` header (in original
order — hop 1 is newest, last is oldest/closest to the true sender), and the
`Authentication-Results` / `DKIM-Signature` headers other modules need. Real-world detail
worth mentioning: Python's own `email.utils.parseaddr()` returns nothing at all on some
malformed real phishing headers (an unquoted comma before `<address>`), so this module has a
regex fallback that recovers the address anyway — found in 11 of 52 real samples tested.

### `ip_extractor.py` — finds the IP inside a Received: header
The forensically meaningful IP is the one in square brackets — `[203.0.113.5]` — because
that's what the receiving mail server itself observed on the TCP connection. A hostname next
to it can be forged (whoever controls that domain's forward DNS controls what it says); the
bracketed IP can't be. Falls back to parenthesized or bare IPv4/IPv6 patterns if brackets
aren't present.

### `ip_validator.py` — filters out IPs not worth tracing
Classifies every IP as public / private / loopback / link_local / reserved / invalid /
unresolved using Python's `ipaddress` module. Only `public` IPs get sent on to geolocation/
ASN/DNS lookups — private LAN hops (`10.x.x.x`, internal relay addresses) are kept in the
trace for completeness but never looked up externally.

### `geolocation.py` — where is this IP?
Calls `ip-api.com`'s free JSON API (no key needed) for country/region/city/lat/lon/ISP.
Caches results in-memory so the same IP isn't looked up twice in one run. Any failure
(timeout, rate limit) returns `status: "error"` instead of crashing the pipeline.

### `asn_lookup.py` — who *owns* this IP?
Primary method: RDAP lookup via the `ipwhois` library against the real regional internet
registries (ARIN/RIPE/APNIC/etc.) — tells you the actual network owner. Falls back to the
`org`/`isp`/`as` fields `geolocation.py` already fetched if `ipwhois` isn't installed. Either
way, the result gets classified as `hosting_provider` (AWS, Azure, DigitalOcean, OVH, etc. —
disposable infrastructure a phishing campaign can spin up cheaply) or `isp_or_other` via a
keyword match against known cloud/hosting providers.

### `dns_lookup.py` — reverse DNS
Asks "what hostname is actually registered to point at this IP?" using nothing but Python's
built-in `socket.gethostbyaddr()`. This is the check that catches an email claiming to be
from `paypal.com` when the sending IP reverse-resolves to something like
`vps-4471.cheaphost.ru`. `domain_matches_claim()` does a permissive suffix check so
legitimate providers using subdomains (`mail-sor-f41.google.com` for a `@gmail.com` sender)
don't get flagged.

### `infrastructure.py` — combines the three lookups into red flags
For the true origin hop (the last traceable one), raises indicators when: the IP belongs to
a cloud/hosting provider instead of normal residential/corporate mail infra; reverse DNS
doesn't match the claimed sending domain, or has no PTR record at all; the message's relay
chain crossed 3+ different countries; or every single lookup failed outright (flagged as a
tooling limitation, not evidence of fraud — a failed API call by itself proves nothing).
`risk_level_from_indicators()` is the simple count-based classifier reused twice — once here,
once after auth indicators are added in — 0 indicators → low, 1–2 → medium, 3+ → high.

### `auth_checker.py` — is the sender who they claim to be?
Two paths, tried in order:

1. **Header-based (preferred):** almost every real mail provider already ran SPF/DKIM/DMARC
   the moment the email arrived and stamped the verdict into an `Authentication-Results`
   header. Reading that is free, instant, and more reliable than reimplementing verification
   — the receiving server had context (envelope sender, HELO string) this pipeline doesn't
   always have.
2. **Live DNS fallback**, used only when that header is missing (hand-crafted test emails,
   some smaller providers):
   - **SPF**: fetches the domain's `v=spf1` TXT record, evaluates `ip4:`/`ip6:`/`include:`/
     `all` mechanisms against the traced sender IP. Not the full RFC (no macros, deep
     includes, mx/ptr mechanisms) — good enough to demo correctly against most real domains.
   - **DKIM**: checks whether a `DKIM-Signature` header exists and whether a public key is
     actually published at `<selector>._domainkey.<domain>` in DNS. Important honesty point
     for judges: this confirms DKIM is *configured*, it does **not** cryptographically verify
     the signature (that needs full RFC 6376 header/body canonicalization).
   - **DMARC**: simplified alignment check — passes if SPF or DKIM passed *and* the passing
     domain matches the visible `From:` domain. Real DMARC also allows organizational-domain
     matches in "relaxed" mode; this only does exact matches.

`build_auth_indicators()` turns the three verdicts into the same plain-English indicator
strings `infrastructure.py` produces, so they merge into one combined indicator list and one
combined risk level.

### The attachment forensics subsystem (6 modules, coordinated by `attachment_analyzer.py`)
Static analysis only — **nothing is ever opened, executed, or macro-run.**

- `attachment_extractor.py` — pulls every MIME attachment out of the .eml.
- `attachment_metadata.py` — filename, extension, size, SHA-256 hash, detected MIME type,
  and **Shannon entropy** (a measure of byte-level randomness — near-random-looking data
  usually means the file is compressed or encrypted, which is itself a mild red flag on an
  attachment that claims to be a plain document).
- `attachment_detector.py` — checks the file's actual magic-byte signature against its
  declared/detected MIME type and extension; flags executables, scripts, macro-capable
  document formats, and **double extensions** (`invoice.pdf.exe` — a classic disguise trick).
- `attachment_macro_analyzer.py` — for Office documents, statically scans for VBA macro
  presence, auto-executing macros (`AutoOpen`, `Document_Open`, etc.), suspicious API calls,
  and common obfuscation patterns (hex/base64 encoding, Dridex-style string splitting) —
  again, read the macro source text, never run it.
- `attachment_ioc.py` — extracts URLs, IPs, and domains embedded in the attachment's raw
  bytes (Indicators of Compromise) without opening the file in any application.
- `attachment_analyzer.py` — the coordinator. Runs all of the above per attachment, merges
  every individual finding into one `forensic_indicators` list per file, then rolls the whole
  email's attachments into a summary (`executable_attachments`, `macro_attachments`,
  `script_attachments`, `signature_mismatches` counts). **Explicitly does not calculate a risk
  score** — that's `fraud_score.py`'s job, kept as a separate concern on purpose.

### `campaign_correlation.py` — is this part of a bigger wave?
The one module that looks *across* emails instead of at one email alone. Extracts a
fingerprint per email (campaign-ID header if present, sender domain, reply-to, source IP,
SPF/DKIM/DMARC verdicts, and a normalized/stripped version of the HTML body for template
matching), then runs two different algorithms depending on the question being asked:

- **`calculate_campaign_scores()`** — anchor-based. Picks the batch's most common sender
  domain as a "legitimate reference," flags any email as an "anchor" if it either looks like
  a lookalike of that domain or has 2+ auth failures, then propagates suspicion to any other
  email that pairs strongly (`calculate_pair_score()`, 0–100) with an anchor. Deliberately
  conservative — it stays silent on a batch where nothing looks like a classic spoofing
  anchor, even if the emails are obviously the same spam run.
- **`find_campaign_clusters()`** — general-purpose. No anchor concept at all: every pair of
  emails in the batch gets a similarity score, and a **union-find** (disjoint-set) structure
  groups any that score ≥55 together into clusters. This is what actually catches real-world
  campaigns pulled from a public corpus, where nothing looks like "a lookalike domain of our
  own outgoing mail" but 10 samples clearly share the same template.

`calculate_pair_score()` is the shared similarity function both algorithms lean on: +30 same
campaign-ID header, +20 identical normalized body template, +15 same source IP, +15 subject
similarity ≥70%, +10 same reply-to, +10 same sender domain, +10 lookalike sender domain
(≥85% string similarity) — capped at 100.

`fraud_score.py` runs **both** algorithms and takes the max of the two, merging the reasons
from whichever one fired — that fix came directly out of testing against the real Phishing
Pot samples, where the anchor method alone found almost nothing (real phishing rarely stamps
a campaign-ID header) but the cluster method found real matches.

### `fraud_score.py` — the final 0–100 number
Three independently-computed sub-scores, weighted and summed:

```
fraud_score = geo_score × 0.25 + attachment_score × 0.35 + campaign_score × 0.40
```

- **`score_from_infrastructure()`** (feeds the 0.25 weight): `count = 0` → 5.0; otherwise
  `min(100, 30 + count×18)` where `count` is the number of combined infra+auth indicators.
- **`score_from_attachments()`** (0.35 weight): 0 if no attachments at all; otherwise
  `executables×45 + macros×35 + scripts×35 + signature_mismatches×25`, plus a small capped
  bump (`min(total_indicator_count×4, 20)`) for sheer volume of forensic findings, capped at
  100 overall.
- **`score_from_campaign()`** (0.40 weight, the heaviest): **batch mode** if 2+ related .eml
  files were supplied — `max(anchor_score, cluster_score)` as described above. **Single-email
  fallback** otherwise: +25 for urgency/account/reward language in the subject
  ("verify", "suspended", "24 hours", "claim", ...), +35 if 2+ of SPF/DKIM/DMARC failed, +15
  if exactly 1 failed.

`classify_risk()` then buckets the final number: **<30 Low Risk, <60 Medium Risk, <80 High
Risk, ≥80 Critical Risk.**

**Important nuance to have ready for judges** — there are deliberately *two* separate risk
signals in the final output, and they're allowed to disagree:

- `risk_level` — pure indicator-*count* based (0→low, 1–2→medium, 3+→high), computed in
  `infrastructure.py`.
- `fraud_classification` — the numeric-score-based bucket above, computed in `fraud_score.py`.

A message can easily show `risk_level: HIGH` (3+ indicators tripped) while
`fraud_classification` reads `Medium Risk` (the weighted number landed at 43), because one
counts flags and the other weighs them. That's by design, not a bug — you saw this exact
combination in your Streamlit test run.

### `report.py` — human-readable terminal report
Purely a presentation layer over the same JSON `main.py` produces — `--report` mode prints a
colored, sectioned report (origin trace table, SPF/DKIM/DMARC, attachments, campaign
correlation, indicators) instead of raw JSON. No new logic lives here.

### `app.py` — the Streamlit deployment
The newest piece, and it adds **zero new detection logic** — it's a UI layer that calls the
exact same `main.run_pipeline()` the CLI uses and renders the same result dict with Streamlit
widgets instead of ANSI text. Sidebar lets you pick a bundled sample or upload your own
`.eml` file(s) (upload 2+ at once to trigger batch campaign correlation between them);
main panel shows the headline score/classification/risk-level, email metadata, the hop-trace
table, SPF/DKIM/DMARC badges, an expandable per-attachment forensic breakdown, campaign
correlation reasons, the full indicator list, the weighted-score breakdown, and a raw-JSON /
downloadable-report option. One UX quirk worth knowing: it keeps the *last* result on screen
until you click **Run analysis** again — uploading a new file doesn't auto-refresh the report.

## 5. Sample data

`samples/real_world_campaign/` holds 52 **real, captured phishing emails** from the
[Phishing Pot](https://github.com/rf-peixoto/phishing_pot) research corpus (honeypot-collected,
CC BY-NC 4.0 — attribution required, non-commercial use only; see the `NOTICE.md` in that
folder). This is what actually exercises the clustering logic meaningfully — the synthetic
`campaign_batch/` folder proves the algorithm works on paper, but the real samples are what
show it finding matches nobody hand-engineered.

## 6. Fast answers for likely judge questions

- **"Is the scoring AI?"** No — it's an explainable, weighted rule-based formula today. Every
  number in it can be traced back to a specific indicator. ML (PyCaret/Scikit-learn) is the
  stated upgrade path once you have labeled data to train against, per your own Feasibility
  slide.
- **"Do you verify DKIM cryptographically?"** Only when the receiving mail server already did
  it and stamped `Authentication-Results` (the common real-world case). The fallback DNS path
  only confirms DKIM is *configured* (public key exists), not that the signature is
  cryptographically valid — say this proactively, it reads as rigor, not a weakness.
  Real crypto verification is a documented upgrade path (`dkimpy`).
- **"Do you execute attachments to check them?"** Never. Every attachment check — hashing,
  entropy, signature detection, macro scanning, IOC extraction — is static, byte-level
  analysis only.
- **"Where's the blockchain component?"** Be honest: not built yet. If pressed, the plan
  (from your Technical Approach slide) is SHA-256 hash-chaining each fraud report so any past
  report can be tamper-detected, extendable later to Hyperledger Fabric for a real distributed
  ledger. It's a self-contained, addable module if you decide you need it before demo day.
- **"How do you find campaigns without a shared header?"** That's exactly what
  `find_campaign_clusters()` is for — pairwise similarity across body template, sender
  infrastructure, and subject wording, with no dependency on any single header being present.
