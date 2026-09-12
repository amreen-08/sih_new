# Email Forensics Toolkit

A header-forensics and fraud-scoring pipeline for suspicious emails: traces
the real origin of a message hop-by-hop, checks SPF/DKIM/DMARC, statically
analyzes attachments without ever executing them, correlates related emails
into campaigns, and rolls everything into one explainable fraud score.

Built for an SIH-style problem statement (email header forensics + digital
evidence). This is the working proof-of-concept slice: everything below
runs end-to-end against a real `.eml` file today. A blockchain evidence
ledger (writing each report's hash to a tamper-evident chain for
chain-of-custody) and the dashboard/map front end are the natural next
layers to build on top of this JSON output - this toolkit is what produces
the data they'd consume.

## What this is built from

This project combines and completes code from several team members'
modules. A few things were changed in the process:

- **Two `main.py` files existed** (one wired up attachment analysis, the
  other wired up SPF/DKIM/DMARC + the `--report` formatter). They've been
  merged into a single `main.py` that does everything both did, plus a
  real fraud score.
- **Two fraud-scoring files existed** (`fraud_score.py` with three
  hardcoded numbers, `final_codex.py` with a hardcoded list of six demo
  `.eml` filenames). They've been split into `fraud_score.py` (clean,
  importable, scores the REAL pipeline output) and
  `campaign_correlation.py` (the reusable multi-email correlation logic,
  now usable against any folder of `.eml` files, not just one hardcoded
  demo set).
- **Three files were referenced by `main.py`'s imports but never actually
  included in the upload**: `ip_extractor.py`, `ip_validator.py`, and
  `infrastructure.py`. They've been rebuilt here from the exact function
  signatures and return shapes the rest of the codebase (and `report.py`)
  already depended on. If the original versions of these three files
  exist somewhere, swap them in and the rest of the pipeline should keep
  working unchanged - the interface is what matters.

## Pipeline

```
main.py
  -> email_parser.py         parse raw .eml into structured headers
  -> ip_extractor.py         pull an IP out of every Received: header
  -> ip_validator.py         drop private/invalid IPs, mark traceable hops
  -> geolocation.py    \
  -> asn_lookup.py       >   per traceable hop: where is it, who owns it, what's its reverse DNS
  -> dns_lookup.py     /
  -> infrastructure.py       combine hop lookups into hop profiles + infra indicators
  -> auth_checker.py         SPF / DKIM / DMARC - is the sender who they claim to be?
  -> attachment_analyzer.py  static attachment forensics (metadata, file-type, macros, IOCs)
  -> fraud_score.py          weighted 0-100 fraud score across all of the above
  -> report.py / JSON        human-readable report, or machine-readable JSON
```

`attachment_analyzer.py` itself coordinates five smaller modules:
`attachment_extractor` (pulls attachments out of the `.eml`),
`attachment_metadata` (hash/size/entropy/MIME), `attachment_detector`
(file signature vs. declared type, executables, double extensions),
`attachment_macro_analyzer` (static VBA analysis via `oletools`, never
executes anything), and `attachment_ioc` (URLs/IPs/domains found inside
the attachment bytes - never visited).

Nothing in this pipeline executes an attachment, visits an extracted URL,
or opens a macro. Every network call (geolocation, ASN lookup, DNS) is
wrapped so a failure degrades to `"status": "error"` instead of crashing
the run.

## Quick start

```bash
pip install -r requirements.txt
python main.py samples/sample_email.eml --report
```

Other useful invocations:

```bash
# Machine-readable JSON (pretty-printed)
python main.py samples/sample_email.eml --pretty

# Save the report to a file instead of stdout
python main.py samples/sample_email.eml --report -o report.txt

# Score this email against a batch of related .eml files (a quarantine
# folder, a mailbox export) for real cross-email campaign correlation
# instead of the single-email fallback heuristics
python main.py samples/campaign_batch/variant_01.eml --campaign-dir samples/campaign_batch

# Score a REAL captured phishing email against a batch of real ones
python main.py samples/real_world_campaign/sample-5058.eml --campaign-dir samples/real_world_campaign --report

# Find which emails in a batch are actually the same campaign, without
# scoring any single one of them as "the target" - general similarity
# clustering across any pile of .eml files
python campaign_correlation.py --cluster --dir samples/real_world_campaign
```

## Sample emails

- `samples/real_world_campaign/` - **52 real, publicly-shared phishing
  emails** (not fabricated), pulled from the "Phishing Pot" research
  corpus (CC BY-NC 4.0 - see `NOTICE.md` in that folder for attribution
  and license terms). Includes several genuinely repeated campaigns
  (same domain, same template, caught multiple times) so
  `--cluster` has real matches to find - try it, it's a better demo than
  the synthetic data below. Run `fetch_real_world_samples.py` in that
  folder to pull a fresh/larger batch yourself.
- `samples/sample_email.eml` - a fabricated phishing email: lookalike
  domain (`paypa1-secure.com`), failed SPF/DKIM/DMARC, a VPS/hosting
  origin IP whose reverse DNS doesn't match the claimed domain, urgency
  language, and a `.pdf.exe` double-extension executable attachment.
  Scores **High Risk** end-to-end.
- `samples/legit_email.eml` - a clean control email (passing SPF/DKIM/
  DMARC, no attachments) to sanity-check the pipeline doesn't just flag
  everything.
- `samples/campaign_batch/` - three variants of the same phishing
  template (shared `X-CampaignID`, reply-to, and body) for exercising
  `--campaign-dir` correlation.

All sample data is fabricated for testing - none of it is a real
phishing sample or targets a real domain/organization.

## Output schema (abridged)

```json
{
  "email": {"subject": "...", "from_address": "...", "from_domain": "...", "message_id": "...", "date": "..."},
  "sender_ip": "51.75.64.22",
  "geo": {"country": "...", "city": "..."},
  "hop_trace": [ { "hop": 1, "ip": "...", "country": "...", "asn_description": "...", "hostname_matches_claimed_domain": false, "...": "..." } ],
  "spf": {"result": "fail", "source": "...", "detail": "..."},
  "dkim": {"result": "fail", "source": "...", "detail": "..."},
  "dmarc": {"result": "fail", "policy": null, "source": "...", "detail": "..."},
  "indicators": ["...plain-English red flags..."],
  "risk_level": "high",
  "attachments": { "attachment_count": 1, "attachments": [...], "summary": {...} },
  "fraud_score": 67.55,
  "fraud_classification": "High Risk",
  "fraud_score_breakdown": {"geo_score": 100.0, "attachment_score": 53.0, "campaign_score": 60.0, "weights": {...}},
  "campaign_correlation": {"mode": "single", "reasons": ["..."]}
}
```

This is the contract the blockchain evidence-ledger module and the
dashboard front end should build against.

## Optional dependencies

Every optional dependency below has a working fallback if it's missing -
the pipeline never crashes for lack of one, it just loses some precision.
None were installable in the sandbox this project was assembled in
(outbound PyPI access was blocked by that environment's network policy),
so **install them in your own environment** before a live demo:

| Package | Used by | If missing |
|---|---|---|
| `requests` | `geolocation.py` | **Required** - geolocation won't work at all without it |
| `dnspython` | `auth_checker.py` | Falls back to header-only SPF/DKIM/DMARC (fine when `Authentication-Results` is already present, which is true for almost all real-world mail) |
| `ipwhois` | `asn_lookup.py` | Falls back to the ASN/org fields `ip-api.com` already returned during geolocation |
| `python-magic` (+ system `libmagic`) | `attachment_metadata.py` | Falls back to Python's `mimetypes` stdlib module (less accurate MIME sniffing) |
| `oletools` | `attachment_macro_analyzer.py` | Macro analysis is skipped (reported honestly as `"analysis_performed": false"`, not silently ignored) |

## Honest limitations (say these out loud to judges, don't let them find them)

- **DKIM verification is NOT full cryptographic verification.** The live
  fallback in `auth_checker.py` confirms a DKIM signature is *present*
  and a public key is *published*, not that the signature is
  cryptographically valid. Full verification needs RFC 6376 header/body
  canonicalization - `dkimpy` does this in one call if you want to add it.
- **DMARC alignment is simplified** (exact-domain match, not the full
  RFC 7489 organizational-domain relaxed mode).
- **SPF evaluation is simplified** (`ip4:`/`ip6:`/one level of `include:`/
  the trailing `all` mechanism - not macros, `mx`/`ptr`, or deep include
  chains).
- **The reverse-DNS "hostname matches claimed domain" check is a naive
  suffix match.** It correctly catches the crude phishing case
  (`vps-1234.cheaphost.ru` claiming to be `paypal.com`) but can
  false-positive on legitimate mail sent through a third-party ESP whose
  reverse DNS doesn't share a suffix with the visible `From:` domain -
  cross-check it against the SPF/DKIM/DMARC verdicts rather than trusting
  it alone.
- **Fraud score weights (25% geo/infra, 35% attachments, 40% campaign)
  and the sub-score formulas in `fraud_score.py` are a reasonable starting
  heuristic, not a validated model.** Tune them against a labeled dataset
  before treating the number as authoritative.
- **Campaign correlation needs at least one other related email to do
  anything beyond single-email heuristics.** Point `--campaign-dir` at a
  real batch (a quarantine folder, a mailbox export) for the strongest
  signal.
- **The `X-CampaignID` header used in `calculate_campaign_scores()` is
  almost never present on real-world mail** - it only exists because the
  hand-built demo data in `samples/campaign_batch/` includes it. Real
  correlation across `samples/real_world_campaign/` relies instead on a
  high enough overall pair score (matching body template + reply-to/IP/
  domain overlap, no header needed) - confirmed working against actual
  captured phishing mail, not just the synthetic demo set.
- **`risk_level` and `fraud_classification` are two independent signals
  and can disagree** - `risk_level` (shown as the colored banner in
  `--report`) comes purely from the *count* of infrastructure/auth
  indicators; `fraud_classification` comes from the weighted 0-100
  `fraud_score`. A message can show `RISK LEVEL: HIGH` (3+ indicator
  hits) while its numeric fraud score still lands in "Low Risk" territory
  if none of those indicators happened to be severe. This surfaced
  running the pipeline against real-world samples - worth understanding
  before a judge asks why the two don't always match.
- **The `geo_score`/`attachment_score`/`campaign_score` you see in
  `fraud_score_breakdown` can shift slightly between identical runs of
  the same email.** `score_from_infrastructure()` is deterministic given
  its inputs, but those inputs (reverse DNS, geolocation, ASN lookups)
  come from live network calls each run - a PTR lookup or an `ip-api.com`
  call that succeeds on one run and times out on the next changes the
  indicator count, which changes the score. This is inherent to relying
  on live external lookups, not a bug; worth mentioning if a judge asks
  why two consecutive runs printed slightly different numbers.

### Fixed: fraud score used to ignore its own clustering tool

Earlier in this project's life, `score_from_campaign()` (batch mode)
only called `calculate_campaign_scores()` - the anchor-based scorer,
which requires an email to pair strongly with an ALREADY-suspicious
anchor (lookalike domain, or 2+ auth failures). Run against real-world
samples, this produced a genuine inconsistency: `campaign_correlation.py
--cluster` would correctly find that three real emails shared the exact
same template and infrastructure, while the numeric fraud score for each
of them still showed `campaign_score: 0`, because none of the three
happened to look like a classic spoofing anchor on its own - they were
just the same spam campaign, caught three times.

`score_from_campaign()` now runs BOTH signals and takes the max: the
anchor-based score, and a cluster-membership score (`find_campaign_clusters()`
- did this email land in a real cluster with other emails in the batch,
and how strong was the closest match). Reasons from whichever signal(s)
fired are both reported, so the report is explicit about which method
found the correlation. Confirmed fixed against `sample-5058.eml`:
`campaign_score` went from 0 to 55 and `fraud_score` from 21.0 to 43.0,
now correctly reflecting the 3-email real-world cluster the tool finds.

### Fixed: `--report` was silently dropping attachment and campaign findings

`report.py`'s formatted `--report` output never had sections for
attachment analysis or campaign correlation, even though both were
computed and sitting in the JSON the whole time - the only way to see
whether an email had a malicious attachment was to drop into `--pretty`
JSON and read it yourself. Added an `ATTACHMENTS` section (per-file
findings, red filename if risky) and a `CAMPAIGN CORRELATION` section
(mode + reasons) to the report, plus the `fraud_classification` label
next to the numeric fraud score.

### Fixed: malformed real-world From headers silently returned nothing

11 of the 52 real-world samples (21% of the corpus) have a `From:`
header Python's own `email.utils.parseaddr()` cannot parse at all -
e.g. `"Microsoft account team", _ <no-reply@access-accsecurity.com>`,
where the stray unquoted comma before the address breaks RFC 2822
address-list parsing. `parseaddr()` doesn't fail loudly on this - it
returns `("", "")`, so the sender silently disappeared: blank `From:` in
the report, blank `(domain: )`, and every downstream check that compares
against the claimed domain (reverse-DNS match, SPF/DMARC alignment,
lookalike-domain detection) was comparing against an empty string
instead of the real one. `email_parser.py` now falls back to a regex
extraction (first `<email>` pattern, or a bare email-looking token) only
when the standard parser comes up empty - well-formed headers are
unaffected, confirmed against the whole existing sample set. Whether
this pattern is accidental sloppiness or a deliberate parser-evasion
trick varies by campaign; either way, real attacker mail should not be
able to blank out its own sender field just by malforming a header.

## File-by-file map

| File | Role |
|---|---|
| `main.py` | Orchestrates the full pipeline; CLI entry point |
| `email_parser.py` | Parses raw `.eml` into structured header data |
| `ip_extractor.py` | Pulls an IP out of each `Received:` header *(rebuilt - see above)* |
| `ip_validator.py` | Filters to public, traceable IPs *(rebuilt - see above)* |
| `geolocation.py` | IP -> country/city/lat/lon via `ip-api.com` |
| `asn_lookup.py` | IP -> ASN/owner via RDAP, hosting-provider heuristic |
| `dns_lookup.py` | Reverse DNS (PTR) lookup |
| `infrastructure.py` | Combines hop lookups; flags infra red flags *(rebuilt - see above)* |
| `auth_checker.py` | SPF/DKIM/DMARC, header-based + live DNS fallback |
| `attachment_extractor.py` | Pulls attachments out of the `.eml` |
| `attachment_metadata.py` | Hash, size, entropy, MIME type |
| `attachment_detector.py` | File signature, executables, double extensions, mismatches |
| `attachment_macro_analyzer.py` | Static VBA/macro analysis via `oletools` |
| `attachment_ioc.py` | URLs/IPs/domains found inside attachment bytes |
| `attachment_analyzer.py` | Coordinates the five attachment modules above |
| `campaign_correlation.py` | Cross-email fingerprint matching / campaign attribution |
| `fraud_score.py` | Combines infra + attachment + campaign risk into one score |
| `report.py` | Human-readable terminal report formatter |
