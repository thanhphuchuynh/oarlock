---
stepsCompleted: [1, 2, 3, 4, 5, 6]
inputDocuments:
  - _bmad-output/planning-artifacts/research-technical-oarlock-2026-08-20.md
  - _bmad-output/planning-artifacts/adversarial-review-spec-2026-08-20.md
  - ARCHITECTURE.md
  - docs/threat-model.md
workflowType: 'research'
lastStep: 6
research_type: 'domain'
research_topic: 'The market and regulatory space an open-source privileged-session gateway for NAT-bound consumer hardware lands in'
research_goals: 'Establish whether the category is real and growing, who is in it, and what compliance will demand of session recording — before the PRD fixes requirements'
user_name: 'Tphuc'
date: '2026-08-20'
web_research_enabled: true
source_verification: true
findings_that_change_the_design: 4
---

# Research Report: domain

**Date:** 2026-08-20
**Author:** Tphuc
**Research Type:** domain

---

## Executive Summary

The category is real, growing fast, and regulated in two directions that **point opposite
ways on the single most sensitive setting in the specification.**

| # | finding | effect |
|---|---|---|
| **D1** | PAM is a **$5.3 B market in 2026** heading for ~$19.7 B by 2033 (≈20.6 % CAGR), and session recording is a named driver | The category is not speculative. It also means the incumbents are well funded and Oarlock competes on a niche, not on breadth. |
| **D2** | **PCI DSS 4.0.1** (mandatory since March 2025) expects privileged session recording capturing *every administrator keystroke* in a **tamper-proof log** | Two gaps: `record_input: false` is the wrong default for a PCI deployment, and **Oarlock's recordings have no integrity protection at all**. |
| **D3** | Under GDPR, continuous keystroke logging is **effectively prohibited**; a French regulator fined a company **€40 000 in Dec 2024** for keystroke monitoring; works councils in DE, NL, AT, SE, FR and PL hold **co-determination rights**, and systematic monitoring needs a **DPIA before deployment** | The operators being recorded are employees. Recording input to satisfy D2 can be a separate legal violation in the EU, independent of GDPR. |
| **D4** | The **EU Cyber Resilience Act** starts mandatory incident and vulnerability reporting on **11 September 2026** — three weeks away — and fully applies 11 Dec 2027. It covers products with digital elements **including remote data processing components essential to a product's core function** | Oarlock is exactly such a component. Shipping it inside an EU-sold device pulls in security-by-design, lifecycle updates, coordinated disclosure and SBOM obligations, and the project has none of that yet. |

**The headline is D2 versus D3.** `record_input` is not a preference to be defaulted once
and forgotten. It is a **jurisdiction- and tenant-scoped policy** where one regime asks for
keystrokes and another forbids them, and the specification currently treats it as a single
global boolean with a privacy rationale.

## Table of Contents

1. [Industry structure and market](#1-industry-structure-and-market)
2. [Competitive landscape](#2-competitive-landscape)
3. [Regulatory environment](#3-regulatory-environment)
4. [Technology trends](#4-technology-trends)
5. [Synthesis and design implications](#5-synthesis-and-design-implications)
6. [Sources](#6-sources)

---

## 1. Industry structure and market

Privileged access management was valued at **US$ 5.3 bn in 2026**, projected to
**US$ 19.7 bn by 2033** at a **20.6 % CAGR**. Independent estimates for 2026 range roughly
**$4.4–6.3 bn** depending on scope, and forecasts cluster between 16 % and 29 % CAGR — the
spread is large enough that the precise number should not be quoted as fact, but the
direction is unambiguous. Confidence: medium on magnitude, high on direction.

Session recording is called out as a **key component** of PAM rather than an add-on, and
regulation is the named driver: HIPAA audit-trail mandates for EMR administrators, Japan's
FSA cybersecurity guidelines and Economic Security Promotion Act pushing financial
institutions and semiconductor firms toward privileged session recording.

**What this means for a niche project.** The money is in enterprise PAM for
human-administered servers, and it is well defended. Oarlock is not competing there. Its
niche — privileged sessions to **hardware the vendor does not administer, sitting on a
customer's network, running no listener** — is a corner the incumbents reach only by
requiring an agent that assumes a Linux host with system users. That corner is real and it
is not where a $19 bn market is spending its money, which is both the opportunity and the
reason this stays a focused open-source project rather than a product plan.

## 2. Competitive landscape

The technical research covered the tooling comparison. The domain-level observation is
about **licence direction**, and it is consistent enough to be a trend rather than an
anecdote:

- **Teleport** — OSS core relicensed Apache 2.0 → **AGPLv3** (1 Dec 2023); Community
  Edition moved to a **commercial licence at v16**, restricting company use while remaining
  free for individuals.
- **HashiCorp** — moved its entire portfolio to **BUSL 1.1** in August 2023, the event that
  produced OpenTofu.
- **OpenZiti** — remains **Apache 2.0**, no change found.

The pattern: infrastructure vendors with a commercial product have been walking their
permissive licences back, and the response has been forks and permissively licensed
alternatives. Two consequences for Oarlock:

1. **Apache-2.0 is a differentiator, not just a default.** The thing a company cannot get
   from Teleport any more is a permissively licensed foundation it may build a product on.
   That is precisely what Oarlock offers.
2. **It also means Oarlock will be adopted by people who want to avoid paying someone**,
   which sets expectations about contribution: expect users, not contributors, and plan the
   maintenance burden accordingly.

## 3. Regulatory environment

### 3.1 PCI DSS wants keystrokes in a tamper-proof log

PCI DSS **4.0.1 has been mandatory since March 2025**. Privileged session recording is
treated as a required safeguard, described as capturing *every administrator keystroke,
file access and configuration change in a tamper-proof log*, with sessions replayable in
full showing time, date, commands and responses, aligned to Requirement 8 (identify and
authenticate), 10 (log and monitor) and 12 (policy). 2026 audits are reported to focus on
stricter session-management enforcement and on behavioural anomalies rather than static
grants.

Two gaps this opens in the specification:

**(a) `record_input: false` is the wrong default for such a deployment.** The reasoning
behind the default — keystroke capture turns recordings into a credential store — remains
correct and is worth keeping. But the document presents the setting as one a careful
operator would leave off, when a PCI-scoped operator may have no choice. The setting needs
to be presented as a **compliance decision with a documented consequence**, not a hygiene
default.

**(b) Nothing in Oarlock's recordings is tamper-evident.** "Tamper-proof log" is the phrase
the requirement uses, and the spec's recorder writes plain asciicast to a filesystem or a
bucket. Any holder of write access to the store can alter a recording afterwards and
nothing detects it. What is missing:

- a **hash chain** over the event stream, so truncation or edits are detectable;
- a **signed manifest** at close, over the chain head, the session metadata and the byte
  counts;
- **object-lock / WORM guidance** for the S3 and GCS recorders;
- and an integrity check surfaced at replay, because an integrity guarantee nobody verifies
  is decoration.

This is a genuine specification gap, not a configuration one, and it is cheap now and
expensive later — a hash chain has to be designed into the writer, not bolted on to a
corpus of existing recordings.

### 3.2 GDPR and EU employment law point the other way

The operators whose sessions Oarlock records are **employees**, which puts these recordings
inside EU employee-monitoring law wherever operators sit in the EU:

- Continuous keystroke logging and covert screen capture are treated as **effectively
  prohibited regardless of the legal basis claimed** — generally disproportionate and hard
  to justify under a legitimate-interest test.
- Enforcement is not theoretical: **CNIL fined a company €40 000 in December 2024** over
  inactivity-based keystroke monitoring.
- **Consent is almost never the right legal basis** for employee monitoring, and systematic
  monitoring requires a **Data Protection Impact Assessment before deployment**.
- **Works councils hold co-determination rights** in the Netherlands, Germany, Austria and
  Sweden; Germany requires consultation *before* a monitoring system is introduced, France
  requires a published internal policy plus consultation, Poland requires it in work
  regulations with a works-council agreement. **Deploying without that is a separate legal
  violation, not a GDPR matter.**

Note the asymmetry carefully, because it decides how much of this is Oarlock's problem:
Oarlock records a **privileged administrative session on company equipment**, which is a
security control with a much stronger justification than productivity surveillance. Nothing
found suggests recording administrative sessions is itself disproportionate. What the
research does establish is that **capturing keystrokes** is the line, and that **the
process obligations — DPIA, works-council consultation, published policy — attach to the
deployer, not to the tool.**

So Oarlock's obligation is to make the deployer's compliance possible and its choices
explicit: per-region policy, a documented DPIA input, and a clear statement of what each
setting captures.

### 3.3 The Cyber Resilience Act has a deadline three weeks away

- **11 September 2026**: mandatory incident and vulnerability reporting obligations begin.
- **11 December 2027**: full applicability.
- Scope: all products with digital elements — hardware, embedded systems, IoT — and
  explicitly **remote data processing components essential to a product's core function**.
- Requirements: security by design, lifecycle security updates, transparent vulnerability
  handling.
- Alongside it, **NIS2**'s first compliance audit deadline was **30 June 2026**, covering
  18 critical sectors at the organisational level, while CRA covers the products.

**Oarlock is a remote data processing component.** A connected exercise machine sold in the
EU with an Oarlock agent inside it is in CRA scope, and the agent is part of what has to
satisfy security-by-design, update and disclosure obligations. The threat model currently
defers this entirely: § 13 says a security contact is needed "once this project is real".
Under CRA that is not a nice-to-have for anyone shipping it in an EU product.

Concretely the project needs, before anyone embeds it: `SECURITY.md` with a coordinated
disclosure policy and a real contact, an **SBOM** per release, signed releases with
verifiable provenance, a documented support and security-update window, and a changelog
that distinguishes security fixes. None of that is architecture — all of it is the kind of
thing that is painful to retrofit onto a project with users.

## 4. Technology trends

Two directions in the sources that bear on the design:

- **Away from static grants, toward behaviour.** 2026 PCI audit focus is described as
  moving to *behavioural anomalies rather than static access grants*, and the short-lived
  credential consensus points the same way. Oarlock's mid-session re-check and revocation
  stream are already on the right side of this; what it lacks is any anomaly surface — no
  metric for "this operator has opened 40 sessions in an hour", no hook for a detection
  system. `AuditSink` is the natural place, and nothing currently says so.
- **Recording is becoming table stakes, not a differentiator.** Multiple regimes now name
  it. That reinforces the choice to terminate SSH at the gateway, and it means the
  interesting competition moves to what you can *do* with recordings — search, integrity,
  retention, redaction — rather than whether you have them.

The gap nobody in the sources addresses: **redaction**. A recording that captured a
credential is a durable secret, and every regime that wants recordings also wants secrets
protected. No researched source describes redacting a terminal recording, which suggests
either that nobody does it well or that it is genuinely hard — probably both, since it means
pattern-matching a byte stream with escape sequences in it. Worth flagging as out of scope
explicitly rather than leaving as an assumed capability.

## 5. Synthesis and design implications

| # | change | where | urgency |
|---|---|---|---|
| **1** | Add **recording integrity**: hash chain over the event stream, signed manifest at close, WORM/object-lock guidance, verification at replay | `ARCHITECTURE.md` § 8, `docs/plugins.md` § 4 | **High** — must be in the writer from the first commit; cannot be retrofitted to existing recordings |
| **2** | Reframe `record_input` as a **jurisdiction-scoped compliance policy**, per tenant or region, not one global boolean — with both rationales stated | `ARCHITECTURE.md` § 8, `docs/threat-model.md` § 9 | High — it is the setting most likely to be set wrong in both directions |
| **3** | Add a **compliance appendix**: what each setting captures, DPIA inputs, works-council note, PCI mapping to Requirements 8/10/12 | new `docs/compliance.md` | Medium — needed before the first regulated adopter, not before M0 |
| **4** | Add `SECURITY.md`, coordinated disclosure, SBOM per release, signed releases, documented support window | repo root, CI | **High** — CRA reporting obligations begin 11 Sep 2026, and this is cheap now |
| **5** | State explicitly that **redaction is out of scope**, and that a recording must be treated as secret-bearing | `docs/threat-model.md` § 9 | Medium — silence reads as a promise |
| **6** | Give `AuditSink` a documented **anomaly surface**: session rate per principal, denial rate, unattended-session count | `docs/plugins.md` § 10 | Low — but it is where the regimes are heading |

**On the market question the workflow exists to answer:** the category is real and growing
at roughly 20 % a year, recording is a named regulatory driver rather than a feature
preference, and the licence direction of the incumbents has opened exactly the gap a
permissively licensed project can occupy. Nothing in the domain research argues against
building this. What it argues is that **the compliance surface is larger than the
specification currently admits**, and that two of its defaults are set as if only privacy
mattered when a second regime is pulling the other way.

## 6. Sources

- [Persistence Market Research — PAM market, $5.3 bn 2026 → $19.7 bn 2033](https://www.persistencemarketresearch.com/market-research/privileged-access-management-market.asp) · [Mordor Intelligence — PAM market](https://www.mordorintelligence.com/industry-reports/privileged-access-management-pam-market) · [Fortune Business Insights](https://www.fortunebusinessinsights.com/privileged-access-management-market-112360) · [Netwrix — PAM solutions market 2026 guide](https://netwrix.com/en/resources/blog/privileged-access-management-solutions-market/)
- [PCI DSS privileged session recording](https://hoop.dev/blog/pci-dss-privileged-session-recording-a-mandatory-safeguard) · [PCI DSS 4.0 requirements checklist for 2026](https://securityboulevard.com/2026/02/pci-dss-4-0-requirements-checklist-for-2026/) · [PCI DSS v4.0 deadlines](https://www.snvatech.com/blog/pci-dss-v4-0-deadlines-everything-you-need-to-know) · [the 12 PCI DSS requirements](https://www.venn.com/learn/pci-dss-compliance/pci-dss-requirements/)
- [Employee monitoring and GDPR](https://secureprivacy.ai/blog/employee-monitoring-gdpr-guide) · [GDPR-compliant employee monitoring checklist 2026](https://gstride.ai/blog/gdpr-compliant-employee-monitoring/) · [12 most asked questions on EU employee monitoring laws, 2026](https://www.worktime.com/blog/legal-aspects/12-most-asked-questions-on-eu-employee-monitoring-laws) · [Davis Wright Tremaine — remote monitoring of employees in the EU](https://www.dwt.com/blogs/privacy--security-law-blog/2020/11/employee-data-monitoring-gdpr-compliance) · [is keystroke logging legal](https://apploye.com/blog/is-it-legal-to-use-keylogger/)
- [Crowell & Moring — CRA 11 September 2026 reporting deadline](https://www.crowell.com/en/insights/client-alerts/eu-cyber-resilience-act-countdown-11-september-2026-incidentvulnerability-reporting-deadline-is-less-than-100-days-away) · [European Commission — Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) · [Wilson Sonsini — new EU obligations for connected devices](https://www.wsgr.com/en/insights/new-eu-cybersecurity-obligations-for-connected-devices-what-you-need-to-know.html) · [Somos — navigating NIS2 and the CRA for IoT](https://www.somos.com/insights/navigating-nis2-and-cyber-resilience-act) · [CRA for software and IoT companies](https://www.wirtek.com/blog/cyber-resilience-act-explained-for-software-and-iot-companies)
- [Teleport OSS to AGPLv3](https://goteleport.com/blog/teleport-oss-switches-to-agpl-v3/) · [Teleport CE commercial licence at v16](https://goteleport.com/blog/teleport-community-license/) · [Business Source License](https://en.wikipedia.org/wiki/Business_Source_License) · [OpenTofu](https://en.wikipedia.org/wiki/OpenTofu)
