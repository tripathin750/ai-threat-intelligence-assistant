# AI-Based Threat Intelligence Assistant
# Day 22 – MITRE ATT&CK Deep Dive

**Date:** 6 August 2026

---

# Objective

Understand the structure of MITRE ATT&CK well enough to design a responsible mapping layer — what a tactic, technique, and sub-technique actually represent, and specifically what a CVE→technique mapping can and cannot honestly claim.

---

# Topics Studied

## Tactics vs Techniques vs Sub-techniques vs Procedures

```
Tactic            "why" — the adversary's goal (e.g. Initial Access)
   └─ Technique    "how", in general      (e.g. T1190 Exploit Public-Facing Application)
       └─ Sub-technique   "how", more specific   (e.g. T1059.001 PowerShell)
           └─ Procedure   the specific, observed real-world instance
```

A **tactic** is the adversary's objective. A **technique** is a general method of achieving it. A **sub-technique** narrows that method further. A **procedure** is a documented, specific real-world use of a technique by a particular threat actor or malware family. ATT&CK organizes hundreds of techniques under 14 Enterprise tactics (Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact, and Resource Development).

## Why CVEs and ATT&CK Are Different Kinds of Data

A CVE describes a *specific software flaw*. An ATT&CK technique describes a *general adversary behavior*. A CVE being exploitable does not, by itself, specify which ATT&CK technique an attacker would use to exploit it in practice — that depends on context (is it Internet-facing? does exploitation require an authenticated session? does it enable code execution or just information disclosure?) that isn't always fully captured in a CVE description.

## The Honest Limit of Automated Mapping

This is the single most important thing to internalize before writing any mapping code: **a keyword match between a CVE description and an ATT&CK technique's typical behavior is a hypothesis, not a fact.** MITRE's own CVE→ATT&CK mappings (where they exist, e.g. via CAPEC) are curated by analysts; an automated system inferring the same connection from description text alone is doing something structurally weaker and must say so explicitly, every time.

## Groups and Software (Context for Later, Not Implemented Here)

ATT&CK also catalogues **Groups** (named threat actors) and **Software** (malware/tools), each linked to the techniques they're documented using. This project's MVP catalogue (Day 23) covers only techniques directly relevant to vulnerability exploitation — Groups/Software mapping is a natural extension but out of scope for the current pipeline.

---

# Key Learnings

- ATT&CK's tactic→technique→sub-technique→procedure hierarchy moves from "why" to increasingly specific "how."
- A CVE is a flaw; a technique is a behavior — connecting them requires inference, not a lookup.
- Any automated CVE→ATT&CK mapping must be labelled as an inference, distinct from an official, analyst-curated assertion — this becomes the `mapping_type: Literal["inferred", "official"]` field implemented on Day 24.

---

# Security Considerations

Presenting an inferred ATT&CK mapping as if it were an official MITRE assertion would be a form of overclaiming that could mislead a defender's prioritization — for example, causing a team to focus detection effort on the wrong technique. The mapping design (Day 23–24) treats this as a correctness requirement, not a nice-to-have caveat.

---

# Reflection

This was a research day rather than a coding day, but it's the day that determined the shape of `mapping_type` and the conservative, signal-based (rather than broad keyword-based) inference approach implemented next — understanding what ATT&CK actually represents made it obvious that an inference needs to be narrow and explainable, not a best-effort guess dressed up as a fact.

---

# Next Steps

- Bring a curated subset of the Enterprise ATT&CK catalogue into the database (Day 23).
- Implement the inference logic and its explicit `inferred` vs `official` labelling (Day 24).

---

# 🎯 End-of-Day Challenge — With Answers

**1. What's the difference between a technique and a procedure?**
✅ A technique is a general method (e.g. "Exploit Public-Facing Application"); a procedure is a specific, documented real-world instance of a particular actor using that technique.

**2. Why can't a CVE be automatically and confidently mapped to one "correct" ATT&CK technique?**
✅ Because a CVE describes a flaw, not an attacker's chosen method of exploitation — the same vulnerability could plausibly be used via more than one technique depending on context the CVE description may not fully specify.

**3. Why does the mapping design need an explicit `inferred` vs `official` distinction?**
✅ Because an automated, description-based inference is a fundamentally weaker claim than a MITRE-curated mapping, and presenting them identically would mislead anyone using the mapping to prioritize defenses.

---

# 🎤 Interview Questions

**Q1. Why not just map every CVE to the broadest possible tactic ("Initial Access") to guarantee some coverage?**
That would trade specificity for coverage in a way that provides false confidence — a broad, low-information mapping applied to nearly everything is worse than no mapping at all, because it looks informative without actually helping prioritize a response.

**Q2. How would you validate an automated mapping's quality?**
Compare a sample of inferred mappings against any available official/curated mappings (e.g. via CAPEC or vendor advisories) and measure agreement; track false-positive rate (a mapping asserted where no reasonable analyst would agree) separately from coverage (what fraction of CVEs get any mapping at all) — this is exactly the evaluation approach used on Day 30.

---

# ⚡ 5-Minute Revision

- Tactic (why) → Technique (how) → Sub-technique (how, specific) → Procedure (observed instance).
- 14 Enterprise ATT&CK tactics.
- CVE = flaw; ATT&CK technique = behavior — connecting them is inference.
- Inferred mappings must be explicitly labelled, never presented as official.
