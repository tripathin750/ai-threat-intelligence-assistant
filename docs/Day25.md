# AI-Based Threat Intelligence Assistant
# Day 25 – Security Mitigation Fundamentals

**Date:** 9 August 2026

---

# Objective

Establish the vocabulary and structure for mitigation guidance before writing the recommendation engine: what kinds of controls exist, how they relate to urgency, and how a per-technique mitigation knowledge base should be organized — `MITIGATION_BY_TECHNIQUE` in [backend/data/attack_catalog.py](../backend/data/attack_catalog.py).

---

# Topics Studied

## Categories of Mitigation

- **Patching** — apply the vendor's fix; the most direct remediation when one exists.
- **Configuration changes** — disabling an unused feature, hardening a default setting.
- **Network segmentation** — limiting which systems can reach the vulnerable component.
- **Access control / least privilege** — restricting who or what can exercise the vulnerable path.
- **Input validation** — a compensating control against classes like injection, sometimes achievable at a WAF/proxy layer even before a patch is available.
- **Compensating controls** — anything that reduces risk without removing the underlying flaw, used when immediate patching isn't feasible.
- **Vendor advisories** — always the authoritative source for product-specific remediation steps; this project explicitly directs users there rather than guessing product details itself (Day 18).

## Time Horizon Matters as Much as the Action

A mitigation recommendation is more useful when it's split by urgency:

```
Immediate action    → what to do right now, today
Short-term          → compensating controls while the real fix is prepared
Long-term           → the structural practice that prevents a recurrence
```

This maps directly to `MitigationResult`'s three fields (Day 26): `immediate_action`, `short_term`, `long_term`.

## Structuring Mitigation Knowledge Per ATT&CK Technique

```python
MITIGATION_BY_TECHNIQUE = {
    "T1190": "Reduce Internet exposure of affected applications and place them behind appropriate access controls.",
    "T1203": "Restrict untrusted files and keep client software patched through managed update processes.",
    "T1210": "Restrict remote-service access to trusted networks and require strong authentication.",
    "T1068": "Apply least privilege and promptly patch local privilege-escalation vulnerabilities.",
    "T1059": "Constrain command execution with least-privilege service accounts and application allowlisting where appropriate.",
}
```

Tying mitigation guidance to the *technique* (behavior) rather than to the CVE itself means the same well-reasoned, generic guidance ("reduce Internet exposure" for T1190) applies consistently to every CVE that maps to that technique, instead of re-deriving bespoke advice per CVE — a technique-level knowledge base scales far better than a per-CVE one, and is exactly the kind of general knowledge that doesn't hallucinate the way a CVE-specific fabricated detail would.

## Severity Still Matters Independently of Technique

Not every high-severity CVE maps to a known technique (a novel or unusually described CVE can have zero ATT&CK signals, Day 24), and not every technique-mapped CVE is critical. Mitigation guidance needs both severity-driven urgency and technique-driven specifics, combined — which is exactly what `recommend_mitigations()` does on Day 26.

---

# Key Learnings

- Mitigation advice benefits from an explicit time horizon (immediate/short-term/long-term), not just a flat list.
- A technique-level (not CVE-level) mitigation knowledge base is more maintainable and more defensible than trying to generate bespoke advice per vulnerability.
- Vendor advisories remain the authoritative source for product-specific steps — a general-purpose tool should point there, not attempt to replace them.
- Severity and technique context are independent inputs that both need to feed the final recommendation.

---

# Security Considerations

Recommending an overly specific but wrong remediation step (e.g. a fabricated configuration change for a product the system doesn't actually know) would be actively harmful — it could give a false sense of remediation while the real exposure remains. This is why the mitigation knowledge base stays general and technique-scoped rather than attempting CVE-specific remediation detail it has no reliable way to source.

---

# Reflection

Mitigation guidance is the part of this pipeline most directly consumed by a human making a real operational decision, which makes the "don't fabricate specifics" discipline from earlier days matter most here. Keeping the knowledge base at the technique level, generic but genuinely useful, was the right tradeoff for an MVP that has no live vendor-advisory integration yet.

---

# Next Steps

- Implement `recommend_mitigations()` combining severity and inferred techniques (Day 26).

---

# 🎯 End-of-Day Challenge — With Answers

**1. Why split mitigation guidance into immediate/short-term/long-term rather than one flat recommendation?**
✅ Different actions are actionable on different timelines — a compensating control today looks different from the structural process change that prevents recurrence; presenting them separately makes the guidance usable immediately without waiting on the long-term item.

**2. Why key the mitigation knowledge base by ATT&CK technique instead of by CVE?**
✅ Techniques represent general, recurring behaviors — one well-reasoned piece of guidance per technique applies correctly to every CVE that maps to it, rather than needing bespoke (and harder to verify) guidance generated per CVE.

**3. Why does this project direct users to vendor advisories instead of generating product-specific remediation steps itself?**
✅ It has no reliable source for product-specific detail (exact config paths, version numbers, workarounds) — generating that from a CVE description alone would risk fabricating specifics the project has no way to verify.

---

# 🎤 Interview Questions

**Q1. How would you extend the mitigation knowledge base to include severity-specific guidance per technique, not just a flat mapping?**
Change `MITIGATION_BY_TECHNIQUE`'s values from a single string to a small structure keyed by severity band (e.g. `{"CRITICAL": "...", "default": "..."}`), and have `recommend_mitigations()` select the appropriate entry — the calling code already has both the technique ID and the severity available.

**Q2. What's the risk of mitigation guidance becoming stale relative to actual current best practice?**
Because it's versioned in code (Day 23's reasoning applies here too), it requires a deliberate review/update rather than updating automatically — a periodic review process (e.g. against current CISA/NIST guidance) would need to be a defined operational practice, not something the current architecture automates.

---

# ⚡ 5-Minute Revision

- Mitigation categories: patching, config changes, segmentation, access control, input validation, compensating controls, vendor advisories.
- Time horizon: immediate / short-term / long-term.
- Knowledge base keyed by ATT&CK technique, not by CVE — scales and stays trustworthy.
- Severity (urgency) and technique (specifics) are independent inputs, combined at generation time.
- Never fabricate product-specific remediation detail the system can't verify.
