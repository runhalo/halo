# Halo Jurisdiction Coverage Matrix

_Last updated: April 9, 2026_

## Regulatory Framework Comparison

| Framework | Age Threshold | Consent Model | Tracking Rules | Ad Restrictions | Penalty Range | Enforcement Body | Halo Rules |
|-----------|---------------|---------------|----------------|-----------------|---------------|------------------|------------|
| **US COPPA** | < 13 | Parental consent (VPC) | Requires consent for persistent identifiers | Behavioral ads require VPC | $53,088/violation/day | FTC | 26 |
| **California AADCA** | < 18 | Default high privacy | High privacy by default | Profiling banned by default | $2,500-$7,500/child | CA AG | 15 |
| **UK AADC** | < 18 | Design-based (15 standards) | Off by default; no profiling | Targeted ads prohibited | Up to 4% global turnover | ICO | 19 |
| **EU GDPR Art. 8** | 13-16 (varies by state) | Parental consent (geo-fragmented) | Minimization required | Legitimate interest restricted | Up to 4% global turnover | DPAs | 5 |
| **EU DSA Art. 28** | < 18 | Platform duty of care | Profiling banned for minors | Profiling-based ads banned | Up to 6% global turnover | EC / DSCs | 10 |
| **EU AI Act** | < 18 | Risk-based (high-risk AI) | Transparency required | AI-based targeting restricted | Up to €35M or 7% turnover | AI Office | 30 |
| **India DPDP** | < 18 | Parental consent (strictest) | **ALL tracking banned** | **ALL targeted ads banned** | Up to ₹250 crore (~$30M) | DPB | 5 |
| **Brazil LGPD** | < 12 (children) / < 18 (adolescents) | Best interest standard | Best interest test required | Data-gated gameplay banned | Up to 2% revenue (R$50M cap) | ANPD | 4 |
| **Canada PIPEDA** | < 13 (no meaningful consent) | Meaningful consent test | OPC deems behavioral ads inappropriate | Behavioral ads fail "reasonable purpose" | Up to $100K CAD/violation | OPC | 4 |
| **South Korea PIPA** | < 14 | Parental/guardian consent | Clear child-appropriate notices | 3% global revenue penalty | Up to 3% global revenue | PIPC | 3 |
| **Australia OSA/Min Age** | < 16 (social media ban) | **Outright ban** (no consent override) | eSafety Commissioner powers | Platform-level restrictions | Up to A$49.5M | eSafety Commissioner | 13 |
| **Utah SB 142** | < 18 | Parental consent + app store | DM restrictions for minors | Supervisory tools required | State enforcement | UT AG | 5 |
| **Ethical Design** | N/A | Advisory (AAP/WHO) | Addictive design detection | Dark pattern detection | Advisory | N/A | 5 |
| **AI Audit** | N/A | Advisory | AI-generated code risks | N/A | Advisory | N/A | 6 |
| **AU Safety by Design** | N/A | Design framework | Safety by design principles | N/A | eSafety guidance | eSafety Commissioner | 6 |
| **Behavioral Design** | N/A | Advisory (AAP/WHO) | Social comparison, loot boxes | Stopping cues, parent tools | Advisory | N/A | 4 |

## Summary Statistics

| Metric | Value |
|--------|-------|
| Total regulatory frameworks | 16 |
| Total active rules | 160 |
| Jurisdictions covered | 12 (US Federal, California, Utah, UK, EU, India, Brazil, Canada, South Korea, Australia, international) |
| Languages supported | 10 (JavaScript, TypeScript, Python, PHP, Ruby, Java, Kotlin, Swift, Go, HTML) |
| Enforcement actions tracked | 24 |
| Regulatory calendar events | 14 |

## Key Differentiators by Jurisdiction

### Strictest: India DPDP Act (Section 9)
- Under-18 threshold (highest globally)
- **Absolute ban** on tracking, behavioral monitoring, AND targeted advertising
- No consent override — parental consent cannot authorize tracking
- Triple lock: consent + no tracking + no ads

### Most Fragmented: EU GDPR Article 8
- Consent age varies 13-16 by member state
- Ireland/Spain/UK/Denmark/Sweden/Poland/Latvia = 13
- France = 15
- Germany/Netherlands = 16
- Requires geo-aware age gating

### Most Unique: Australia Minimum Age Act
- **Outright ban** on under-16 social media accounts
- Parental consent **cannot override** the ban
- Only jurisdiction with a pure prohibition model (vs. consent model)
- A$49.5M maximum penalty

### Most Comprehensive: UK AADC
- 15 design standards covering the full product lifecycle
- Applies to services "likely to be accessed" by children (broad scope)
- Includes nudge techniques, connected toys, parental controls
- Enforced since September 2021 with active ICO investigations

## Citation Sources

All rules in Halo trace to verified primary regulatory sources:

| Jurisdiction | Primary Source |
|--------------|---------------|
| US COPPA | [16 CFR Part 312](https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-312) |
| GDPR Art. 8 | [gdpr-info.eu/art-8](https://gdpr-info.eu/art-8-gdpr/) |
| EU DSA Art. 28 | [eu-digital-services-act.com](https://www.eu-digital-services-act.com/Digital_Services_Act_Article_28.html) |
| India DPDP | [dpdpa.com Section 9](https://dpdpa.com/dpdpa2023/chapter-2/section9.html) |
| Brazil LGPD | [lgpd-brazil.info Article 14](https://lgpd-brazil.info/chapter_02/article_14) |
| Canada PIPEDA | [OPC Meaningful Consent](https://www.priv.gc.ca/en/privacy-topics/collecting-personal-information/consent/gl_omc_201805/) |
| South Korea PIPA | [ICLG Data Protection - Korea](https://iclg.com/practice-areas/data-protection-laws-and-regulations/korea) |
| Australia OSA | [eSafety Social Media Age](https://www.esafety.gov.au/about-us/industry-regulation/social-media-age-restrictions) |
| UK AADC | [ICO Children's Code](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/childrens-information/childrens-code-guidance-and-resources/) |
| California AADCA | [AB 2273](https://leginfo.legislature.ca.gov/faces/billNavClient.xhtml?bill_id=202120220AB2273) |
| Utah SB 142 | [SB0142](https://le.utah.gov/~2025/bills/static/SB0142.html) |
| EU AI Act | [artificialintelligenceact.eu](https://artificialintelligenceact.eu/) |
