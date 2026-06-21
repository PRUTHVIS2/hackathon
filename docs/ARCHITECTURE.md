# Architecture Documentation

## Identity Sprawl & Privileged Access Abuse Detection System

**Track:** Identity & Access Risk Governance
**Approach:** Option B — Cross-Platform Privilege Hygiene + Behavioral Baselines
**Stack:** Python, NetworkX, Pandas, scikit-learn, Streamlit, Plotly

---

## 1. System Overview

This system addresses the enterprise challenge of identity sprawl across hybrid environments (Active Directory, Azure AD, AWS IAM, Okta, Salesforce, ServiceNow) by consolidating fragmented identity data, computing effective privilege including nested group inheritance, detecting abuse patterns, and generating explainable remediation guidance.

**Core Question Answered:** *Which identities in the organization are the most dangerous right now, why are they dangerous, and what should be done about them?*

---

## 2. Architecture Diagram

```
╔═══════════════════════════════════════════════════════════════════╗
║  PHASE 1: DATA LAYER (CSV Files)                                   ║
║  ├─ identities.csv          500 master identity records            ║
║  ├─ ad_accounts.csv         500 AD accounts with group memberships ║
║  ├─ aws_accounts.csv        200 AWS IAM accounts                   ║
║  ├─ okta_accounts.csv       445 Okta accounts                      ║
║  ├─ salesforce_accounts.csv 446 Salesforce accounts                ║
║  ├─ group_memberships.csv   25 groups with inheritance hierarchy   ║
║  └─ audit_events.csv        ~337,000 events over 538 days          ║
╚══════════════════════════════════╤══════════════════════════════════╝
                                   │
                                   ▼
╔═══════════════════════════════════════════════════════════════════╗
║  PHASE 2: IDENTITY CORRELATION ENGINE                              ║
║  ├─ Username normalization per platform convention                 ║
║  ├─ Fuzzy matching: fname.lname ↔ f+lname ↔ email prefixes        ║
║  ├─ Service account pattern: svc_{dept}_{num}                      ║
║  ├─ Contractor prefix handling: c- / c_                            ║
║  └─ Output: identity_360.json (unified identity view)              ║
║  └─ Accuracy: 97.9% (1,558/1,591 correct matches)                 ║
╚══════════════════════════════════╤══════════════════════════════════╝
                                   │
                                   ▼
╔═══════════════════════════════════════════════════════════════════╗
║  PHASE 3: PRIVILEGE NORMALIZATION                                  ║
║  ├─ AD:   StandardUser→1, PowerUser→2, ServerAdmin→4,            ║
║  │        DomainAdmin→5                                            ║
║  ├─ AWS:  ReadOnly→1, PowerUser→3, Administrator→5                ║
║  ├─ Okta: User→1, SuperAdmin→5                                     ║
║  └─ SF:   Standard→1, SystemAdmin→5                                ║
╚══════════════════════════════════╤══════════════════════════════════╝
                                   │
                                   ▼
╔═══════════════════════════════════════════════════════════════════╗
║  PHASE 4: EFFECTIVE PRIVILEGE CALCULATION                          ║
║  ├─ Build group inheritance graph (NetworkX DiGraph)               ║
║  ├─ Detect cycles (prevents infinite loops)                        ║
║  ├─ Walk inheritance chain: child→parent→grandparent              ║
║  ├─ effective_privilege = max(direct, inherited)                   ║
║  └─ 59 identities elevated via inheritance                         ║
╚══════════════════════════════════╤══════════════════════════════════╝
                                   │
                                   ▼
╔═══════════════════════════════════════════════════════════════════╗
║  PHASE 5: BEHAVIORAL ANALYSIS                                      ║
║  ├─ Login frequency per week                                       ║
║  ├─ Platform count from audit events                               ║
║  ├─ Days since last login (computed from events)                   ║
║  ├─ Admin actions (30d and total)                                  ║
║  ├─ Token usage count                                              ║
║  ├─ IP analysis: unique count, dominant ratio, anomaly flag        ║
║  ├─ Activity spike: 3+ admin actions in 5-day window              ║
║  ├─ After-hours activity ratio                                     ║
║  └─ Privilege changes in 30 days                                   ║
╚══════════════════════════════════╤══════════════════════════════════╝
                                   │
                                   ▼
╔═══════════════════════════════════════════════════════════════════╗
║  PHASE 6: RISK DETECTION ENGINE (6 Rules)                          ║
║  ├─ R1: Offboarding Gap — Terminated + Active accounts             ║
║  ├─ R2: Cross-Platform Admin — Admin on 3+ platforms               ║
║  ├─ R3: Dormant Admin — Admin + 90+ days inactive                  ║
║  ├─ R4: Old Credentials — Token/key age > 365 days                 ║
║  ├─ R5: Contractor Admin — Contractor with elevated privilege      ║
║  └─ R6: Service Account Abuse — Svc acct + admin + anomalies      ║
║  └─ Each rule returns: triggered, severity, evidence, platform     ║
╚══════════════════════════════════╤══════════════════════════════════╝
                                   │
                                   ▼
╔═══════════════════════════════════════════════════════════════════╗
║  PHASE 7: RISK SCORING ENGINE                                      ║
║  ├─ Weighted formula:                                              ║
║  │  privilege(40%) + dormancy(20%) + spread(20%) +                ║
║  │  credentials(10%) + offboarding(10%)                            ║
║  ├─ Severity floor: Critical rule → min 80, High rule → min 60    ║
║  ├─ Behavioral boost for anomalies                                 ║
║  └─ Output: 0-100 score + Critical/High/Medium/Low level          ║
╚══════════════════════════════════╤══════════════════════════════════╝
                                   │
                                   ▼
╔═══════════════════════════════════════════════════════════════════╗
║  PHASE 8 & 9: EXPLAINABILITY & REMEDIATION                         ║
║  ├─ Explanations: privilege facts → rule flags → behavioral       ║
║  └─ Remediations: platform-specific actions per triggered rule    ║
║     [OFFBOARDING] Disable {platform} account '{username}'         ║
║     [PRIVILEGE REVIEW] Reduce least-privilege on {platforms}      ║
║     [DORMANCY] Disable/re-certify {platform} admin access         ║
║     [CREDENTIALS] Rotate API token/access key                     ║
║     [CONTRACTOR] Escalate for manager review                      ║
║     [SERVICE ACCT] Audit owner/justification                     ║
╚══════════════════════════════════╤══════════════════════════════════╝
                                   │
                                   ▼
╔═══════════════════════════════════════════════════════════════════╗
║  PHASE 10: DASHBOARD (Streamlit)                                   ║
║  ├─ Executive Summary: KPIs, top 20 risks, distribution charts    ║
║  ├─ Risk Intelligence: heatmaps, platform analysis                 ║
║  ├─ Identity Investigation: search + deep dive profile             ║
║  ├─ Offboarding Watchlist: terminated-but-active identities        ║
║  ├─ Cross-Platform Privilege: multi-platform admin view            ║
║  └─ Behavioral Anomalies: spike and IP anomaly tracking            ║
╚═══════════════════════════════════════════════════════════════════╝
```

---

## 3. AI/ML Approach Explanation

### Anomaly Detection
While this system uses primarily rule-based detection (deterministic, auditable), it incorporates ML-inspired anomaly detection in Phase 5:

**Behavioral Baselining:**
- Each identity's activity pattern is profiled across 11 features
- Anomalies are flagged using statistical thresholds:
  - **Activity Spike:** 3+ admin actions within any 5-day window (configurable)
  - **IP Anomaly:** Dominant IP ratio < 70% with >2 unique IPs (indicates credential sharing or travel)
  - **After-Hours:** >30% activity outside 7 AM - 8 PM business hours

**Scoring Weights:**
The weighted scoring formula (40/20/20/10/10) prioritizes privilege as the strongest risk signal, followed by dormancy and platform spread. This aligns with MITRE ATT&CK T1078 (Valid Accounts) where privileged valid credentials are the primary lateral movement vector.

### Explainability
Every risk score is fully traceable:
- **No black box:** All scores derive from explicit rules + weighted components
- **Evidence-based:** Each rule trigger includes specific evidence (which platform, which account, which metric)
- **Audit-ready:** Remediation actions map 1:1 to triggered rules

---

## 4. Framework Alignment

| Framework | Control | Implementation |
|---|---|---|
| **NIST SP 800-53** | AC-2 Account Management | Lifecycle tracking, dormancy detection, offboarding gap detection |
| **NIST SP 800-53** | AC-6 Least Privilege | Effective privilege calculation, cross-platform admin detection |
| **NIST SP 800-53** | IA-4 Identifier Management | Cross-platform identity correlation (97.9% accuracy) |
| **MITRE ATT&CK** | T1078 Valid Accounts | Dormant admin detection, credential age monitoring |
| **MITRE ATT&CK** | T1098 Account Manipulation | Privilege escalation via inheritance, role change monitoring |
| **MITRE ATT&CK** | T1550 Use Alternate Authentication | Token usage anomaly detection, service account abuse |
| **GDPR** | Article 5 Data Minimisation | Least privilege enforcement, over-provisioning detection |
| **GDPR** | Article 32 Security of Processing | Cross-platform identity controls, offboarding enforcement |
| **CIS Controls** | 5 Account Management | Identity lifecycle, access review automation |
| **CIS Controls** | 6 Access Control Management | Privilege normalization, effective access calculation |

---

## 5. File Structure

```
identity_governance/
├── csv_files/                      # Input data
│   ├── identities.csv              # 500 master records
│   ├── ad_accounts.csv             # AD accounts
│   ├── aws_accounts.csv            # AWS accounts
│   ├── okta_accounts.csv           # Okta accounts
│   ├── salesforce_accounts.csv     # Salesforce accounts
│   ├── group_memberships.csv       # 25 groups with hierarchy
│   └── audit_events.csv            # ~337K events
├── output_files/                   # Pipeline outputs
│   ├── identity_360.json           # Unified identity view
│   ├── phase2_match_report.csv     # Correlation audit trail
│   ├── behavioral_features.json    # Per-identity behavioral profile
│   ├── risk_flags.json             # Rule triggers per identity
│   └── risk_scores.json            # Final risk scores
├── docs/                           # Documentation
│   ├── ARCHITECTURE.md             # This document
│   ├── DATA_DICTIONARY.md          # Data field definitions
│   └── SAMPLE_RISK_REPORT.md       # Example findings
├── phase2_identity_correlation.py  # Phase 2 engine
├── pipeline.py                     # Phases 3-9 pipeline
├── dashboard.py                    # Phase 10 Streamlit dashboard
└── generate_data.py                # Data generation script
```

---

## 6. Performance Characteristics

| Metric | Value |
|---|---|
| Identity Coverage | 100% (500/500 identities assessed) |
| Correlation Accuracy | 97.9% (cross-platform identity matching) |
| Risk Detection | 6 rules across 4 platforms |
| Audit Events Processed | ~337,000 over 538 days |
| Pipeline Execution Time | ~15 seconds (end-to-end) |
| False Positive Mitigation | Severity floor + behavioral validation |

---

## 7. Extensibility

The pipeline is designed for extension:

1. **Add new platforms:** Extend `PRIVILEGE_MAP` in Phase 3 and add platform-specific CSV handling in Phase 2
2. **Add new risk rules:** Implement a new `rule_*` function in Phase 6 and add to the rule execution list
3. **Custom scoring weights:** Modify the weights in `calculate_risk_score()` in Phase 7
4. **ML enhancement:** Replace the rule-based scoring with an Isolation Forest or XGBoost model in Phase 7
5. **Real-time ingestion:** Replace CSV loading with streaming event ingestion (Kafka, Kinesis)
