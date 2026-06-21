# Identity Sprawl & Privileged Access Abuse Detection

**Track:** Identity & Access Risk Governance  
**Difficulty:** Intermediate-Advanced  
**Approach:** Option B — Cross-Platform Privilege Hygiene + Behavioral Baselines

---

## Quick Start

### Prerequisites
- Python 3.9+
- pip packages: `streamlit plotly pandas networkx`

### Run the Pipeline
```bash
# 1. Generate simulated data (already done)
# See csv_files/ for 500 identities across 4 platforms

# 2. Run Phase 2: Identity Correlation
python phase2_identity_correlation.py

# 3. Run Phases 3-9: Full Pipeline
python pipeline.py

# 4. Launch Dashboard
streamlit run dashboard.py
```

### Pipeline Outputs
All outputs are written to `output_files/`:
- `identity_360.json` — Unified identity view with risk scores, explanations, remediations
- `risk_flags.json` — Per-identity rule triggers
- `risk_scores.json` — Final risk scores and component breakdown
- `behavioral_features.json` — Per-identity behavioral profiles
- `phase2_match_report.csv` — Correlation accuracy audit trail

---

## System Capabilities

| Capability | Implementation |
|---|---|
| **Cross-Platform Identity Correlation** | Username convention matching with collision handling (97.9% accuracy) |
| **Effective Privilege Calculation** | NetworkX graph traversal for nested group inheritance |
| **Behavioral Baselining** | 11 features from 337K audit events: login frequency, IP analysis, activity spikes |
| **Risk Detection** | 6 deterministic rules with evidence payloads |
| **Risk Scoring** | Weighted formula (40/20/20/10/10) with severity floor enforcement |
| **Explainability** | Human-readable risk factors + per-component score breakdown |
| **Remediation** | Platform-specific actions: `[OFFBOARDING]`, `[PRIVILEGE REVIEW]`, `[CREDENTIALS]` |

---

## Risk Detection Rules

| Rule | Severity | Detection Logic |
|---|---|---|
| R1: Offboarding Gap | High | Terminated in HR + Active platform accounts |
| R2: Cross-Platform Admin | Critical | Admin (level 5) on 3+ platforms |
| R3: Dormant Admin | High | Admin privilege + 90+ days inactive |
| R4: Old Credentials | Medium | API token/access key age > 365 days |
| R5: Contractor Admin | High | Contractor with effective privilege 4+ |
| R6: Service Account Abuse | Critical | Service account + admin + behavioral anomalies |

---

## Dashboard Views

1. **Executive Summary** — KPI cards, top 20 risks, distribution charts
2. **Risk Intelligence** — Department heatmap, platform coverage, risk factor analysis
3. **Identity Investigation** — Search + deep dive with cross-platform access footprint
4. **Offboarding Watchlist** — Terminated-but-active identities with remediation steps
5. **Cross-Platform Privilege** — Multi-platform admin view with blast radius assessment
6. **Behavioral Anomalies** — Activity spikes, IP anomalies, after-hours patterns

---

## Framework Alignment

- **NIST SP 800-53:** AC-2, AC-6, IA-4
- **MITRE ATT&CK:** T1078, T1098, T1550
- **GDPR:** Article 5, Article 32
- **CIS Controls:** 5, 6

---

## Documentation

- `docs/ARCHITECTURE.md` — Full architecture and AI/ML approach
- `docs/DATA_DICTIONARY.md` — All data fields and group hierarchy
- `docs/SAMPLE_RISK_REPORT.md` — Top 10 riskiest identities with remediation steps

---

## File Structure

```
identity_governance/
  csv_files/            # 6 input CSVs (500 identities, ~337K events)
  output_files/         # Pipeline outputs (JSON + CSV)
  docs/                 # Architecture, data dictionary, risk report
  phase2_identity_correlation.py
  pipeline.py           # Phases 3-9
  dashboard.py          # Streamlit dashboard
  README.md
```
