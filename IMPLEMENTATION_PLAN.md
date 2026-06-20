# Identity Sprawl & Privileged Access Abuse Detection — Implementation Plan

**Track:** Identity & Access Risk Governance
**Approach:** Option B — Cross-Platform Privilege Hygiene + Behavioral Baselines
**Core question the demo must answer:** *Which identities in the organization are the most dangerous right now, why are they dangerous, and what should be done about them?*

---

## 0. Status at a glance

| Phase | Status | Notes |
|---|---|---|
| 1. Data Layer | ✅ Done | 500 identities, 5 platform/event files, validated |
| 2. Identity Correlation Engine | ✅ Done | 96.9% match accuracy, documented failure modes |
| 3. Privilege Normalization | ⬜ Not started | |
| 4. Effective Privilege Calculation | ⬜ Not started | Needs a group/role mapping file (gap — see §4) |
| 5. Behavioral Analysis | ⬜ Not started | |
| 6. Risk Detection Engine | ⬜ Not started | Rules validated against data in Phase 1 |
| 7. Risk Scoring Engine | ⬜ Not started | |
| 8. Explainability Engine | ⬜ Not started | |
| 9. Remediation Engine | ⬜ Not started | |
| 10. Dashboard | ⬜ Not started | |
| 11. AI Enhancement | ⬜ Not started | |

**Known gap to resolve before Phase 4:** the brief calls for a *group/role mappings* file (100–200 rows of nested group memberships) so effective privilege can be computed via inheritance (`John → Security Team → Cloud Admins → AWS Administrator`). The current 6 CSVs don't have this — `group_memberships`/`assigned_groups` are flat strings, not a traversable hierarchy. Decide and generate this **before** starting Phase 4 (see §4.1).

---

## 1. Files produced so far

```
/identities.csv              500 rows — master identity record
/ad_accounts.csv             466 rows — AD accounts
/aws_accounts.csv            270 rows — AWS accounts
/okta_accounts.csv           420 rows — Okta accounts
/salesforce_accounts.csv     338 rows — Salesforce accounts
/audit_events.csv          ~39,700 rows — event log, 538-day span
/identity_360.json            500 entries — Phase 2 output (unified identity view)
/phase2_match_report.csv     2,000 rows — Phase 2 audit trail (every match decision + confidence)
/validate_identity_data.ipynb  — reusable validation notebook, rerun after any data regeneration
```

**Known, accepted data characteristics** (don't re-litigate these — they're intentional):
- ~4.8% of human identities share an exact full name with another person (realistic residual collision, not a bug).
- Service accounts use a `svc_<dept>_<number>` naming convention; contractors get a `c-`/`c_` username prefix.
- Platform coverage varies by department (IT/Eng/Security on all 4 platforms; HR/Ops on fewer) — this is what gives `platform_spread` real variance as a risk feature.
- All 6 target risk scenarios (offboarding gap, cross-platform admin, dormant admin, old credentials, contractor admin, service account abuse) are present with healthy counts (10–55 identities each).

---

## 2. Architecture overview

```
┌─────────────────────────────────────────────────────────────────┐
│  Phase 1: Data Layer (CSVs)                                     │
└───────────────────────────┬───────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 2: Identity Correlation Engine  →  identity_360.json     │
└───────────────────────────┬───────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 3: Privilege Normalization      →  normalized_privileges │
│  Phase 4: Effective Privilege Calc.    →  effective_access      │
└───────────────────────────┬───────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 5: Behavioral Analysis          →  behavioral_features   │
└───────────────────────────┬───────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 6: Risk Detection Engine (rules) → risk_flags             │
│  Phase 7: Risk Scoring Engine           → risk_scores.json      │
└───────────────────────────┬───────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 8: Explainability Engine        →  explained_findings    │
│  Phase 9: Remediation Engine           →  remediation_actions   │
└───────────────────────────┬───────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 10: Dashboard (Streamlit/Flask)                           │
│  Phase 11: AI Enhancement (LLM narrative layer, optional)        │
└─────────────────────────────────────────────────────────────────┘
```

**Recommended stack** (per the brief's Option B suggestion, and consistent with what's been built so far):
- Python, Pandas, NumPy
- SQLite (optional — only if you want queryable persistence between phases instead of passing JSON/CSV between notebooks/scripts)
- Plotly or Streamlit's native charts for the dashboard
- An LLM API call (Anthropic or OpenAI) for Phase 11 only — keep it at the very end, narrative-only, not in the critical path

---

## 3. Phase 3 — Privilege Normalization

**Goal:** map every platform-specific privilege label to one common 1–5 scale so cross-platform comparison is possible.

**Input:** `ad_accounts.csv`, `aws_accounts.csv`, `okta_accounts.csv`, `salesforce_accounts.csv` (privilege_level columns, vocabulary already extracted during validation).

**Build a normalization table** (hardcode as a Python dict or a small CSV — either is fine, a dict is simpler for 500 rows):

| Platform | Raw value | Normalized score | Normalized label |
|---|---|---|---|
| AD | StandardUser | 1 | ReadOnly/User |
| AD | PowerUser | 3 | PowerUser |
| AD | ServerAdmin | 4 | Manager-tier |
| AD | DomainAdmin | 5 | Critical Admin |
| AWS | ReadOnly | 1 | ReadOnly/User |
| AWS | PowerUser | 3 | PowerUser |
| AWS | Administrator | 5 | Critical Admin |
| Okta | User | 1 | ReadOnly/User |
| Okta | SuperAdmin | 5 | Critical Admin |
| Salesforce | Standard | 1 | ReadOnly/User |
| Salesforce | SystemAdmin | 5 | Critical Admin |

**Implementation steps:**
1. Write `normalize_privilege(platform, raw_value) -> int` as a pure lookup function (raise/flag on unmapped values — don't silently default to a guess).
2. Apply it across all four platform files, producing one column `normalized_score` per row.
3. **Validate coverage**: every raw value in every platform file must have a mapping entry. Run this as an assertion, not a visual check — fail loudly if a new privilege value appears after a data regeneration.
4. Output: extend `identity_360.json` (or a new `normalized_privileges.json`) with each identity's normalized score per platform.

**Deliverable:** `phase3_normalization.ipynb` + `normalized_privileges.json`

**Acceptance check:** every row in every platform file has a non-null `normalized_score`; spot-check 5 identities by hand against the table above.

---

## 4. Phase 4 — Effective Privilege Calculation

**Goal:** compute `effective_privilege_score` per identity = direct access + inherited access (via nested group membership).

### 4.1 — Resolve the group-mapping data gap first

The original brief's "Sample Data Provided" section explicitly lists a **group/role mappings** file (100–200 rows, nested group memberships and inherited permissions) as a separate input from the platform account files. You don't have this yet. Decide one of:

- **(a) Generate it now.** Prompt Gemini (same pattern as before) for a `group_memberships.csv` with columns like `group_id, group_name, platform, parent_group_id, grants_privilege_level`, then assign identities to leaf groups via their existing `group_memberships`/`assigned_groups` string columns (split on `;`). This is the most faithful to the brief and gives Phase 4 a real inheritance chain to traverse (`John → Security Team → Cloud Admins → AWS Administrator`).
- **(b) Approximate without it.** Treat each identity's *direct* platform privilege (from Phase 3) as their effective privilege, and use `manager_id` chains purely for Rule-level context (e.g. "reports to an admin") rather than true privilege inheritance. Faster, but weaker — Phase 4 becomes "Phase 3 renamed" with no real inheritance logic, which undersells the project relative to the brief.

**Recommendation:** do (a). You already have a working Gemini relationship for data generation, and "effective privilege via inheritance" is one of the two headline technical asks in the brief (the other being cross-platform correlation, which you've already built). Skipping it leaves a visible gap in any review against the original spec.

### 4.2 — Build the inheritance walk

1. Model groups as a directed graph: `group -> parent_group` edges, terminating at a root (no cycles — **explicitly check for this**, since you already hit a manager_id cycle bug once in Phase 1; the same class of bug can recur here).
2. For each identity, find direct group memberships (per platform), then walk up the parent chain, collecting every privilege grant attached to any ancestor group.
3. `effective_privilege_score = max(direct_score, max(inherited_scores))` — take the highest privilege reachable, not a sum (a Domain Admin who's also a member of a ReadOnly group is still a Domain Admin).
4. Store both the direct and effective score per identity/platform, so Phase 8 can later explain *why* (e.g. "inherited AWS Administrator via Cloud Admins group, not granted directly").

**Deliverable:** `phase4_effective_privilege.ipynb` + extends `identity_360.json` with `effective_privilege_score` per platform and an `inheritance_path` field (list of groups walked) for explainability later.

**Acceptance check:** no cycles in the group graph (reuse the cycle-detection pattern from the Phase 1 `manager_id` check); spot-check that at least a few identities show `effective_score > direct_score` (otherwise inheritance isn't adding anything, and Phase 4 has no story to tell).

---

## 5. Phase 5 — Behavioral Analysis

**Goal:** turn `audit_events.csv` into per-identity behavioral features.

**Input:** `audit_events.csv` (already validated — confirms dormancy alignment, admin-action spikes, and anomalous-IP patterns are genuinely present).

**Features to compute per identity:**

| Feature | Computation |
|---|---|
| `login_frequency_per_week` | count of `Login` events / (date range in weeks) |
| `platform_count` | distinct platforms appearing in that identity's events (cross-check against Phase 2's platform list — should usually match, flag if not) |
| `last_login_days` | `(NOW - max(timestamp)).days`, recomputed from events rather than trusted blindly from the platform CSVs, since this is the "real" source of truth once events exist |
| `admin_actions_30d` / `admin_actions_total` | count of `AdminAction`/`RoleChange` events, both recent and lifetime |
| `token_usage_count` | count of `TokenUsage` events (relevant for service accounts especially) |
| `unique_ip_count` | distinct `ip_address` values |
| `dominant_ip_ratio` | (count of most-frequent IP) / (total events) — low values signal IP inconsistency |
| `activity_spike_flag` | boolean: 3+ `AdminAction` events within any 5-day window (reuse the exact logic already written and validated in the Phase 1 notebook's audit-scenario checks) |
| `anomalous_ip_flag` | boolean: dominant IP > 70% of events AND at least one IP < 10% of events (reuse from the same notebook) |

**Implementation note:** the activity-spike and anomalous-IP detection logic already exists, tested, in `validate_identity_data.ipynb` (Section 10a). Don't rewrite it — extract those two functions into a shared module (e.g. `behavioral_utils.py`) so Phase 5 and the original validation notebook both import from one place instead of drifting out of sync.

**Deliverable:** `phase5_behavioral_features.ipynb` + `behavioral_features.json` (keyed by identity_id).

**Acceptance check:** every identity with at least one audit event has a complete feature row (no partial nulls from a groupby edge case); spot check the 13 known activity-spike identities and 10 known anomalous-IP identities from Phase 1 validation still flag correctly here.

---

## 6. Phase 6 — Risk Detection Engine

**Goal:** implement the 6 rules as discrete, named functions — not one big scoring blob — so each rule's output is independently inspectable (this matters a lot for Phase 8/9 later).

| Rule | Logic | Severity |
|---|---|---|
| 1. Offboarding Gap | `employment_status == 'Terminated'` AND any platform `account_status == 'Active'` | High |
| 2. Cross-Platform Admin | `effective_privilege_score == 5` (Critical) on 3+ platforms | Critical |
| 3. Dormant Admin | `effective_privilege_score == 5` on any platform AND `last_login_days >= 90` on that platform | High |
| 4. Old Credentials | `access_key_age_days > 365` (AWS) OR `api_token_age_days > 365` (Salesforce) | Medium |
| 5. Contractor Admin | `employment_type == 'Contractor'` AND `effective_privilege_score >= 4` on any platform | High |
| 6. Service Account Abuse | `employment_type == 'ServiceAccount'` AND `effective_privilege_score == 5` on any platform | Critical |

**Implementation pattern:**
```python
def rule_offboarding_gap(identity_record) -> RuleResult:
    # returns: triggered (bool), severity (str), evidence (dict) -- not just True/False
    ...
```
Each rule returns **evidence**, not just a boolean — e.g. Rule 1 should return *which* platform(s) are still active and since when. This evidence is exactly what Phase 8 needs; don't make Phase 8 recompute it.

**Deliverable:** `phase6_risk_rules.py` (a real module, not a notebook — these functions get reused in Phase 7/8/9) + `risk_flags.json`.

**Acceptance check:** rerun against the counts already validated in Phase 1 (Rule 1: 15, Rule 2: 55, Rule 3: 35, Rule 4: 23, Rule 5: 10, Rule 6: 15) — if your Phase 6 implementation produces meaningfully different counts, something in Phase 3/4/5 upstream introduced a discrepancy and needs tracing before moving on.

---

## 7. Phase 7 — Risk Scoring Engine

**Goal:** combine rule outputs and behavioral features into one final 0–100 score per identity.

**Formula (from the brief, adjust weights only if you have a justification):**
```
risk_score = (
    privilege_score * 0.4
    + dormancy_score * 0.2
    + platform_spread_score * 0.2
    + credential_risk_score * 0.1
    + offboarding_risk_score * 0.1
)
```

**Component scoring (each normalized to 0–100 before weighting):**
- `privilege_score`: max effective privilege across platforms, scaled (5→100, 1→20)
- `dormancy_score`: scaled `last_login_days` (cap at e.g. 180 days = 100)
- `platform_spread_score`: `platform_count / 4 * 100`
- `credential_risk_score`: scaled token/key age (cap at 730 days = 100)
- `offboarding_risk_score`: 100 if Rule 1 triggered, else 0

**Risk levels:** 0–30 Low, 31–60 Medium, 61–80 High, 81–100 Critical (per brief).

**Important:** don't let the weighted formula silently override the discrete rule severities from Phase 6. A "Critical" rule trigger (e.g. Service Account Abuse) should produce a Critical *or* High score even if the weighted average alone would land it in Medium — add a floor: `final_score = max(weighted_score, rule_severity_floor)`. Otherwise a genuinely critical case in Rule 6 could get diluted into a misleadingly low number by averaging.

**Deliverable:** `phase7_risk_scoring.ipynb` + `risk_scores.json` (identity_id → score, level, component breakdown).

**Acceptance check:** every identity flagged by Rule 2 or Rule 6 (the two "Critical" rules) should land in High or Critical overall, never Low/Medium — explicitly assert this rather than eyeballing it.

---

## 8. Phase 8 — Explainability Engine

**Goal:** turn `risk_score = 85` into a short, evidence-backed list of *why*.

**This is where Phase 6's evidence payloads and Phase 4's `inheritance_path` field pay off** — don't recompute anything here, just format what's already been collected.

```
EMP0045 — Risk Score: 85 (Critical)

Reasons:
• AWS Administrator (direct grant)
• Okta Super Admin (inherited via "Cloud Admins" group)
• Salesforce System Admin (direct grant)
• Inactive 120 days on AWS
• API token 450 days old (Salesforce)
```

**Implementation:** one function `explain(identity_id) -> list[str]`, pulling from the Phase 6 rule evidence + Phase 4 inheritance paths + Phase 5 behavioral features, in that priority order (privilege facts first, then dormancy, then credentials — matches how a human analyst would triage).

**Deliverable:** `phase8_explainability.py` + a sample output file with explanations for the top 20 riskiest identities (you'll want this file specifically for the brief's required "Sample risk report with 5–10 detected risky identities" deliverable).

---

## 9. Phase 9 — Remediation Engine

**Goal:** map each triggered rule to a concrete, platform-specific action — not generic advice.

| Rule triggered | Remediation template |
|---|---|
| Offboarding Gap | "Disable {platform} account `{username}` immediately — terminated {termination_date}, still Active" |
| Cross-Platform Admin | "Review necessity of admin access on {platform_list}; consider reducing to least-privilege role on at least one platform" |
| Dormant Admin | "Disable or re-certify {platform} admin access for `{username}` — inactive {last_login_days} days" |
| Old Credentials | "Rotate {credential_type} for `{username}` — {age_days} days old" |
| Contractor Admin | "Escalate for manager review: contractor `{username}` holds {privilege_level} on {platform}" |
| Service Account Abuse | "Audit owner/justification for service account `{username}`'s {platform} admin grant; rotate credentials and scope down if unjustified" |

**Implementation:** one function per rule (mirrors Phase 6's structure), templated string output, returns a list since one identity can trigger multiple rules and should get multiple remediation lines.

**Deliverable:** `phase9_remediation.py`, feeding directly into both Phase 8's report and the Phase 10 dashboard.

---

## 10. Phase 10 — Dashboard

**Recommendation: Streamlit**, not Flask — far less boilerplate for a data-heavy internal tool like this, and it's what most similar hackathon submissions use for fast iteration.

**Pages/sections to build, in priority order:**
1. **Executive summary** — total identities, count by risk level, count of dormant admins, count of offboarding gaps (single row of metric cards).
2. **Top risky identities** — sortable table, top 20 by score, click-through to detail view.
3. **Identity detail / search** — search by `identity_id` or name → show all accounts, effective privileges, risk score breakdown, explanation (Phase 8 output), remediation actions (Phase 9 output). This is the single most important screen for a live demo.
4. **Risk heatmap** — department × risk level (you already have department-level platform-coverage variance built into the data, so this should show real differentiation, not a flat heatmap).
5. **Offboarding dashboard** — dedicated view filtering to Rule 1 hits only.

**Deliverable:** `dashboard.py` (Streamlit app), runnable via `streamlit run dashboard.py`.

**Don't build:** a generic "all identities" paginated table with no filtering — it won't demo well and isn't asked for. Prioritize the search/detail view and the top-20 list; those carry the demo.

---

## 11. Phase 11 — AI Enhancement (optional, do last)

**Goal:** one LLM call per flagged identity, turning the structured findings into a short prose paragraph for the report/dashboard.

**Keep this strictly additive and isolated:**
- Input: the exact JSON shape your Phase 8 output already produces (`{"identity": ..., "risk_score": ..., "findings": [...]}`)
- Output: 2–4 sentence narrative, nothing else
- **Do not** let the LLM compute scores, decide severities, or alter remediation actions — it only narrates what Phases 6–9 already decided deterministically. This keeps your scoring auditable (a requirement implied by the brief's "Risk Explainability" success criterion) and avoids the LLM hallucinating a justification that doesn't match the actual evidence.
- Run this only on the final top-N identities for the report, not all 500 — no need to burn API calls on Low-risk identities nobody will read about.

**Deliverable:** `phase11_ai_narrative.py`, called only at report-generation time.

---

## 12. Suggested build order & rough effort

Given the brief's Option B estimate of 25–35 hours total, and that Phases 1–2 are done:

| Phase | Est. hours | Depends on |
|---|---|---|
| 4.1 Group mapping data generation | 1–2 | — |
| 3. Privilege Normalization | 2–3 | Phase 1 |
| 4. Effective Privilege Calc | 4–5 | Phase 3, 4.1 |
| 5. Behavioral Analysis | 3–4 | Phase 1 (audit_events) |
| 6. Risk Detection Engine | 3–4 | Phase 3, 4, 5 |
| 7. Risk Scoring Engine | 2 | Phase 6 |
| 8. Explainability | 2 | Phase 6, 7 |
| 9. Remediation | 1–2 | Phase 6 |
| 10. Dashboard | 6–8 | Phase 7, 8, 9 |
| 11. AI Enhancement | 2 | Phase 8 |
| Docs (architecture write-up, data dictionary) | 2 | All |

**Total remaining: ~28–37 hours.**

---

## 13. Final deliverables checklist (per the brief)

- [ ] Working prototype with simulated multi-platform identity data + data dictionary
- [x] Cross-platform identity resolver (Phase 2 — `identity_360.json`)
- [ ] Effective privilege calculator with nested group inheritance (Phase 4 — **blocked on §4.1**)
- [ ] Risk scoring engine with explainable per-identity breakdown (Phases 6–8)
- [ ] Dashboard: risk list, cross-platform privilege view, offboarding gaps, incident detail (Phase 10)
- [ ] Architecture documentation + AI/ML approach explanation
- [ ] Sample risk report, 5–10 risky identities, platform-specific remediation steps (Phase 8/9 output)

---

## 14. Open decisions for you to make before continuing

1. **§4.1** — generate the group-mappings file, or approximate without true inheritance? (Recommended: generate it.)
2. **AWS matcher precision** (carried over from Phase 2) — worth hardening the `firstinitial+lastname` collision handling before it propagates into Phase 3+, or accept the documented 96.9% and move on?
3. **Dashboard framework** — confirmed Streamlit, or do you have a reason to prefer Flask (e.g. a requirement to deploy somewhere Streamlit doesn't fit)?
