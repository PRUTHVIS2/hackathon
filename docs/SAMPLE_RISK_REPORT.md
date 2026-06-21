# Sample Risk Report

**Generated:** 2024-06-21

**Scope:** Top 10 riskiest identities from 500-identity hybrid enterprise dataset

---

## #1: Scarlett Anderson (CON001)

**Department:** IT | **Type:** Contractor | **Status:** Terminated

### Risk Score: 100 (Critical)

**Score Components:**
- Privilege (40%): 100
- Dormancy (20%): 100
- Platform Spread (20%): 100
- Credential Age (10%): 59
- Offboarding (10%): 0
- Behavioral Boost: +15

### Risk Factors Detected

- OKTA: SuperAdmin (effective level 5, inherited via Okta_AppAdmins (direct: SuperAdmin))
- SALESFORCE: SystemAdmin (effective level 5, inherited via SF_Admins (direct: SystemAdmin))
- Old Credentials: AWS access key 431 days old
- Contractor Admin: OKTA effective privilege level 5; SALESFORCE effective privilege level 5
- Behavioral: IP usage anomaly (52 unique IPs, dominant ratio 0.06)

### Cross-Platform Access Footprint

| Platform | Status | Last Login | Raw Role | Effective Privilege | Inheritance |
|----------|--------|------------|----------|-------------------|-------------|
| AD | Disabled | 284 days | PowerUser | 2 | Direct |
| AWS | Disabled | 270 days | PowerUser | 3 | Direct |
| OKTA | Disabled | 330 days | SuperAdmin | 5 | Okta_AppAdmins (direct: SuperAdmin) |
| SALESFORCE | Disabled | 356 days | SystemAdmin | 5 | SF_Admins (direct: SystemAdmin) |

### Behavioral Profile

- Days Since Login: N/A
- Platforms Active (30d): N/A
- Admin Actions (30d): 0
- Unique IPs: 52
- Activity Spike: No
- IP Anomaly: Yes
- After-Hours Ratio: 9%

### Recommended Remediation Actions

1. [CREDENTIALS] Rotate access key for AWS 'c_sanderson' — 431 days old
1. [CONTRACTOR] Escalate for manager review: contractor 'Scarlett Anderson' holds elevated privileges. Verify scope and document justification.
1. [BEHAVIORAL] Investigate anomalous IP pattern — verify with identity owner or consider credential rotation

---

## #2: Jonathan Cox (CON004)

**Department:** IT | **Type:** Contractor | **Status:** Terminated

### Risk Score: 100 (Critical)

**Score Components:**
- Privilege (40%): 100
- Dormancy (20%): 92
- Platform Spread (20%): 100
- Credential Age (10%): 10
- Offboarding (10%): 0
- Behavioral Boost: +25

### Risk Factors Detected

- AWS: Administrator (effective level 5, inherited via AWS-Security (direct: Administrator))
- OKTA: SuperAdmin (effective level 5, inherited via Okta_AppAdmins (direct: SuperAdmin))
- SALESFORCE: SystemAdmin (effective level 5, inherited via SF_Admins (direct: SystemAdmin))
- Cross-Platform Admin: Critical admin on 3 platforms: AWS, OKTA, SALESFORCE — blast radius review required
- Contractor Admin: AWS effective privilege level 5; OKTA effective privilege level 5; SALESFORCE effective privilege level 5
- Behavioral: Admin action spike detected (0 actions in 30 days)
- Behavioral: IP usage anomaly (70 unique IPs, dominant ratio 0.04)

### Cross-Platform Access Footprint

| Platform | Status | Last Login | Raw Role | Effective Privilege | Inheritance |
|----------|--------|------------|----------|-------------------|-------------|
| AD | Disabled | 209 days | PowerUser | 2 | Direct |
| AWS | Disabled | 310 days | Administrator | 5 | AWS-Security (direct: Administrator) |
| OKTA | Disabled | 352 days | SuperAdmin | 5 | Okta_AppAdmins (direct: SuperAdmin) |
| SALESFORCE | Disabled | 166 days | SystemAdmin | 5 | SF_Admins (direct: SystemAdmin) |

### Behavioral Profile

- Days Since Login: N/A
- Platforms Active (30d): N/A
- Admin Actions (30d): 0
- Unique IPs: 70
- Activity Spike: Yes
- IP Anomaly: Yes
- After-Hours Ratio: 17%

### Recommended Remediation Actions

1. [PRIVILEGE REVIEW] Review admin necessity on AWS, OKTA, SALESFORCE. Consider reducing to least-privilege on at least one platform. Document business justification.
1. [CONTRACTOR] Escalate for manager review: contractor 'Jonathan Cox' holds elevated privileges. Verify scope and document justification.
1. [BEHAVIORAL] Investigate anomalous IP pattern — verify with identity owner or consider credential rotation
1. [BEHAVIORAL] Review recent admin action spike — confirm authorized activity or investigate potential compromise

---

## #3: Kimberly Scott (CON007)

**Department:** Security | **Type:** Contractor | **Status:** Terminated

### Risk Score: 100 (Critical)

**Score Components:**
- Privilege (40%): 100
- Dormancy (20%): 97
- Platform Spread (20%): 100
- Credential Age (10%): 18
- Offboarding (10%): 0
- Behavioral Boost: +25

### Risk Factors Detected

- SALESFORCE: SystemAdmin (effective level 5, inherited via SF_Admins (direct: SystemAdmin))
- Contractor Admin: SALESFORCE effective privilege level 5
- Behavioral: Admin action spike detected (0 actions in 30 days)
- Behavioral: IP usage anomaly (59 unique IPs, dominant ratio 0.04)

### Cross-Platform Access Footprint

| Platform | Status | Last Login | Raw Role | Effective Privilege | Inheritance |
|----------|--------|------------|----------|-------------------|-------------|
| AD | Disabled | 174 days | StandardUser | 1 | Direct |
| AWS | Disabled | 361 days | PowerUser | 3 | Direct |
| OKTA | Disabled | 223 days | User | 1 | Direct |
| SALESFORCE | Disabled | 223 days | SystemAdmin | 5 | SF_Admins (direct: SystemAdmin) |

### Behavioral Profile

- Days Since Login: N/A
- Platforms Active (30d): N/A
- Admin Actions (30d): 0
- Unique IPs: 59
- Activity Spike: Yes
- IP Anomaly: Yes
- After-Hours Ratio: 19%

### Recommended Remediation Actions

1. [CONTRACTOR] Escalate for manager review: contractor 'Kimberly Scott' holds elevated privileges. Verify scope and document justification.
1. [BEHAVIORAL] Investigate anomalous IP pattern — verify with identity owner or consider credential rotation
1. [BEHAVIORAL] Review recent admin action spike — confirm authorized activity or investigate potential compromise

---

## #4: Zoey Lee (CON035)

**Department:** IT | **Type:** Contractor | **Status:** Active

### Risk Score: 100 (Critical)

**Score Components:**
- Privilege (40%): 100
- Dormancy (20%): 14
- Platform Spread (20%): 100
- Credential Age (10%): 16
- Offboarding (10%): 0
- Behavioral Boost: +25

### Risk Factors Detected

- AWS: Administrator (effective level 5, inherited via AWS-Security (direct: Administrator))
- OKTA: SuperAdmin (effective level 5, inherited via Okta_AppAdmins (direct: SuperAdmin))
- SALESFORCE: SystemAdmin (effective level 5, inherited via SF_Admins (direct: SystemAdmin))
- Cross-Platform Admin: Critical admin on 3 platforms: AWS, OKTA, SALESFORCE — blast radius review required
- Contractor Admin: AWS effective privilege level 5; OKTA effective privilege level 5; SALESFORCE effective privilege level 5
- Behavioral: Admin action spike detected (2 actions in 30 days)
- Behavioral: IP usage anomaly (85 unique IPs, dominant ratio 0.03)

### Cross-Platform Access Footprint

| Platform | Status | Last Login | Raw Role | Effective Privilege | Inheritance |
|----------|--------|------------|----------|-------------------|-------------|
| AD | Active | 65 days | PowerUser | 2 | Direct |
| AWS | Active | 61 days | Administrator | 5 | AWS-Security (direct: Administrator) |
| OKTA | Active | 26 days | SuperAdmin | 5 | Okta_AppAdmins (direct: SuperAdmin) |
| SALESFORCE | Active | 71 days | SystemAdmin | 5 | SF_Admins (direct: SystemAdmin) |

### Behavioral Profile

- Days Since Login: N/A
- Platforms Active (30d): N/A
- Admin Actions (30d): 2
- Unique IPs: 85
- Activity Spike: Yes
- IP Anomaly: Yes
- After-Hours Ratio: 18%

### Recommended Remediation Actions

1. [PRIVILEGE REVIEW] Review admin necessity on AWS, OKTA, SALESFORCE. Consider reducing to least-privilege on at least one platform. Document business justification.
1. [CONTRACTOR] Escalate for manager review: contractor 'Zoey Lee' holds elevated privileges. Verify scope and document justification.
1. [BEHAVIORAL] Investigate anomalous IP pattern — verify with identity owner or consider credential rotation
1. [BEHAVIORAL] Review recent admin action spike — confirm authorized activity or investigate potential compromise

---

## #5: Joseph James (EMP0001)

**Department:** Sales | **Type:** Employee | **Status:** Terminated

### Risk Score: 100 (Critical)

**Score Components:**
- Privilege (40%): 100
- Dormancy (20%): 100
- Platform Spread (20%): 50
- Credential Age (10%): 17
- Offboarding (10%): 100
- Behavioral Boost: +25

### Risk Factors Detected

- AD: DomainAdmin (effective level 5, inherited via IT Support (direct: PowerUser))
- SALESFORCE: SystemAdmin (effective level 5, direct grant)
- Offboarding Gap: Account still Active on ad, salesforce — terminated 2024-06-30
- Dormant Admin: AD admin inactive 337 days; SALESFORCE admin inactive 386 days
- Behavioral: Admin action spike detected (0 actions in 30 days)
- Behavioral: IP usage anomaly (69 unique IPs, dominant ratio 0.04)
- Dormancy: 337 days since last login on AD
- Dormancy: 386 days since last login on SALESFORCE

### Cross-Platform Access Footprint

| Platform | Status | Last Login | Raw Role | Effective Privilege | Inheritance |
|----------|--------|------------|----------|-------------------|-------------|
| AD | Active | 337 days | DomainAdmin | 5 | IT Support (direct: PowerUser) |
| SALESFORCE | Active | 386 days | SystemAdmin | 5 | Direct |

### Behavioral Profile

- Days Since Login: N/A
- Platforms Active (30d): N/A
- Admin Actions (30d): 0
- Unique IPs: 69
- Activity Spike: Yes
- IP Anomaly: Yes
- After-Hours Ratio: 19%

### Recommended Remediation Actions

1. [OFFBOARDING] Disable AD account 'joseph.james' — terminated 2024-06-30, still Active
1. [OFFBOARDING] Disable SALESFORCE account 'joseph_james_sf' — terminated 2024-06-30, still Active
1. [DORMANCY] Disable or re-certify AD admin 'joseph.james' — inactive 337 days
1. [DORMANCY] Disable or re-certify SALESFORCE admin 'joseph_james_sf' — inactive 386 days
1. [BEHAVIORAL] Investigate anomalous IP pattern — verify with identity owner or consider credential rotation
1. [BEHAVIORAL] Review recent admin action spike — confirm authorized activity or investigate potential compromise

---

## #6: Jeffrey Reyes (EMP0002)

**Department:** IT | **Type:** Employee | **Status:** Terminated

### Risk Score: 100 (Critical)

**Score Components:**
- Privilege (40%): 100
- Dormancy (20%): 100
- Platform Spread (20%): 100
- Credential Age (10%): 21
- Offboarding (10%): 100
- Behavioral Boost: +25

### Risk Factors Detected

- AD: DomainAdmin (effective level 5, inherited via Server Admins (direct: ServerAdmin))
- AWS: Administrator (effective level 5, inherited via AWS-Admins (direct: Administrator))
- OKTA: SuperAdmin (effective level 5, inherited via Okta_SuperAdmins (direct: SuperAdmin))
- SALESFORCE: SystemAdmin (effective level 5, inherited via SF_Admins (direct: SystemAdmin))
- Offboarding Gap: Account still Active on ad, aws, okta — terminated 2024-02-20
- Cross-Platform Admin: Critical admin on 4 platforms: AD, AWS, OKTA, SALESFORCE — blast radius review required
- Dormant Admin: AD admin inactive 246 days; AWS admin inactive 353 days; OKTA admin inactive 202 days
- Behavioral: Admin action spike detected (0 actions in 30 days)
- Behavioral: IP usage anomaly (62 unique IPs, dominant ratio 0.03)
- Dormancy: 246 days since last login on AD
- Dormancy: 353 days since last login on AWS
- Dormancy: 202 days since last login on OKTA

### Cross-Platform Access Footprint

| Platform | Status | Last Login | Raw Role | Effective Privilege | Inheritance |
|----------|--------|------------|----------|-------------------|-------------|
| AD | Active | 246 days | DomainAdmin | 5 | Server Admins (direct: ServerAdmin) |
| AWS | Active | 353 days | Administrator | 5 | AWS-Admins (direct: Administrator) |
| OKTA | Active | 202 days | SuperAdmin | 5 | Okta_SuperAdmins (direct: SuperAdmin) |
| SALESFORCE | Disabled | 372 days | SystemAdmin | 5 | SF_Admins (direct: SystemAdmin) |

### Behavioral Profile

- Days Since Login: N/A
- Platforms Active (30d): N/A
- Admin Actions (30d): 0
- Unique IPs: 62
- Activity Spike: Yes
- IP Anomaly: Yes
- After-Hours Ratio: 16%

### Recommended Remediation Actions

1. [OFFBOARDING] Disable AD account 'jeffrey.reyes' — terminated 2024-02-20, still Active
1. [OFFBOARDING] Disable AWS account 'jreyes' — terminated 2024-02-20, still Active
1. [OFFBOARDING] Disable OKTA account 'jeffrey.reyes@company.com' — terminated 2024-02-20, still Active
1. [PRIVILEGE REVIEW] Review admin necessity on AD, AWS, OKTA, SALESFORCE. Consider reducing to least-privilege on at least one platform. Document business justification.
1. [DORMANCY] Disable or re-certify AD admin 'jeffrey.reyes' — inactive 246 days
1. [DORMANCY] Disable or re-certify AWS admin 'jreyes' — inactive 353 days
1. [DORMANCY] Disable or re-certify OKTA admin 'jeffrey.reyes@company.com' — inactive 202 days
1. [DORMANCY] Disable or re-certify SALESFORCE admin 'jeffrey_reyes_sf' — inactive 372 days
1. [BEHAVIORAL] Investigate anomalous IP pattern — verify with identity owner or consider credential rotation
1. [BEHAVIORAL] Review recent admin action spike — confirm authorized activity or investigate potential compromise

---

## #7: Lily Baker (EMP0003)

**Department:** Engineering | **Type:** Employee | **Status:** Terminated

### Risk Score: 100 (Critical)

**Score Components:**
- Privilege (40%): 100
- Dormancy (20%): 98
- Platform Spread (20%): 100
- Credential Age (10%): 96
- Offboarding (10%): 100
- Behavioral Boost: +15

### Risk Factors Detected

- AD: DomainAdmin (effective level 5, inherited via IT Support (direct: PowerUser))
- AWS: Administrator (effective level 5, inherited via AWS-Admins (direct: Administrator))
- OKTA: SuperAdmin (effective level 5, inherited via Okta_SuperAdmins (direct: SuperAdmin))
- Offboarding Gap: Account still Active on ad, aws — terminated 2024-05-07
- Cross-Platform Admin: Critical admin on 3 platforms: AD, AWS, OKTA — blast radius review required
- Dormant Admin: AD admin inactive 177 days; AWS admin inactive 388 days
- Old Credentials: AD API token 704 days old
- Behavioral: IP usage anomaly (58 unique IPs, dominant ratio 0.04)
- Dormancy: 177 days since last login on AD
- Dormancy: 388 days since last login on AWS

### Cross-Platform Access Footprint

| Platform | Status | Last Login | Raw Role | Effective Privilege | Inheritance |
|----------|--------|------------|----------|-------------------|-------------|
| AD | Active | 177 days | DomainAdmin | 5 | IT Support (direct: PowerUser) |
| AWS | Active | 388 days | Administrator | 5 | AWS-Admins (direct: Administrator) |
| OKTA | Disabled | 380 days | SuperAdmin | 5 | Okta_SuperAdmins (direct: SuperAdmin) |
| SALESFORCE | Disabled | 239 days | Standard | 1 | Direct |

### Behavioral Profile

- Days Since Login: N/A
- Platforms Active (30d): N/A
- Admin Actions (30d): 0
- Unique IPs: 58
- Activity Spike: No
- IP Anomaly: Yes
- After-Hours Ratio: 23%

### Recommended Remediation Actions

1. [OFFBOARDING] Disable AD account 'lily.baker' — terminated 2024-05-07, still Active
1. [OFFBOARDING] Disable AWS account 'lbaker' — terminated 2024-05-07, still Active
1. [PRIVILEGE REVIEW] Review admin necessity on AD, AWS, OKTA. Consider reducing to least-privilege on at least one platform. Document business justification.
1. [DORMANCY] Disable or re-certify AD admin 'lily.baker' — inactive 177 days
1. [DORMANCY] Disable or re-certify AWS admin 'lbaker' — inactive 388 days
1. [DORMANCY] Disable or re-certify OKTA admin 'lily.baker@company.com' — inactive 380 days
1. [CREDENTIALS] Rotate API token for AD 'lily.baker' — 704 days old (exceeds 365-day policy)
1. [BEHAVIORAL] Investigate anomalous IP pattern — verify with identity owner or consider credential rotation

---

## #8: Larry Edwards (EMP0004)

**Department:** Security | **Type:** Employee | **Status:** Terminated

### Risk Score: 100 (Critical)

**Score Components:**
- Privilege (40%): 100
- Dormancy (20%): 67
- Platform Spread (20%): 100
- Credential Age (10%): 17
- Offboarding (10%): 100
- Behavioral Boost: +25

### Risk Factors Detected

- AD: DomainAdmin (effective level 5, inherited via Security Team (direct: ServerAdmin))
- AWS: Administrator (effective level 5, inherited via AWS-Admins (direct: Administrator))
- OKTA: SuperAdmin (effective level 5, inherited via Okta_SuperAdmins (direct: SuperAdmin))
- SALESFORCE: SystemAdmin (effective level 5, inherited via SF_Admins (direct: SystemAdmin))
- Offboarding Gap: Account still Active on ad — terminated 2024-08-04
- Cross-Platform Admin: Critical admin on 4 platforms: AD, AWS, OKTA, SALESFORCE — blast radius review required
- Dormant Admin: AD admin inactive 334 days
- Behavioral: Admin action spike detected (0 actions in 30 days)
- Behavioral: IP usage anomaly (66 unique IPs, dominant ratio 0.04)
- Dormancy: 334 days since last login on AD

### Cross-Platform Access Footprint

| Platform | Status | Last Login | Raw Role | Effective Privilege | Inheritance |
|----------|--------|------------|----------|-------------------|-------------|
| AD | Active | 334 days | DomainAdmin | 5 | Security Team (direct: ServerAdmin) |
| AWS | Disabled | 188 days | Administrator | 5 | AWS-Admins (direct: Administrator) |
| OKTA | Disabled | 146 days | SuperAdmin | 5 | Okta_SuperAdmins (direct: SuperAdmin) |
| SALESFORCE | Disabled | 120 days | SystemAdmin | 5 | SF_Admins (direct: SystemAdmin) |

### Behavioral Profile

- Days Since Login: N/A
- Platforms Active (30d): N/A
- Admin Actions (30d): 0
- Unique IPs: 66
- Activity Spike: Yes
- IP Anomaly: Yes
- After-Hours Ratio: 16%

### Recommended Remediation Actions

1. [OFFBOARDING] Disable AD account 'larry.edwards' — terminated 2024-08-04, still Active
1. [PRIVILEGE REVIEW] Review admin necessity on AD, AWS, OKTA, SALESFORCE. Consider reducing to least-privilege on at least one platform. Document business justification.
1. [DORMANCY] Disable or re-certify AD admin 'larry.edwards' — inactive 334 days
1. [DORMANCY] Disable or re-certify AWS admin 'ledwards' — inactive 188 days
1. [DORMANCY] Disable or re-certify OKTA admin 'larry.edwards@company.com' — inactive 146 days
1. [DORMANCY] Disable or re-certify SALESFORCE admin 'larry_edwards_sf' — inactive 120 days
1. [BEHAVIORAL] Investigate anomalous IP pattern — verify with identity owner or consider credential rotation
1. [BEHAVIORAL] Review recent admin action spike — confirm authorized activity or investigate potential compromise

---

## #9: William Wood (EMP0006)

**Department:** IT | **Type:** Employee | **Status:** Terminated

### Risk Score: 100 (Critical)

**Score Components:**
- Privilege (40%): 100
- Dormancy (20%): 72
- Platform Spread (20%): 100
- Credential Age (10%): 26
- Offboarding (10%): 100
- Behavioral Boost: +15

### Risk Factors Detected

- AD: ServerAdmin (effective level 4, inherited via Server Admins (direct: ServerAdmin))
- AWS: Administrator (effective level 5, inherited via AWS-Admins (direct: Administrator))
- OKTA: SuperAdmin (effective level 5, inherited via Okta_SuperAdmins (direct: SuperAdmin))
- SALESFORCE: SystemAdmin (effective level 5, inherited via SF_Admins (direct: SystemAdmin))
- Offboarding Gap: Account still Active on ad, aws — terminated 2024-02-17
- Cross-Platform Admin: Critical admin on 3 platforms: AWS, OKTA, SALESFORCE — blast radius review required
- Dormant Admin: AD admin inactive 144 days; AWS admin inactive 129 days
- Behavioral: IP usage anomaly (36 unique IPs, dominant ratio 0.06)
- Dormancy: 144 days since last login on AD
- Dormancy: 129 days since last login on AWS

### Cross-Platform Access Footprint

| Platform | Status | Last Login | Raw Role | Effective Privilege | Inheritance |
|----------|--------|------------|----------|-------------------|-------------|
| AD | Active | 144 days | ServerAdmin | 4 | Server Admins (direct: ServerAdmin) |
| AWS | Active | 129 days | Administrator | 5 | AWS-Admins (direct: Administrator) |
| OKTA | Disabled | 361 days | SuperAdmin | 5 | Okta_SuperAdmins (direct: SuperAdmin) |
| SALESFORCE | Disabled | 332 days | SystemAdmin | 5 | SF_Admins (direct: SystemAdmin) |

### Behavioral Profile

- Days Since Login: N/A
- Platforms Active (30d): N/A
- Admin Actions (30d): 0
- Unique IPs: 36
- Activity Spike: No
- IP Anomaly: Yes
- After-Hours Ratio: 17%

### Recommended Remediation Actions

1. [OFFBOARDING] Disable AD account 'william.wood' — terminated 2024-02-17, still Active
1. [OFFBOARDING] Disable AWS account 'wwood' — terminated 2024-02-17, still Active
1. [PRIVILEGE REVIEW] Review admin necessity on AWS, OKTA, SALESFORCE. Consider reducing to least-privilege on at least one platform. Document business justification.
1. [DORMANCY] Disable or re-certify AD admin 'william.wood' — inactive 144 days
1. [DORMANCY] Disable or re-certify AWS admin 'wwood' — inactive 129 days
1. [DORMANCY] Disable or re-certify OKTA admin 'william.wood@company.com' — inactive 361 days
1. [DORMANCY] Disable or re-certify SALESFORCE admin 'william_wood_sf' — inactive 332 days
1. [BEHAVIORAL] Investigate anomalous IP pattern — verify with identity owner or consider credential rotation

---

## #10: Patricia Howard (EMP0011)

**Department:** IT | **Type:** Employee | **Status:** Terminated

### Risk Score: 100 (Critical)

**Score Components:**
- Privilege (40%): 100
- Dormancy (20%): 74
- Platform Spread (20%): 100
- Credential Age (10%): 21
- Offboarding (10%): 100
- Behavioral Boost: +15

### Risk Factors Detected

- AD: ServerAdmin (effective level 5, inherited via Cloud Admins (direct: DomainAdmin))
- OKTA: SuperAdmin (effective level 5, inherited via Okta_SuperAdmins (direct: SuperAdmin))
- Offboarding Gap: Account still Active on ad, okta — terminated 2024-06-09
- Dormant Admin: AD admin inactive 241 days; OKTA admin inactive 149 days
- Behavioral: IP usage anomaly (55 unique IPs, dominant ratio 0.04)
- Dormancy: 241 days since last login on AD
- Dormancy: 149 days since last login on OKTA

### Cross-Platform Access Footprint

| Platform | Status | Last Login | Raw Role | Effective Privilege | Inheritance |
|----------|--------|------------|----------|-------------------|-------------|
| AD | Active | 241 days | ServerAdmin | 5 | Cloud Admins (direct: DomainAdmin) |
| AWS | Disabled | 393 days | ReadOnly | 1 | Direct |
| OKTA | Active | 149 days | SuperAdmin | 5 | Okta_SuperAdmins (direct: SuperAdmin) |
| SALESFORCE | Disabled | 134 days | Standard | 1 | Direct |

### Behavioral Profile

- Days Since Login: N/A
- Platforms Active (30d): N/A
- Admin Actions (30d): 0
- Unique IPs: 55
- Activity Spike: No
- IP Anomaly: Yes
- After-Hours Ratio: 18%

### Recommended Remediation Actions

1. [OFFBOARDING] Disable AD account 'patricia.howard' — terminated 2024-06-09, still Active
1. [OFFBOARDING] Disable OKTA account 'patricia.howard@company.com' — terminated 2024-06-09, still Active
1. [DORMANCY] Disable or re-certify AD admin 'patricia.howard' — inactive 241 days
1. [DORMANCY] Disable or re-certify OKTA admin 'patricia.howard@company.com' — inactive 149 days
1. [BEHAVIORAL] Investigate anomalous IP pattern — verify with identity owner or consider credential rotation

---

## Summary Statistics

- **Total Identities Assessed:** 500
- **Critical Risk:** 156
- **High Risk:** 82
- **Medium Risk:** 262
- **Offboarding Gaps:** 0
- **Dormant Admins:** 0
- **Cross-Platform Admins:** 0
