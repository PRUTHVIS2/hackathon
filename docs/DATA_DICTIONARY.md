# Data Dictionary

## Identity Sprawl & Privileged Access Abuse Detection System

---

## 1. identities.csv

Master identity records for all persons and service accounts in the organization.

| Field | Type | Description | Example |
|---|---|---|---|
| `identity_id` | String | Unique identifier | `EMP0045`, `SVC003`, `CON012` |
| `full_name` | String | Display name | `Christopher Brown`, `svc_engineering_003` |
| `department` | String | Organizational unit | `IT`, `Engineering`, `Security` |
| `employment_type` | Enum | Account classification | `Employee`, `Contractor`, `ServiceAccount` |
| `employment_status` | Enum | Current HR status | `Active`, `Terminated` |
| `hire_date` | Date | Employment start date | `2022-03-15` |
| `termination_date` | Date | Employment end date (empty if active) | `2024-01-20` |
| `manager_id` | String | Supervisor's identity_id | `EMP0010` |
| `email` | String | Primary email address | `christopher.brown@company.com` |

---

## 2. ad_accounts.csv

Active Directory account records.

| Field | Type | Description | Example |
|---|---|---|---|
| `identity_id` | String | FK to identities.csv | `EMP0045` |
| `ad_username` | String | AD sAMAccountName | `christopher.brown` |
| `privilege_level` | Enum | Direct AD privilege | `StandardUser`, `PowerUser`, `ServerAdmin`, `DomainAdmin` |
| `group_memberships` | String | Semicolon-separated AD groups | `Developers;IT Support` |
| `account_status` | Enum | AD account state | `Active`, `Disabled` |
| `last_login_days` | Integer | Days since last AD login | `45` |
| `created_date` | Date | Account creation date | `2022-03-15` |
| `api_token_age_days` | Integer | Age of associated API token | `120` |

---

## 3. aws_accounts.csv

AWS IAM account records.

| Field | Type | Description | Example |
|---|---|---|---|
| `identity_id` | String | FK to identities.csv | `EMP0045` |
| `aws_username` | String | IAM user name | `cbrown` |
| `privilege_level` | Enum | IAM policy level | `ReadOnly`, `PowerUser`, `Administrator` |
| `group_memberships` | String | Semicolon-separated IAM groups | `AWS-DevOps` |
| `account_status` | Enum | IAM account state | `Active`, `Disabled` |
| `last_login_days` | Integer | Days since last AWS Console login | `12` |
| `created_date` | Date | Account creation date | `2022-03-15` |
| `access_key_age_days` | Integer | Age of IAM access key | `45` |

---

## 4. okta_accounts.csv

Okta identity records.

| Field | Type | Description | Example |
|---|---|---|---|
| `identity_id` | String | FK to identities.csv | `EMP0045` |
| `okta_login` | String | Okta login/email | `christopher.brown@company.com` |
| `privilege_level` | Enum | Okta admin level | `User`, `SuperAdmin` |
| `assigned_groups` | String | Semicolon-separated Okta groups | `Okta_Users` |
| `account_status` | Enum | Okta account state | `Active`, `Disabled` |
| `last_login_days` | Integer | Days since last Okta login | `5` |
| `created_date` | Date | Account creation date | `2022-03-15` |
| `mfa_status` | Enum | MFA enrollment state | `Enrolled`, `NotEnrolled` |

---

## 5. salesforce_accounts.csv

Salesforce account records.

| Field | Type | Description | Example |
|---|---|---|---|
| `identity_id` | String | FK to identities.csv | `EMP0045` |
| `sf_username` | String | Salesforce username | `christopher_brown_sf` |
| `privilege_level` | Enum | Salesforce profile level | `Standard`, `SystemAdmin` |
| `assigned_groups` | String | Semicolon-separated permission sets | `SF_Users` |
| `account_status` | Enum | Salesforce user state | `Active`, `Disabled` |
| `last_login_days` | Integer | Days since last Salesforce login | `8` |
| `created_date` | Date | Account creation date | `2022-03-15` |
| `api_token_age_days` | Integer | Age of connected app OAuth token | `200` |

---

## 6. group_memberships.csv

Group hierarchy definitions for effective privilege inheritance.

| Field | Type | Description | Example |
|---|---|---|---|
| `group_id` | String | Unique group identifier | `ADG001` |
| `group_name` | String | Display name | `Domain Admins` |
| `platform` | Enum | Source platform | `ad`, `aws`, `okta`, `salesforce` |
| `parent_group_id` | String | Parent group FK (empty if root) | `ADG003` |
| `grants_privilege_level` | String | Privilege granted by membership | `DomainAdmin` |

### Group Hierarchy Structure

```
Domain Admins (AD, level 5)
  └── Cloud Admins (AD, level 5)

Enterprise Admins (AD, level 5)

Server Admins (AD, level 4)
  ├── Security Team (AD, level 4)
  └── Database Admins (AD, level 4)

IT Support (AD, level 2)
  └── Help Desk (AD, level 2)

AWS-Admins (AWS, level 5)
  └── AWS-Security (AWS, level 5)

AWS-DevOps (AWS, level 3)
  └── AWS-DataTeam (AWS, level 3)

Okta_Admins (Okta, level 5)
  ├── Okta_AppAdmins (Okta, level 5)
  └── Okta_SuperAdmins (Okta, level 5)
```

---

## 7. audit_events.csv

Security event log spanning 538 days.

| Field | Type | Description | Example |
|---|---|---|---|
| `event_id` | String | Unique event identifier | `EVT0001234` |
| `timestamp` | DateTime | Event occurrence time | `2023-06-15 14:30:22` |
| `identity_id` | String | FK to identities.csv | `EMP0045` |
| `platform` | Enum | System generating the event | `ad`, `aws`, `okta`, `salesforce` |
| `event_type` | Enum | Category of event | `Login`, `AdminAction`, `RoleChange`, `TokenUsage`, `ResourceAccess`, `Logout` |
| `action` | String | Specific action taken | `LoginSuccess`, `UserCreated`, `RoleGranted` |
| `resource` | String | Target resource | `s3_bucket`, `user_account` |
| `ip_address` | String | Source IP | `10.0.15.23` |
| `result` | Enum | Outcome | `Success`, `Failure` |

---

## 8. identity_360.json (Output)

Unified identity view produced by Phase 2 and enriched by Phases 3-9.

| Field Path | Type | Description |
|---|---|---|
| `identity` | Object | Full record from identities.csv |
| `accounts.{platform}` | Object | Platform account with all CSV fields |
| `accounts.{platform}.normalized_privilege` | Integer | 1-5 normalized score |
| `accounts.{platform}.effective_privilege` | Integer | Max(direct, inherited) |
| `accounts.{platform}.inheritance_path` | Array | Groups walked for inheritance |
| `behavioral` | Object | Phase 5 behavioral features |
| `risk.score` | Float | Final 0-100 risk score |
| `risk.level` | Enum | Critical/High/Medium/Low |
| `risk.components` | Object | Per-component score breakdown |
| `explainability` | Array | Human-readable risk explanations |
| `remediations` | Array | Platform-specific remediation actions |

---

## Data Quality Notes

- **~4.8% name collision rate** for exact full name duplicates (realistic residual)
- **Platform coverage varies by department:** IT/Eng/Security on all 4 platforms; HR/Ops on fewer
- **All 6 risk scenarios** are present with healthy counts (10-55 each)
- **Group inheritance** creates hidden effective privilege for ~12% of identities
