#!/usr/bin/env python3
"""
Identity Sprawl & Privileged Access Abuse Detection Pipeline
Implements Phases 3-9 of the Implementation Plan:
  - Phase 3: Privilege Normalization
  - Phase 4: Effective Privilege Calculation (with group inheritance)
  - Phase 5: Behavioral Analysis
  - Phase 6: Risk Detection Engine (6 rules with evidence)
  - Phase 7: Risk Scoring Engine
  - Phase 8: Explainability Engine
  - Phase 9: Remediation Engine
"""

import csv
import json
import os
from collections import defaultdict
from datetime import datetime, timedelta
import networkx as nx

# ============================================================
# CONFIGURATION
# ============================================================
CSV_DIR = os.path.join(os.path.dirname(__file__), 'csv_files')
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'output_files')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ============================================================
# PHASE 3: PRIVILEGE NORMALIZATION
# ============================================================
PRIVILEGE_MAP = {
    'ad': {
        'StandardUser':    {'score': 1, 'label': 'ReadOnly/User'},
        'PowerUser':       {'score': 2, 'label': 'PowerUser'},
        'ServerAdmin':     {'score': 4, 'label': 'Manager-tier'},
        'DomainAdmin':     {'score': 5, 'label': 'Critical Admin'},
    },
    'aws': {
        'ReadOnly':        {'score': 1, 'label': 'ReadOnly/User'},
        'PowerUser':       {'score': 3, 'label': 'PowerUser'},
        'Administrator':   {'score': 5, 'label': 'Critical Admin'},
    },
    'okta': {
        'User':            {'score': 1, 'label': 'ReadOnly/User'},
        'SuperAdmin':      {'score': 5, 'label': 'Critical Admin'},
    },
    'salesforce': {
        'Standard':        {'score': 1, 'label': 'ReadOnly/User'},
        'SystemAdmin':     {'score': 5, 'label': 'Critical Admin'},
    }
}

def normalize_privilege(platform, raw_value):
    """Map platform-specific privilege to unified 1-5 scale."""
    mapping = PRIVILEGE_MAP.get(platform, {})
    if raw_value not in mapping:
        raise ValueError(f"Unknown privilege '{raw_value}' for platform '{platform}'. "
                        f"Please add it to PRIVILEGE_MAP.")
    return mapping[raw_value]

# ============================================================
# PHASE 4: EFFECTIVE PRIVILEGE CALCULATION
# ============================================================
def load_group_hierarchy():
    """Load group memberships and build inheritance graph."""
    groups = {}
    with open(os.path.join(CSV_DIR, 'group_memberships.csv'), 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            groups[row['group_id']] = row
    return groups

def build_inheritance_graph(groups):
    """Build directed graph of group -> parent_group relationships.
    Returns NetworkX DiGraph and detects cycles."""
    G = nx.DiGraph()
    
    # Add all groups as nodes
    for gid, gdata in groups.items():
        G.add_node(gid, **gdata)
    
    # Add parent edges (child -> parent means child inherits from parent)
    for gid, gdata in groups.items():
        parent_id = gdata.get('parent_group_id', '')
        if parent_id and parent_id in groups:
            G.add_edge(gid, parent_id)  # child -> parent
    
    # Check for cycles
    try:
        cycles = list(nx.simple_cycles(G))
        if cycles:
            print(f"    WARNING: Detected {len(cycles)} cycles in group hierarchy: {cycles}")
    except nx.NetworkXNoCycle:
        pass
    
    return G

def get_effective_privilege(group_names, platform, groups, graph):
    """Calculate effective privilege by walking up inheritance chain.
    Returns (effective_score, inheritance_paths)
    
    group_names: semicolon-separated string of group names
    """
    if not group_names:
        return 1, []
    
    group_list = [g.strip() for g in group_names.split(';') if g.strip()]
    if not group_list:
        return 1, []
    
    # Map group names to IDs
    name_to_id = {g['group_name']: gid for gid, g in groups.items()}
    
    max_score = 1
    inheritance_paths = []
    
    for gname in group_list:
        gid = name_to_id.get(gname)
        if not gid:
            continue
        
        gdata = groups.get(gid, {})
        if gdata.get('platform') != platform:
            continue
        
        # Get direct privilege
        raw_priv = gdata.get('grants_privilege_level', 'StandardUser')
        # Map to normalized score
        platform_map = PRIVILEGE_MAP.get(platform, {})
        norm = platform_map.get(raw_priv, {'score': 1})
        direct_score = norm['score']
        
        if direct_score > max_score:
            max_score = direct_score
            inheritance_paths.append(f"{gname} (direct: {raw_priv})")
        
        # Walk up inheritance
        visited = {gid}
        current = gid
        path = [gname]
        
        while True:
            successors = list(graph.successors(current))
            if not successors:
                break
            parent = successors[0]
            if parent in visited:
                break  # Cycle protection
            visited.add(parent)
            
            parent_data = groups.get(parent, {})
            parent_priv_raw = parent_data.get('grants_privilege_level', 'StandardUser')
            parent_norm = platform_map.get(parent_priv_raw, {'score': 1})
            parent_score = parent_norm['score']
            
            path.append(parent_data.get('group_name', parent))
            
            if parent_score > max_score:
                max_score = parent_score
                inheritance_paths.append(f"{' -> '.join(path)} (inherits: {parent_priv_raw})")
            
            current = parent
    
    return max_score, inheritance_paths

# ============================================================
# PHASE 5: BEHAVIORAL ANALYSIS
# ============================================================
def analyze_behavior(identity_id, audit_events, platform_accounts):
    """Extract behavioral features from audit events for a given identity."""
    events = [e for e in audit_events if e['identity_id'] == identity_id]
    
    if not events:
        return {
            'login_frequency_per_week': 0,
            'platform_count': len(platform_accounts),
            'last_login_days': 999,
            'admin_actions_30d': 0,
            'admin_actions_total': 0,
            'token_usage_count': 0,
            'unique_ip_count': 0,
            'dominant_ip_ratio': 0.0,
            'activity_spike_flag': False,
            'anomalous_ip_flag': False,
            'privilege_changes_30d': 0,
            'after_hours_activity_ratio': 0.0,
        }
    
    # Sort by timestamp
    events.sort(key=lambda x: x['timestamp'])
    
    # Login frequency
    login_events = [e for e in events if e['event_type'] == 'Login']
    date_range_days = max(1, (datetime.strptime(events[-1]['timestamp'], '%Y-%m-%d %H:%M:%S') - 
                               datetime.strptime(events[0]['timestamp'], '%Y-%m-%d %H:%M:%S')).days)
    login_frequency = len(login_events) / (date_range_days / 7)
    
    # Platform count from events
    platforms_from_events = set(e['platform'] for e in events)
    
    # Last login (days ago from reference date)
    reference_date = datetime(2024, 6, 21, 23, 59, 59)
    last_event_time = datetime.strptime(events[-1]['timestamp'], '%Y-%m-%d %H:%M:%S')
    last_login_days = (reference_date - last_event_time).days
    
    # Admin actions
    now_30d = reference_date - timedelta(days=30)
    admin_actions_total = [e for e in events if e['event_type'] in ['AdminAction', 'RoleChange']]
    admin_actions_30d = [e for e in admin_actions_total 
                         if datetime.strptime(e['timestamp'], '%Y-%m-%d %H:%M:%S') > now_30d]
    
    # Token usage
    token_usage = [e for e in events if e['event_type'] == 'TokenUsage']
    
    # IP analysis
    ip_counts = defaultdict(int)
    for e in events:
        ip_counts[e['ip_address']] += 1
    unique_ips = len(ip_counts)
    total_events = len(events)
    dominant_ip_count = max(ip_counts.values()) if ip_counts else 0
    dominant_ip_ratio = dominant_ip_count / total_events if total_events > 0 else 0
    
    # Anomalous IP flag: dominant IP > 70% AND at least one IP < 10%
    ip_ratios = [c / total_events for c in ip_counts.values()]
    anomalous_ip = dominant_ip_ratio > 0.7 and any(r < 0.1 for r in ip_ratios) and unique_ips > 2
    
    # Activity spike: 3+ AdminAction within any 5-day window
    admin_events_sorted = sorted(admin_actions_total, key=lambda x: x['timestamp'])
    activity_spike = False
    for i, event in enumerate(admin_events_sorted):
        event_time = datetime.strptime(event['timestamp'], '%Y-%m-%d %H:%M:%S')
        window_end = event_time + timedelta(days=5)
        count_in_window = sum(1 for j in range(i, len(admin_events_sorted))
                             if datetime.strptime(admin_events_sorted[j]['timestamp'], '%Y-%m-%d %H:%M:%S') <= window_end)
        if count_in_window >= 3:
            activity_spike = True
            break
    
    # Privilege changes in last 30 days
    priv_changes = [e for e in events 
                    if e['event_type'] == 'RoleChange' and datetime.strptime(e['timestamp'], '%Y-%m-%d %H:%M:%S') > now_30d]
    
    # After-hours activity (before 7 AM or after 8 PM)
    after_hours = 0
    for e in events:
        hour = datetime.strptime(e['timestamp'], '%Y-%m-%d %H:%M:%S').hour
        if hour < 7 or hour > 20:
            after_hours += 1
    after_hours_ratio = after_hours / total_events if total_events > 0 else 0
    
    return {
        'login_frequency_per_week': round(login_frequency, 2),
        'platform_count': len(platforms_from_events),
        'last_login_days': last_login_days,
        'admin_actions_30d': len(admin_actions_30d),
        'admin_actions_total': len(admin_actions_total),
        'token_usage_count': len(token_usage),
        'unique_ip_count': unique_ips,
        'dominant_ip_ratio': round(dominant_ip_ratio, 2),
        'activity_spike_flag': activity_spike,
        'anomalous_ip_flag': anomalous_ip,
        'privilege_changes_30d': len(priv_changes),
        'after_hours_activity_ratio': round(after_hours_ratio, 2),
    }

# ============================================================
# PHASE 6: RISK DETECTION ENGINE
# ============================================================
class RuleResult:
    def __init__(self, rule_name, triggered, severity, evidence, platform=''):
        self.rule_name = rule_name
        self.triggered = triggered
        self.severity = severity
        self.evidence = evidence
        self.platform = platform
    
    def to_dict(self):
        return {
            'rule': self.rule_name,
            'triggered': self.triggered,
            'severity': self.severity,
            'evidence': self.evidence,
            'platform': self.platform
        }

def rule_offboarding_gap(identity_record, accounts):
    """Rule 1: Terminated identity with active platform accounts."""
    emp_status = identity_record.get('employment_status', 'Active')
    if emp_status != 'Terminated':
        return RuleResult('Offboarding Gap', False, 'High', '', '')
    
    active_platforms = []
    for plat, acct in accounts.items():
        if acct.get('account_status') == 'Active':
            active_platforms.append(plat)
    
    if active_platforms:
        term_date = identity_record.get('termination_date', 'unknown date')
        return RuleResult(
            'Offboarding Gap', True, 'High',
            f"Account still Active on {', '.join(active_platforms)} — terminated {term_date}",
            ', '.join(active_platforms)
        )
    return RuleResult('Offboarding Gap', False, 'High', '', '')

def rule_cross_platform_admin(identity_record, accounts):
    """Rule 2: Admin (score 5) on 3+ platforms."""
    admin_platforms = []
    for plat, acct in accounts.items():
        eff_priv = int(acct.get('effective_privilege', 1) or 1)
        if eff_priv >= 5:
            admin_platforms.append(plat.upper())
    
    if len(admin_platforms) >= 3:
        return RuleResult(
            'Cross-Platform Admin', True, 'Critical',
            f"Critical admin on {len(admin_platforms)} platforms: {', '.join(admin_platforms)} — blast radius review required",
            ', '.join(admin_platforms)
        )
    return RuleResult('Cross-Platform Admin', False, 'Critical', '', '')

def rule_dormant_admin(identity_record, accounts):
    """Rule 3: Admin (score 4+) on any platform with no login in 90+ days."""
    violations = []
    for plat, acct in accounts.items():
        eff_priv = int(acct.get('effective_privilege', 1) or 1)
        last_login = int(acct.get('last_login_days', 999) or 999)
        status = acct.get('account_status', 'Active')
        
        if eff_priv >= 4 and last_login > 90 and status == 'Active':
            violations.append(f"{plat.upper()} admin inactive {last_login} days")
    
    if violations:
        return RuleResult(
            'Dormant Admin', True, 'High',
            '; '.join(violations),
            'multiple'
        )
    return RuleResult('Dormant Admin', False, 'High', '', '')

def rule_old_credentials(identity_record, accounts):
    """Rule 4: API token or access key age > 365 days."""
    violations = []
    for plat, acct in accounts.items():
        api_age = int(acct.get('api_token_age_days', 0) or 0)
        key_age = int(acct.get('access_key_age_days', 0) or 0)
        
        if api_age > 365:
            violations.append(f"{plat.upper()} API token {api_age} days old")
        if key_age > 365:
            violations.append(f"{plat.upper()} access key {key_age} days old")
    
    if violations:
        return RuleResult(
            'Old Credentials', True, 'Medium',
            '; '.join(violations),
            'multiple'
        )
    return RuleResult('Old Credentials', False, 'Medium', '', '')

def rule_contractor_admin(identity_record, accounts):
    """Rule 5: Contractor with elevated privilege (score 4+)."""
    emp_type = identity_record.get('employment_type', '')
    if emp_type != 'Contractor':
        return RuleResult('Contractor Admin', False, 'High', '', '')
    
    violations = []
    for plat, acct in accounts.items():
        eff_priv = int(acct.get('effective_privilege', 1) or 1)
        if eff_priv >= 4:
            violations.append(f"{plat.upper()} effective privilege level {eff_priv}")
    
    if violations:
        return RuleResult(
            'Contractor Admin', True, 'High',
            '; '.join(violations),
            'multiple'
        )
    return RuleResult('Contractor Admin', False, 'High', '', '')

def rule_service_account_abuse(identity_record, accounts, behavioral):
    """Rule 6: Service account with high privilege + suspicious patterns."""
    emp_type = identity_record.get('employment_type', '')
    if emp_type != 'ServiceAccount':
        return RuleResult('Service Account Abuse', False, 'Critical', '', '')
    
    violations = []
    for plat, acct in accounts.items():
        eff_priv = int(acct.get('effective_privilege', 1) or 1)
        if eff_priv >= 4:
            violations.append(f"{plat.upper()} admin privilege (level {eff_priv})")
    
    # Check behavioral anomalies
    if behavioral.get('anomalous_ip_flag'):
        violations.append("Anomalous IP pattern detected")
    if behavioral.get('activity_spike_flag'):
        violations.append("Activity spike in admin actions")
    if behavioral.get('after_hours_activity_ratio', 0) > 0.3:
        violations.append(f"High after-hours activity ({behavioral['after_hours_activity_ratio']:.0%})")
    
    if violations and any(v for v in violations if 'admin' in v.lower()):
        return RuleResult(
            'Service Account Abuse', True, 'Critical',
            '; '.join(violations),
            'multiple'
        )
    return RuleResult('Service Account Abuse', False, 'Critical', '', '')

# ============================================================
# PHASE 7: RISK SCORING ENGINE
# ============================================================
def calculate_risk_score(identity_id, flags, behavioral, accounts):
    """Calculate weighted risk score with severity floor enforcement."""
    
    # Component 1: Privilege score (40%)
    max_priv = max((int(a.get('effective_privilege', 1) or 1) for a in accounts.values()), default=1)
    privilege_score = max_priv * 20  # 5 -> 100, 1 -> 20
    
    # Component 2: Dormancy score (20%)
    min_login = min((int(a.get('last_login_days', 999) or 999) for a in accounts.values()), default=999)
    dormancy_score = min(min_login / 1.8, 100)  # Cap at 180 days = 100
    
    # Component 3: Platform spread (20%)
    platform_count = len(accounts)
    spread_score = min(platform_count / 4 * 100, 100)
    
    # Component 4: Credential risk (10%)
    max_credential_age = 0
    for a in accounts.values():
        api_age = int(a.get('api_token_age_days', 0) or 0)
        key_age = int(a.get('access_key_age_days', 0) or 0)
        max_credential_age = max(max_credential_age, api_age, key_age)
    credential_score = min(max_credential_age / 7.3, 100)  # Cap at 730 days = 100
    
    # Component 5: Offboarding risk (10%)
    offboarding_score = 0
    for f in flags:
        if f.rule_name == 'Offboarding Gap':
            offboarding_score = 100
            break
    
    # Weighted calculation
    weighted = (
        privilege_score * 0.4 +
        dormancy_score * 0.2 +
        spread_score * 0.2 +
        credential_score * 0.1 +
        offboarding_score * 0.1
    )
    
    # Severity floor enforcement
    severity_floor = 0
    for f in flags:
        if f.severity == 'Critical':
            severity_floor = max(severity_floor, 80)
        elif f.severity == 'High':
            severity_floor = max(severity_floor, 60)
    
    # Also boost for behavioral anomalies
    behavioral_boost = 0
    if behavioral.get('activity_spike_flag'):
        behavioral_boost += 10
    if behavioral.get('anomalous_ip_flag'):
        behavioral_boost += 15
    if behavioral.get('after_hours_activity_ratio', 0) > 0.4:
        behavioral_boost += 10
    
    final_score = min(100, max(weighted, severity_floor) + behavioral_boost)
    
    # Risk level
    if final_score >= 80:
        level = 'Critical'
    elif final_score >= 60:
        level = 'High'
    elif final_score >= 30:
        level = 'Medium'
    else:
        level = 'Low'
    
    return {
        'score': round(final_score, 1),
        'level': level,
        'components': {
            'privilege_score': round(privilege_score, 1),
            'dormancy_score': round(dormancy_score, 1),
            'platform_spread_score': round(spread_score, 1),
            'credential_score': round(credential_score, 1),
            'offboarding_score': round(offboarding_score, 1),
            'behavioral_boost': behavioral_boost
        },
        'flags_count': len(flags)
    }

# ============================================================
# PHASE 8 & 9: EXPLAINABILITY & REMEDIATION
# ============================================================
def generate_explanation(identity_id, identity_record, accounts, flags, behavioral, risk_score):
    """Generate human-readable explanation of risk factors."""
    explanations = []
    
    # Privilege facts
    for plat, acct in accounts.items():
        eff_priv = int(acct.get('effective_privilege', 1) or 1)
        raw_priv = acct.get('privilege_level', 'Unknown')
        inheritance = acct.get('inheritance_path', [])
        
        if eff_priv >= 4:
            if inheritance:
                explanations.append(f"{plat.upper()}: {raw_priv} (effective level {eff_priv}, inherited via {', '.join(inheritance)})")
            else:
                explanations.append(f"{plat.upper()}: {raw_priv} (effective level {eff_priv}, direct grant)")
    
    # Rule flags
    for f in flags:
        explanations.append(f"{f.rule_name}: {f.evidence}")
    
    # Behavioral flags
    if behavioral.get('activity_spike_flag'):
        explanations.append(f"Behavioral: Admin action spike detected ({behavioral['admin_actions_30d']} actions in 30 days)")
    if behavioral.get('anomalous_ip_flag'):
        explanations.append(f"Behavioral: IP usage anomaly ({behavioral['unique_ip_count']} unique IPs, dominant ratio {behavioral['dominant_ip_ratio']})")
    if behavioral.get('after_hours_activity_ratio', 0) > 0.3:
        explanations.append(f"Behavioral: {behavioral['after_hours_activity_ratio']:.0%} activity outside business hours")
    
    # Dormancy
    for plat, acct in accounts.items():
        days = int(acct.get('last_login_days', 0) or 0)
        if days > 90 and acct.get('account_status') == 'Active':
            explanations.append(f"Dormancy: {days} days since last login on {plat.upper()}")
    
    return explanations

def generate_remediations(identity_id, identity_record, accounts, flags, behavioral):
    """Generate platform-specific remediation actions."""
    remediations = []
    
    for f in flags:
        if f.rule_name == 'Offboarding Gap':
            for plat in f.platform.split(', '):
                plat = plat.strip()
                acct = accounts.get(plat.lower(), {})
                username = acct.get('ad_username') or acct.get('aws_username') or \
                          acct.get('okta_login') or acct.get('sf_username', 'unknown')
                term_date = identity_record.get('termination_date', 'unknown date')
                remediations.append(f"[OFFBOARDING] Disable {plat.upper()} account '{username}' — terminated {term_date}, still Active")
        
        elif f.rule_name == 'Cross-Platform Admin':
            remediations.append(f"[PRIVILEGE REVIEW] Review admin necessity on {f.platform}. Consider reducing to least-privilege on at least one platform. Document business justification.")
        
        elif f.rule_name == 'Dormant Admin':
            for plat, acct in accounts.items():
                if int(acct.get('effective_privilege', 1) or 1) >= 4 and int(acct.get('last_login_days', 0) or 0) > 90:
                    username = acct.get('ad_username') or acct.get('aws_username') or \
                              acct.get('okta_login') or acct.get('sf_username', 'unknown')
                    remediations.append(f"[DORMANCY] Disable or re-certify {plat.upper()} admin '{username}' — inactive {acct['last_login_days']} days")
        
        elif f.rule_name == 'Old Credentials':
            # Parse evidence
            if 'API token' in f.evidence:
                for plat, acct in accounts.items():
                    api_age = int(acct.get('api_token_age_days', 0) or 0)
                    if api_age > 365:
                        username = acct.get('ad_username') or acct.get('aws_username') or \
                                  acct.get('okta_login') or acct.get('sf_username', 'unknown')
                        remediations.append(f"[CREDENTIALS] Rotate API token for {plat.upper()} '{username}' — {api_age} days old (exceeds 365-day policy)")
            if 'access key' in f.evidence:
                for plat, acct in accounts.items():
                    key_age = int(acct.get('access_key_age_days', 0) or 0)
                    if key_age > 365:
                        username = acct.get('ad_username') or acct.get('aws_username') or \
                                  acct.get('okta_login') or acct.get('sf_username', 'unknown')
                        remediations.append(f"[CREDENTIALS] Rotate access key for {plat.upper()} '{username}' — {key_age} days old")
        
        elif f.rule_name == 'Contractor Admin':
            username = identity_record.get('full_name', 'unknown')
            remediations.append(f"[CONTRACTOR] Escalate for manager review: contractor '{username}' holds elevated privileges. Verify scope and document justification.")
        
        elif f.rule_name == 'Service Account Abuse':
            username = identity_record.get('full_name', 'unknown')
            remediations.append(f"[SERVICE ACCT] Audit '{username}': review owner/justification for admin grants; rotate credentials; scope down if unjustified")
    
    # Behavioral remediations
    if behavioral.get('anomalous_ip_flag'):
        remediations.append("[BEHAVIORAL] Investigate anomalous IP pattern — verify with identity owner or consider credential rotation")
    if behavioral.get('activity_spike_flag'):
        remediations.append("[BEHAVIORAL] Review recent admin action spike — confirm authorized activity or investigate potential compromise")
    
    return remediations

# ============================================================
# MAIN PIPELINE
# ============================================================
def run_pipeline():
    print("=" * 60)
    print("IDENTITY GOVERNANCE PIPELINE")
    print("=" * 60)
    
    # --- Load base data ---
    print("\n[1/7] Loading base identity data...")
    with open(os.path.join(OUTPUT_DIR, 'identity_360.json'), 'r') as f:
        id_360 = json.load(f)
    print(f"      Loaded {len(id_360)} identities from identity_360.json")
    
    # Load group hierarchy
    groups = load_group_hierarchy()
    group_graph = build_inheritance_graph(groups)
    print(f"      Loaded {len(groups)} groups, inheritance graph ready")
    
    # Load audit events
    audit_events = []
    with open(os.path.join(CSV_DIR, 'audit_events.csv'), 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            audit_events.append(row)
    print(f"      Loaded {len(audit_events):,} audit events")
    
    # --- Phase 3: Privilege Normalization ---
    print("\n[2/7] Phase 3: Privilege Normalization")
    unknown_privileges = []
    for uid, data in id_360.items():
        for plat, acct in data.get('accounts', {}).items():
            raw_priv = acct.get('privilege_level')
            try:
                norm = normalize_privilege(plat, raw_priv)
                acct['normalized_privilege'] = norm['score']
                acct['normalized_label'] = norm['label']
            except ValueError as e:
                unknown_privileges.append(str(e))
    
    if unknown_privileges:
        print(f"      WARNING: {len(unknown_privileges)} unknown privilege values")
    else:
        print(f"      All privileges normalized successfully")
    
    # --- Phase 4: Effective Privilege Calculation ---
    print("\n[3/7] Phase 4: Effective Privilege Calculation (with inheritance)")
    identities_with_inheritance = 0
    
    for uid, data in id_360.items():
        for plat, acct in data.get('accounts', {}).items():
            base_priv = acct.get('normalized_privilege', 1)
            
            # Get group memberships
            group_field = 'group_memberships' if plat in ['ad', 'aws'] else 'assigned_groups'
            group_str = acct.get(group_field, '')
            
            if group_str:
                inherited_score, inheritance_paths = get_effective_privilege(
                    group_str, plat, groups, group_graph
                )
                eff_priv = max(base_priv, inherited_score)
                acct['effective_privilege'] = eff_priv
                acct['inheritance_path'] = inheritance_paths
                if inheritance_paths and eff_priv > base_priv:
                    identities_with_inheritance += 1
            else:
                acct['effective_privilege'] = base_priv
                acct['inheritance_path'] = []
    
    print(f"      Effective privilege calculated for all accounts")
    print(f"      {identities_with_inheritance} identities have elevated privilege via inheritance")
    
    # --- Phase 5: Behavioral Analysis ---
    print("\n[4/7] Phase 5: Behavioral Analysis")
    behavioral_features = {}
    
    for uid, data in id_360.items():
        features = analyze_behavior(uid, audit_events, data.get('accounts', {}))
        behavioral_features[uid] = features
    
    with open(os.path.join(OUTPUT_DIR, 'behavioral_features.json'), 'w') as f:
        json.dump(behavioral_features, f, indent=2)
    
    spike_count = sum(1 for v in behavioral_features.values() if v['activity_spike_flag'])
    ip_anomaly_count = sum(1 for v in behavioral_features.values() if v['anomalous_ip_flag'])
    print(f"      Behavioral features extracted for {len(behavioral_features)} identities")
    print(f"      Activity spikes: {spike_count}")
    print(f"      IP anomalies: {ip_anomaly_count}")
    
    # --- Phase 6: Risk Detection ---
    print("\n[5/7] Phase 6: Risk Detection Engine")
    risk_flags = {}
    
    for uid, data in id_360.items():
        identity_record = data['identity']
        accounts = data.get('accounts', {})
        behavioral = behavioral_features.get(uid, {})
        
        flags = []
        
        # Run all 6 rules
        r1 = rule_offboarding_gap(identity_record, accounts)
        if r1.triggered:
            flags.append(r1)
        
        r2 = rule_cross_platform_admin(identity_record, accounts)
        if r2.triggered:
            flags.append(r2)
        
        r3 = rule_dormant_admin(identity_record, accounts)
        if r3.triggered:
            flags.append(r3)
        
        r4 = rule_old_credentials(identity_record, accounts)
        if r4.triggered:
            flags.append(r4)
        
        r5 = rule_contractor_admin(identity_record, accounts)
        if r5.triggered:
            flags.append(r5)
        
        r6 = rule_service_account_abuse(identity_record, accounts, behavioral)
        if r6.triggered:
            flags.append(r6)
        
        risk_flags[uid] = [f.to_dict() for f in flags]
    
    with open(os.path.join(OUTPUT_DIR, 'risk_flags.json'), 'w') as f:
        json.dump(risk_flags, f, indent=2)
    
    # Summary
    rule_counts = defaultdict(int)
    for flags in risk_flags.values():
        for f in flags:
            rule_counts[f['rule']] += 1
    
    print(f"      Risk flags generated for all identities")
    for rule, count in sorted(rule_counts.items()):
        print(f"        {rule}: {count}")
    
    # --- Phase 7: Risk Scoring ---
    print("\n[6/7] Phase 7: Risk Scoring Engine")
    risk_scores = {}
    
    for uid, data in id_360.items():
        accounts = data.get('accounts', {})
        flags = [RuleResult(f['rule'], True, f['severity'], f['evidence'], f['platform']) 
                 for f in risk_flags.get(uid, [])]
        behavioral = behavioral_features.get(uid, {})
        
        score_data = calculate_risk_score(uid, flags, behavioral, accounts)
        risk_scores[uid] = score_data
    
    with open(os.path.join(OUTPUT_DIR, 'risk_scores.json'), 'w') as f:
        json.dump(risk_scores, f, indent=2)
    
    # Summary
    level_counts = defaultdict(int)
    for score in risk_scores.values():
        level_counts[score['level']] += 1
    
    print(f"      Risk scores calculated")
    for level in ['Critical', 'High', 'Medium', 'Low']:
        print(f"        {level}: {level_counts[level]}")
    
    # --- Phases 8 & 9: Explainability & Remediation ---
    print("\n[7/7] Phases 8 & 9: Explainability & Remediation")
    
    for uid, data in id_360.items():
        identity_record = data['identity']
        accounts = data.get('accounts', {})
        flags = [RuleResult(f['rule'], True, f['severity'], f['evidence'], f['platform']) 
                 for f in risk_flags.get(uid, [])]
        behavioral = behavioral_features.get(uid, {})
        
        # Generate explanations
        explanations = generate_explanation(uid, identity_record, accounts, flags, behavioral, risk_scores[uid])
        data['explainability'] = explanations
        
        # Generate remediations
        remediations = generate_remediations(uid, identity_record, accounts, flags, behavioral)
        data['remediations'] = remediations
        
        # Attach risk score and behavioral data
        data['risk'] = risk_scores[uid]
        data['behavioral'] = behavioral
    
    # Save final enriched identity_360
    with open(os.path.join(OUTPUT_DIR, 'identity_360.json'), 'w') as f:
        json.dump(id_360, f, indent=2)
    
    print(f"      Explanations and remediations generated")
    
    # --- Validation ---
    print("\n" + "=" * 60)
    print("VALIDATION")
    print("=" * 60)
    
    # Check that Critical rules produce High/Critical scores
    critical_violations = []
    for uid, flags in risk_flags.items():
        has_critical_rule = any(f['severity'] == 'Critical' for f in flags)
        if has_critical_rule and risk_scores[uid]['level'] not in ['Critical', 'High']:
            critical_violations.append(uid)
    
    if critical_violations:
        print(f"WARNING: {len(critical_violations)} identities with Critical rules have Low/Medium scores")
    else:
        print("PASS: All Critical-severity rules produce High or Critical overall scores")
    
    # Check offboarding gaps
    ob_count = sum(1 for flags in risk_flags.values() 
                   if any(f['rule'] == 'Offboarding Gap' for f in flags))
    print(f"INFO: Offboarding gaps detected: {ob_count}")
    
    # Check dormant admins
    da_count = sum(1 for flags in risk_flags.values() 
                   if any(f['rule'] == 'Dormant Admin' for f in flags))
    print(f"INFO: Dormant admins detected: {da_count}")
    
    print("\n" + "=" * 60)
    print("PIPELINE COMPLETE")
    print(f"Output directory: {OUTPUT_DIR}")
    print("=" * 60)

if __name__ == '__main__':
    run_pipeline()
