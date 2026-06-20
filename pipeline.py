import csv
import json
import os
import random
from datetime import datetime, timedelta

def run_pipeline():
    print("Starting pipeline execution for Phases 3-9...")
    data_dir = 'csv files'
    
    # ---------------------------------------------------------
    # PHASE 3: Privilege Normalization
    # ---------------------------------------------------------
    print("Phase 3: Privilege Normalization")
    priv_map = {
        'ad': {'StandardUser': 1, 'PowerUser': 2, 'ServerAdmin': 4, 'DomainAdmin': 5},
        'aws': {'ReadOnly': 1, 'PowerUser': 3, 'Administrator': 5},
        'okta': {'User': 1, 'SuperAdmin': 5},
        'salesforce': {'Standard': 1, 'SystemAdmin': 5}
    }
    
    with open('output_files/identity_360.json', 'r') as f:
        id_360 = json.load(f)
        
    for uid, data in id_360.items():
        for plat, acct in data.get('accounts', {}).items():
            raw_priv = acct.get('privilege_level')
            acct['normalized_privilege'] = priv_map.get(plat, {}).get(raw_priv, 1)

    # ---------------------------------------------------------
    # PHASE 4: Effective Privilege Calculation
    # ---------------------------------------------------------
    print("Phase 4: Effective Privilege Calculation")
    # Synthetic group mappings
    group_mappings = {
        'Domain Admins': {'platform': 'ad', 'privilege': 5},
        'Enterprise Admins': {'platform': 'ad', 'privilege': 5},
        'IT Support': {'platform': 'ad', 'privilege': 4},
        'Okta_Admins': {'platform': 'okta', 'privilege': 5},
        'System Administrators': {'platform': 'salesforce', 'privilege': 5}
    }
    
    for uid, data in id_360.items():
        for plat, acct in data.get('accounts', {}).items():
            base_priv = acct.get('normalized_privilege', 1)
            eff_priv = base_priv
            inherited_from = []
            
            # Check groups for AD/Okta
            groups = []
            if plat == 'ad' and 'group_memberships' in acct:
                groups = [g.strip() for g in acct['group_memberships'].split(';')]
            elif plat == 'okta' and 'assigned_groups' in acct:
                groups = [g.strip() for g in acct['assigned_groups'].split(';')]
            
            for g in groups:
                if g in group_mappings and group_mappings[g]['platform'] == plat:
                    g_priv = group_mappings[g]['privilege']
                    if g_priv > eff_priv:
                        eff_priv = g_priv
                        inherited_from.append(g)
            
            acct['effective_privilege'] = eff_priv
            acct['inheritance_path'] = inherited_from

    # ---------------------------------------------------------
    # PHASE 5: Behavioral Analysis (Synthetic generation)
    # ---------------------------------------------------------
    print("Phase 5: Behavioral Analysis")
    behavioral_features = {}
    for uid, data in id_360.items():
        # Extrapolate some behavioral features from the last_login_days present in CSV
        # To avoid making a huge audit log file if we don't need it, we'll just extract what we need
        platforms_active = 0
        min_login_days = 999
        
        for plat, acct in data.get('accounts', {}).items():
            try:
                days = int(acct.get('last_login_days', 999))
                if days < 30: platforms_active += 1
                if days < min_login_days: min_login_days = days
            except:
                pass
                
        behavioral_features[uid] = {
            'platforms_active_30d': platforms_active,
            'days_since_any_login': min_login_days,
            'anomalous_ip_flags': 1 if random.random() > 0.95 else 0
        }
        
    with open('output_files/behavioral_features.json', 'w') as f:
        json.dump(behavioral_features, f, indent=2)

    # ---------------------------------------------------------
    # PHASE 6: Risk Detection Engine
    # ---------------------------------------------------------
    print("Phase 6: Risk Detection Engine")
    risk_flags = {}
    
    for uid, data in id_360.items():
        flags = []
        emp_status = data['identity'].get('employment_status', 'Active')
        emp_type = data['identity'].get('employment_type', 'Employee')
        term_date = data['identity'].get('termination_date', '')
        
        admin_platforms = []
        
        for plat, acct in data.get('accounts', {}).items():
            status = acct.get('account_status', 'Active')
            eff_priv = acct.get('effective_privilege', 1)
            last_login = int(acct.get('last_login_days', 999) or 999)
            
            if eff_priv >= 4:
                admin_platforms.append(plat)
                
            # Rule 1: Offboarding Gap
            if emp_status == 'Terminated' and status == 'Active':
                flags.append({
                    'rule': 'Offboarding Gap',
                    'severity': 'High',
                    'evidence': f"Disable {plat} account immediately - terminated {term_date}, still Active",
                    'platform': plat
                })
                
            # Rule 3: Dormant Admin
            if eff_priv >= 4 and last_login > 90 and status == 'Active':
                flags.append({
                    'rule': 'Dormant Admin',
                    'severity': 'High',
                    'evidence': f"Disable or re-certify {plat} admin access - inactive {last_login} days",
                    'platform': plat
                })
                
            # Rule 4: Old Credentials
            api_age = int(acct.get('api_token_age_days', 0) or 0)
            key_age = int(acct.get('access_key_age_days', 0) or 0)
            if api_age > 365:
                flags.append({
                    'rule': 'Old Credentials',
                    'severity': 'Medium',
                    'evidence': f"Rotate API token on {plat} - {api_age} days old",
                    'platform': plat
                })
            if key_age > 365:
                flags.append({
                    'rule': 'Old Credentials',
                    'severity': 'Medium',
                    'evidence': f"Rotate Access Key on {plat} - {key_age} days old",
                    'platform': plat
                })
                
            # Rule 5: Contractor Admin
            if emp_type == 'Contractor' and eff_priv >= 4:
                flags.append({
                    'rule': 'Contractor Admin',
                    'severity': 'Medium',
                    'evidence': f"Escalate for manager review: contractor holds level {eff_priv} admin on {plat}",
                    'platform': plat
                })
                
            # Rule 6: Service Account Abuse (Critical)
            if emp_type == 'ServiceAccount' and eff_priv >= 4:
                # If a service account is highly privileged and we see active interactive logins (anomalous IP)
                if behavioral_features[uid]['anomalous_ip_flags'] > 0:
                    flags.append({
                        'rule': 'Service Account Abuse',
                        'severity': 'Critical',
                        'evidence': f"Audit owner/justification for service account admin grant on {plat}; possible interactive abuse",
                        'platform': plat
                    })

        # Rule 2: Cross-Platform Admin (Critical)
        if len(admin_platforms) >= 2:
            flags.append({
                'rule': 'Cross-Platform Admin',
                'severity': 'Critical',
                'evidence': f"Review necessity of admin access on {', '.join(admin_platforms)}; consider reducing to least-privilege",
                'platform': 'multiple'
            })
            
        risk_flags[uid] = flags

    with open('output_files/risk_flags.json', 'w') as f:
        json.dump(risk_flags, f, indent=2)

    # ---------------------------------------------------------
    # PHASE 7: Risk Scoring Engine
    # ---------------------------------------------------------
    print("Phase 7: Risk Scoring Engine")
    risk_scores = {}
    
    for uid, flags in risk_flags.items():
        score = 10  # Base score
        severity_floor = 0
        
        for f in flags:
            if f['severity'] == 'Critical':
                score += 40
                severity_floor = max(severity_floor, 80)
            elif f['severity'] == 'High':
                score += 25
                severity_floor = max(severity_floor, 60)
            elif f['severity'] == 'Medium':
                score += 10
                
        # Apply anomalies
        if behavioral_features[uid]['anomalous_ip_flags'] > 0:
            score += 15
            
        # Floor enforcement
        final_score = min(100, max(score, severity_floor))
        
        level = "Low"
        if final_score >= 80: level = "Critical"
        elif final_score >= 60: level = "High"
        elif final_score >= 30: level = "Medium"
        
        risk_scores[uid] = {
            'score': final_score,
            'level': level,
            'flags_count': len(flags)
        }
        
    with open('output_files/risk_scores.json', 'w') as f:
        json.dump(risk_scores, f, indent=2)

    # ---------------------------------------------------------
    # PHASE 8 & 9: Explainability and Remediation
    # ---------------------------------------------------------
    print("Phase 8 & 9: Explainability and Remediation")
    
    # Save the updated identity_360 to include all new fields
    # Inject Risk Score and Explanations
    for uid, data in id_360.items():
        data['risk'] = risk_scores[uid]
        data['behavioral'] = behavioral_features[uid]
        
        explanations = []
        remediations = []
        
        # Add privilege facts
        for plat, acct in data.get('accounts', {}).items():
            if acct.get('effective_privilege', 1) >= 4:
                path = "direct grant"
                if acct.get('inheritance_path'):
                    path = f"inherited via {', '.join(acct['inheritance_path'])}"
                explanations.append(f"{plat} Admin ({path})")
                
        # Add flags
        for f in risk_flags[uid]:
            explanations.append(f"{f['rule']} on {f['platform']}")
            remediations.append(f['evidence']) # The evidence string we built matches Phase 9 remediation templates
            
        data['explainability'] = explanations
        data['remediations'] = remediations
        
    with open('output_files/identity_360.json', 'w') as f:
        json.dump(id_360, f, indent=2)
        
    print("Pipeline execution complete! Data ready for Phase 10 (Dashboard).")

if __name__ == '__main__':
    run_pipeline()
