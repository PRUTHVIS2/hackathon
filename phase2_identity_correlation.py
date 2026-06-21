#!/usr/bin/env python3
"""
Phase 2: Identity Correlation Engine
Maps platform accounts (AD, AWS, Okta, Salesforce) to unified identities.
Produces identity_360_base.json — the foundation for all downstream analysis.
"""

import csv
import json
import os
import re

CSV_DIR = os.path.join(os.path.dirname(__file__), 'csv_files')
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'output_files')
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_identities():
    """Load master identity records."""
    identities = {}
    with open(os.path.join(CSV_DIR, 'identities.csv'), 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            identities[row['identity_id']] = row
    return identities

def match_username_to_identity(username, platform, identities):
    username_lower = username.lower()
    
    # Check if username is service account pattern
    svc_match = re.search(r'svc[-_](\d+)', username_lower)
    
    # Check if username is contractor pattern
    is_contractor = username_lower.startswith('c-') or username_lower.startswith('c_') or '@contractor' in username_lower
    
    best_score = -1.0
    candidates = []
    
    for uid, data in identities.items():
        full_name = data['full_name'].lower()
        parts = full_name.split()
        fname = parts[0]
        lname = parts[-1]
        emp_type = data['employment_type']
        
        score = 0.0
        
        # Service account matching
        if svc_match:
            # Only match service accounts if name looks like svc_something_number
            if emp_type == 'ServiceAccount':
                # Extract number from identity name
                id_svc_match = re.search(r'svc_.*_(\d+)', full_name)
                if id_svc_match and id_svc_match.group(1) == svc_match.group(1):
                    score = 1.0
        else:
            # Preprocess username for human matching
            u = username_lower.split('@')[0]
            if u.startswith('c-') or u.startswith('c_'):
                u = u[2:]
                
            tokens = [t for t in re.split(r'[^a-z]', u) if t]
            alpha_only = re.sub(r'[^a-z]', '', u)
            
            # 1. Token match
            if lname in tokens:
                if fname in tokens:
                    score = 1.0
                elif fname[0] in tokens:
                    score = 0.9
                else:
                    score = 0.6
            # 2. Boundary match
            elif alpha_only.endswith(lname):
                prefix = alpha_only[:-len(lname)]
                if prefix == fname:
                    score = 1.0
                elif prefix == fname[0]:
                    score = 0.9
                elif prefix == '':
                    score = 0.6
            elif alpha_only.startswith(lname):
                suffix = alpha_only[len(lname):]
                if suffix == fname:
                    score = 1.0
                elif suffix == fname[0]:
                    score = 0.9
                elif suffix == '':
                    score = 0.6
            # 3. First name only
            elif fname in tokens or alpha_only == fname:
                score = 0.3
                
            # Disambiguate with contractor flag
            if is_contractor and emp_type == 'Contractor':
                score += 0.05
            elif not is_contractor and emp_type != 'Contractor':
                score += 0.05
                
        if score > best_score:
            best_score = score
            candidates = [uid]
        elif score == best_score and score > 0:
            candidates.append(uid)
            
    if best_score >= 0.5:
        if len(candidates) == 1:
            return candidates[0], str(best_score)
        else:
            return candidates[0], f"{best_score} (Collision)"
    return None, "None"

def correlate():
    """Main correlation function."""
    print("Phase 2: Identity Correlation Engine")
    print("-" * 40)
    
    identities = load_identities()
    print(f"Loaded {len(identities)} master identities")
    
    # Initialize 360 view
    id_360 = {}
    for uid, data in identities.items():
        id_360[uid] = {
            "identity": data,
            "accounts": {}
        }
    
    match_report = []
    
    def process_file(platform, filename, user_field):
        filepath = os.path.join(CSV_DIR, filename)
        if not os.path.exists(filepath):
            print(f"WARNING: {filepath} not found, skipping")
            return
            
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            row_count = 0
            for row in reader:
                row_count += 1
                username = row[user_field]
                actual_uid = row['identity_id']
                
                # Match logic
                predicted_uid, confidence = match_username_to_identity(username, platform, identities)
                
                match_status = "Correct" if predicted_uid == actual_uid else "Incorrect"
                if predicted_uid is None:
                    match_status = "Unmatched"
                
                match_report.append({
                    "platform": platform,
                    "account_username": username,
                    "predicted_identity_id": predicted_uid,
                    "actual_identity_id": actual_uid,
                    "confidence": confidence,
                    "match_status": match_status
                })
                
                if predicted_uid:
                    acct_data = dict(row)
                    del acct_data['identity_id']
                    id_360[predicted_uid]['accounts'][platform] = acct_data
            
            print(f"  {platform}: Processed {row_count} accounts")
    
    process_file('ad', 'ad_accounts.csv', 'ad_username')
    process_file('aws', 'aws_accounts.csv', 'aws_username')
    process_file('okta', 'okta_accounts.csv', 'okta_login')
    process_file('salesforce', 'salesforce_accounts.csv', 'sf_username')
    
    # Save identity_360_base.json
    base_file = os.path.join(OUTPUT_DIR, 'identity_360_base.json')
    with open(base_file, 'w') as f:
        json.dump(id_360, f, indent=2)
        
    # Delete enriched file if it exists to prevent stale data
    enriched_file = os.path.join(OUTPUT_DIR, 'identity_360_enriched.json')
    if os.path.exists(enriched_file):
        os.remove(enriched_file)
    
    # Save match report
    with open(os.path.join(OUTPUT_DIR, 'phase2_match_report.csv'), 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            "platform", "account_username", "predicted_identity_id", 
            "actual_identity_id", "confidence", "match_status"
        ])
        writer.writeheader()
        writer.writerows(match_report)
    
    # Accuracy stats
    total = len(match_report)
    correct = sum(1 for m in match_report if m['match_status'] == 'Correct')
    unmatched = sum(1 for m in match_report if m['match_status'] == 'Unmatched')
    collisions = sum(1 for m in match_report if 'Collision' in m['confidence'])
    
    print(f"\nCorrelation Results:")
    print(f"  Total Accounts: {total}")
    print(f"  Correct Matches: {correct}")
    print(f"  Accuracy: {correct/total:.1%}")
    print(f"  Unmatched: {unmatched}")
    print(f"  Name Collisions: {collisions}")
    
    print("\nFailure Analysis (Non-Collision Mistakes):")
    for m in match_report:
        if m['match_status'] != 'Correct' and m['predicted_identity_id']:
            actual = identities.get(m['actual_identity_id'])
            pred = identities.get(m['predicted_identity_id'])
            if actual and pred and actual['full_name'] != pred['full_name']:
                print(f"  Mismatch: {m['account_username']} -> Predicted: {pred['full_name']} ({pred['identity_id']}), Actual: {actual['full_name']} ({actual['identity_id']})")
                
    print(f"\nSaved: identity_360_base.json, phase2_match_report.csv")

if __name__ == '__main__':
    correlate()
