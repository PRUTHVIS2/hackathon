#!/usr/bin/env python3
"""
Phase 2: Identity Correlation Engine
Maps platform accounts (AD, AWS, Okta, Salesforce) to unified identities.
Produces identity_360.json — the foundation for all downstream analysis.
"""

import csv
import json
import os

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

def build_match_indexes(identities):
    """Build username-to-identity lookup indexes for each platform."""
    indexes = {
        'ad': {},
        'aws': {},
        'okta': {},
        'salesforce': {}
    }
    
    for uid, data in identities.items():
        fname = data['full_name'].split()[0].lower()
        lname = data['full_name'].split()[-1].lower()
        emp_type = data['employment_type']
        
        # Service Accounts: svc_{dept}_{number}
        if emp_type == 'ServiceAccount':
            parts = data['full_name'].split('_')
            num = parts[-1]
            ad_user = f"svc_{num}"
            aws_user = f"svc-{num}"
            okta_user = f"svc_{num}@company.com"
            sf_user = f"svc_{num}_sf"
            
            indexes['ad'].setdefault(ad_user, []).append(uid)
            indexes['aws'].setdefault(aws_user, []).append(uid)
            indexes['okta'].setdefault(okta_user, []).append(uid)
            indexes['salesforce'].setdefault(sf_user, []).append(uid)
            continue
            
        # Contractors and Employees
        ad_user = f"{fname}.{lname}"
        aws_user = f"{fname[0]}{lname}"
        okta_user = f"{fname}.{lname}@company.com"
        sf_user = f"{fname}_{lname}_sf"
        
        if emp_type == 'Contractor':
            ad_user = f"c-{ad_user}"
            aws_user = f"c_{aws_user}"
            okta_user = f"{fname}.{lname}@contractor.company.com"
            sf_user = f"c_{fname}_{lname}_sf"
            
        indexes['ad'].setdefault(ad_user, []).append(uid)
        indexes['aws'].setdefault(aws_user, []).append(uid)
        indexes['okta'].setdefault(okta_user, []).append(uid)
        indexes['salesforce'].setdefault(sf_user, []).append(uid)
        
    return indexes

def correlate():
    """Main correlation function."""
    print("Phase 2: Identity Correlation Engine")
    print("-" * 40)
    
    identities = load_identities()
    print(f"Loaded {len(identities)} master identities")
    
    indexes = build_match_indexes(identities)
    
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
                candidates = indexes[platform].get(username.lower(), [])
                
                predicted_uid = None
                confidence = "None"
                if len(candidates) == 1:
                    predicted_uid = candidates[0]
                    confidence = "High"
                elif len(candidates) > 1:
                    predicted_uid = candidates[0]
                    confidence = "Low (Collision)"
                    
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
    
    # Save identity_360.json
    with open(os.path.join(OUTPUT_DIR, 'identity_360.json'), 'w') as f:
        json.dump(id_360, f, indent=2)
    
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
    print(f"\nSaved: identity_360.json, phase2_match_report.csv")

if __name__ == '__main__':
    correlate()
