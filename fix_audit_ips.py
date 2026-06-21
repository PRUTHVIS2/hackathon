import csv
import random
import os
from collections import defaultdict
from datetime import datetime, timedelta

def generate_ip():
    return f"{random.randint(10, 250)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def main():
    csv_path = 'csv_files/audit_events.csv'
    
    # Read all events
    events = []
    identities = set()
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(row)
            identities.add(row['identity_id'])
            
    identities = list(identities)
    print(f"Loaded {len(events)} events for {len(identities)} identities.")
    
    # Pick 20 identities to be anomalous
    random.seed(42)
    anomalous_identities = set(random.sample(identities, 20))
    
    # Generate 1-2 dominant IPs per identity, and a secondary one
    identity_ips = {}
    for uid in identities:
        num_dominant = random.choices([1, 2], weights=[90, 10])[0]
        dominant_ips = [generate_ip() for _ in range(num_dominant)]
        secondary_ip = generate_ip()
        identity_ips[uid] = {
            'dominant': dominant_ips,
            'secondary': secondary_ip
        }
        
    # Group events by identity to process
    events_by_id = defaultdict(list)
    for e in events:
        events_by_id[e['identity_id']].append(e)
        
    reference_date = datetime(2024, 6, 21, 23, 59, 59)
    now_30d = reference_date - timedelta(days=30)
        
    new_events = []
    
    for uid, uid_events in events_by_id.items():
        uid_events.sort(key=lambda x: x['timestamp'])
        
        is_anomalous = uid in anomalous_identities
        ips = identity_ips[uid]
        
        # We need to make sure we have exactly 1 anomalous event in the last 30 days if it's anomalous
        # Find an event in last 30 days
        last_30d_indices = [
            i for i, e in enumerate(uid_events) 
            if datetime.strptime(e['timestamp'], '%Y-%m-%d %H:%M:%S') > now_30d
        ]
        
        anomalous_index = -1
        if is_anomalous and last_30d_indices:
            anomalous_index = random.choice(last_30d_indices)
        elif is_anomalous:
            # If no events in last 30 days, just pick the last one
            anomalous_index = len(uid_events) - 1
            
        for i, e in enumerate(uid_events):
            if i == anomalous_index:
                e['ip_address'] = generate_ip() # completely new anomalous IP
            else:
                # 90% dominant, 10% secondary
                if random.random() < 0.90:
                    e['ip_address'] = random.choice(ips['dominant'])
                else:
                    e['ip_address'] = ips['secondary']
                    
            new_events.append(e)

    # Sort back to original if needed? Or just sort by timestamp. The original might be sorted by timestamp
    new_events.sort(key=lambda x: x['timestamp'])
    
    # Write back
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=events[0].keys())
        writer.writeheader()
        writer.writerows(new_events)
        
    print(f"Updated IPs for {len(new_events)} events.")
    print(f"Anomalous identities generated: {len(anomalous_identities)}")

if __name__ == '__main__':
    main()
