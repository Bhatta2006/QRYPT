import asyncio
import os
import json
import numpy as np
import joblib
from datetime import datetime
from collections import defaultdict
import asyncpg
from sklearn.ensemble import IsolationForest
from app.core.config import get_settings

async def main():
    settings = get_settings()
    
    # Needs to match the asyncpg DSN format (asyncpg doesn't use the +asyncpg in the schema)
    # The config has postgresql+asyncpg://...
    db_url = settings.database_url.replace("+asyncpg", "")
    
    conn = await asyncpg.connect(db_url)
    
    # We select from scan_events
    query = """
        SELECT trace_id, device_fingerprint_hash, scanned_at as created_at
        FROM scan_events 
        WHERE scanned_at > now() - interval '30 days'
    """
    rows = await conn.fetch(query)
    await conn.close()
    
    data_by_trace = defaultdict(list)
    
    for row in rows:
        trace_id = row['trace_id']
        data_by_trace[trace_id].append({
            'device_fingerprint_hash': row['device_fingerprint_hash'],
            'created_at': row['created_at']
        })
        
    extracted_features = []
    
    if len(rows) < 100:
        print("Insufficient data (< 100 rows). Generating synthetic training data.")
        np.random.seed(42)
        # Generate 500 synthetic traces
        for i in range(500):
            # features: [scan_velocity, device_diversity, geo_scatter, hour_of_day, is_weekend]
            is_anomaly = np.random.rand() < 0.05
            if is_anomaly:
                scan_velocity = np.random.randint(50, 200)
                device_diversity = np.random.randint(5, 50)
            else:
                scan_velocity = np.random.randint(1, 10)
                device_diversity = np.random.randint(1, 3)
                
            hour_of_day = np.random.randint(0, 24)
            is_weekend = np.random.randint(0, 2)
            geo_scatter_radius_km = 0.0
            
            extracted_features.append([
                scan_velocity, 
                device_diversity, 
                geo_scatter_radius_km, 
                hour_of_day, 
                is_weekend
            ])
    else:
        # Extract features per trace_id
        for trace_id, events in data_by_trace.items():
            if not events:
                continue
                
            devices = set(e['device_fingerprint_hash'] for e in events if e['device_fingerprint_hash'])
            device_diversity_score = len(devices)
            
            # Times
            times = [e['created_at'].timestamp() for e in events]
            min_time = min(times)
            max_time = max(times)
            
            elapsed_minutes = (max_time - min_time) / 60.0
            if elapsed_minutes < 1.0:
                elapsed_minutes = 1.0
                
            scan_velocity_per_min = len(events) / elapsed_minutes
            geo_scatter_radius_km = 0.0
            
            # Using the first event's time for hour and weekend
            first_event_time = min(e['created_at'] for e in events)
            hour_of_day = first_event_time.hour
            is_weekend = int(first_event_time.weekday() >= 5)
            
            extracted_features.append([
                int(scan_velocity_per_min),
                int(device_diversity_score),
                geo_scatter_radius_km,
                hour_of_day,
                is_weekend
            ])
            
    X = np.array(extracted_features)
    
    print("Training Isolation Forest...")
    model = IsolationForest(contamination=0.05, n_estimators=200, random_state=42)
    model.fit(X)
    
    model_dir = "/app/models"
    
    # Fallback to local directory if not running in docker
    if not os.path.exists(model_dir):
        if os.path.exists("../../models"):
            model_dir = "../../models"
        else:
            model_dir = "./models"
            os.makedirs(model_dir, exist_ok=True)
            
    model_path = os.path.join(model_dir, "anomaly_model.joblib")
    joblib.dump(model, model_path)
    
    print(f"Model saved. Samples: {len(X)}. Features shape: {X.shape}.")

if __name__ == "__main__":
    asyncio.run(main())
