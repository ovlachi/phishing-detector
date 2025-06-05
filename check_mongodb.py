# save as check_mongodb.py
from pymongo import MongoClient
import json
from datetime import datetime
import sys
import os

# MongoDB connection details (update with your actual connection info)
MONGO_URL = os.getenv("MONGO_URL", "mongodb+srv://mainUser:xxxxxxxxxxxxxxxxxx@cluster0.nipyff1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")  # Change if using a different connection string
DB_NAME = os.getenv("DB_NAME", "phishing_detector")  # Replace with your database name
COLLECTION_NAME = "scan_history"  # Replace with your collection name

def check_latest_records():
    try:
        # Connect to MongoDB
        client = MongoClient(MONGO_URL)
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]
        
        # Find 5 most recent records
        records = list(collection.find().sort("timestamp", -1).limit(5))
        
        # Check if any records were found
        if not records:
            print("No records found in the collection.")
            return
        
        print(f"Found {len(records)} recent records:")
        print("-" * 50)
        
        # Process each record
        for i, record in enumerate(records):
            # Convert ObjectId to string for display
            if "_id" in record:
                record["_id"] = str(record["_id"])
            
            # Convert datetime objects to strings
            for key, value in record.items():
                if isinstance(value, datetime):
                    record[key] = value.isoformat()
            
            # Check for enhanced fields
            has_threat_level = "threat_level" in record
            has_final_confidence = "final_confidence" in record
            has_url_features = "url_features" in record
            
            # Print record summary
            print(f"Record #{i+1}:")
            print(f"URL: {record.get('url', 'N/A')}")
            print(f"Classification: {record.get('classification', 'N/A')}")
            print(f"Has threat_level: {has_threat_level}")
            print(f"Has final_confidence: {has_final_confidence}")
            print(f"Has url_features: {has_url_features}")
            
            # Print enhanced fields if they exist
            if has_threat_level:
                print(f"Threat Level: {record['threat_level']}")
            if has_final_confidence:
                print(f"Final Confidence: {record['final_confidence']}")
            if has_url_features:
                print(f"URL Features: {json.dumps(record['url_features'], indent=2)}")
            
            print("-" * 50)
            
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        sys.exit(1)

if __name__ == "__main__":
    check_latest_records()
