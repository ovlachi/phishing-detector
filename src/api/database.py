"""
Database configuration for MongoDB connection
"""
import motor.motor_asyncio
from bson import ObjectId
import os
from typing import Optional, Dict, Any, List
from datetime import datetime

# MongoDB connection string - replace with your actual connection string
# For local development use: "mongodb://localhost:27017"
MONGO_URL = os.getenv("MONGO_URL", "mongodb+srv://mainUser:8nLh3v2H1A0iVfr1@cluster0.nipyff1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
DB_NAME = os.getenv("DB_NAME", "phishing_detector")

print(f"Connecting to MongoDB at: {MONGO_URL}")
print(f"Using database: {DB_NAME}")

# Create client and database connections
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URL)
database = client[DB_NAME]

# Collections
users_collection = database.users
scan_history_collection = database.scan_history

# Helper for handling MongoDB ObjectId conversion to string
class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")


# Database operations
async def add_user(user_data: Dict[str, Any]) -> str:
    """Add a new user to the database"""
    result = await users_collection.insert_one(user_data)
    return str(result.inserted_id)


async def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Get a user by username"""
    print(f"Looking up user: {username}")
    user = await users_collection.find_one({"username": username})
    print(f"User found: {user is not None}")
    return user


async def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Get a user by email address"""
    print(f"Looking up user by email: {email}")
    user = await users_collection.find_one({"email": email})
    print(f"User found by email: {user is not None}")
    return user

async def update_user(user_id: str, update_data: Dict[str, Any]) -> bool:
    """Update a user's information"""
    result = await users_collection.update_one(
        {"_id": ObjectId(user_id)}, {"$set": update_data}
    )
    return result.modified_count > 0


async def add_scan_record(scan_data: Dict[str, Any]) -> str:
    """Add a scan record to history"""
    result = await scan_history_collection.insert_one(scan_data)
    return str(result.inserted_id)

# Get scan history for a specific user
async def get_user_scan_history(user_id: str) -> List[Dict[str, Any]]:
    """Get scan history for a specific user with better error handling"""
    try:
        print(f"Retrieving scan history for user ID: {user_id}")
        
        # Query the database
        cursor = scan_history_collection.find({"user_id": user_id}).sort("timestamp", -1).limit(100)
        
        # Convert to list
        history = await cursor.to_list(length=100)
        print(f"Found {len(history)} history entries in database")
        
        # Convert ObjectId to string for each document
        for entry in history:
            if '_id' in entry and not isinstance(entry['_id'], str):
                entry['_id'] = str(entry['_id'])
        
        # Make sure timestamps are properly serialized
        for entry in history:
            if 'timestamp' in entry and isinstance(entry['timestamp'], datetime):
                entry['timestamp'] = entry['timestamp'].isoformat()
        
        return history
    except Exception as e:
        print(f"Error in get_user_scan_history: {str(e)}")
        import traceback
        traceback.print_exc()
        
        # Return empty list rather than raising exception
        return []


# Initialize the database (create indexes)
async def init_db():
    """Initialize database indexes"""
    # Create unique indexes on username and email
    await users_collection.create_index("username", unique=True)
    await users_collection.create_index("email", unique=True)
    
    # Create index on user_id and timestamp for scan history
    await scan_history_collection.create_index([("user_id", 1), ("timestamp", -1)])