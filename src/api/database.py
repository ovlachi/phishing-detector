"""
Database configuration for MongoDB connection
"""
import motor.motor_asyncio
from bson import ObjectId
import os
from typing import Optional, Dict, Any, List

# MongoDB connection string - replace with your actual connection string
# For local development use: "mongodb://localhost:27017"
MONGO_URL = os.getenv("MONGO_URL", "mongodb+srv://mainUser:8nLh3v2H1A0iVfr1@cluster0.nipyff1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
DB_NAME = os.getenv("DB_NAME", "phishing_detector")

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
    user = await users_collection.find_one({"username": username})
    return user


async def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Get a user by email"""
    user = await users_collection.find_one({"email": email})
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


async def get_user_scan_history(user_id: str) -> List[Dict[str, Any]]:
    """Get scan history for a specific user"""
    cursor = scan_history_collection.find({"user_id": user_id}).sort("timestamp", -1).limit(100)
    return await cursor.to_list(length=100)


# Initialize the database (create indexes)
async def init_db():
    """Initialize database indexes"""
    # Create unique indexes on username and email
    await users_collection.create_index("username", unique=True)
    await users_collection.create_index("email", unique=True)
    
    # Create index on user_id and timestamp for scan history
    await scan_history_collection.create_index([("user_id", 1), ("timestamp", -1)])