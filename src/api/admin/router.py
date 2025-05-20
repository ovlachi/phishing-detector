from fastapi import APIRouter, Depends, HTTPException, Query, Request
from typing import List, Optional
from datetime import datetime, timedelta
from bson import ObjectId
from pydantic import BaseModel, Field
from ..auth import get_current_admin_user, get_password_hash
from ..database import database, users_collection, scan_history_collection
from ..models import User, UserResponse, UserUpdateRequest

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(get_current_admin_user)]  # Only admin users can access
)

class UserListResponse(BaseModel):
    users: List[UserResponse]
    total: int
    page: int
    page_size: int

class ScanListResponse(BaseModel):
    scans: List
    total: int
    page: int
    page_size: int

# Helper to maintain compatibility with original code
def get_db():
    """Helper function to provide database collections in a structure similar to original code"""
    db = type('', (), {})()
    db.users = users_collection
    db.scans = scan_history_collection
    return db

@router.get("/dashboard")
async def get_dashboard_data():
    """Get summary data for admin dashboard"""
    db = get_db()
    
    # Get user stats
    total_users = await db.users.count_documents({})
    users_last_24h = await db.users.count_documents({
        "created_at": {"$gte": datetime.utcnow() - timedelta(days=1)}
    })
    active_users = await db.users.count_documents({
        "last_login": {"$gte": datetime.utcnow() - timedelta(days=7)}
    })
    premium_users = await db.users.count_documents({"premium": True})
    
    # Get scan stats
    total_scans = await db.scans.count_documents({})
    scans_today = await db.scans.count_documents({
        "timestamp": {"$gte": datetime.utcnow() - timedelta(days=1)}
    })
    
    # Get risk distribution
    pipeline = [
        {"$group": {
            "_id": "$risk",
            "count": {"$sum": 1}
        }}
    ]
    risk_distribution = await db.scans.aggregate(pipeline).to_list(10)
    
    return {
        "user_stats": {
            "total_users": total_users,
            "new_users_24h": users_last_24h,
            "active_users_7d": active_users,
            "premium_users": premium_users,
        },
        "scan_stats": {
            "total_scans": total_scans,
            "scans_today": scans_today,
            "risk_distribution": risk_distribution
        }
    }

@router.get("/users/analytics")
async def get_users_analytics():
    """Get analytics about registered users"""
    db = get_db()
    
    # Get user growth over time (last 30 days)
    pipeline = [
        {"$match": {"created_at": {"$gte": datetime.utcnow() - timedelta(days=30)}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$created_at"}},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}
    ]
    user_growth = await db.users.aggregate(pipeline).to_list(30)
    
    # Get premium conversion
    pipeline = [
        {"$match": {"premium": True}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$premium_since"}},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}
    ]
    premium_conversions = await db.users.aggregate(pipeline).to_list(30)
    
    return {
        "user_growth": user_growth,
        "premium_conversions": premium_conversions
    }

@router.get("/scans/analytics")
async def get_scans_analytics():
    """Get analytics about URL scans"""
    db = get_db()
    
    # Get scans over time (last 30 days)
    pipeline = [
        {"$match": {"timestamp": {"$gte": datetime.utcnow() - timedelta(days=30)}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}
    ]
    scan_volume = await db.scans.aggregate(pipeline).to_list(30)
    
    # Get scan results by type over time
    pipeline = [
        {"$match": {"timestamp": {"$gte": datetime.utcnow() - timedelta(days=30)}}},
        {"$group": {
            "_id": {
                "date": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                "risk": "$risk"
            },
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id.date": 1}}
    ]
    risk_trends = await db.scans.aggregate(pipeline).to_list(100)
    
    return {
        "scan_volume": scan_volume,
        "risk_trends": risk_trends
    }

@router.get("/users", response_model=UserListResponse)
async def get_users_list(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    search: Optional[str] = None,
    filter: Optional[str] = None
):
    """Get list of users with pagination and filtering"""
    db = get_db()
    
    # Build query
    query = {}
    if search:
        query["$or"] = [
            {"username": {"$regex": search, "$options": "i"}},
            {"email": {"$regex": search, "$options": "i"}},
            {"full_name": {"$regex": search, "$options": "i"}}
        ]
    
    if filter:
        if filter == "premium":
            query["premium"] = True
        elif filter == "free":
            query["premium"] = False
        elif filter == "active":
            query["is_active"] = True
        elif filter == "inactive":
            query["is_active"] = False
    
    # Get total count
    total = await db.users.count_documents(query)
    
    # Get paginated users
    users = await db.users.find(query).skip((page - 1) * page_size).limit(page_size).to_list(page_size)
    
    # Convert ObjectId to str for JSON serialization
    for user in users:
        user["_id"] = str(user["_id"])
        if "created_at" in user and isinstance(user["created_at"], datetime):
            user["created_at"] = user["created_at"].isoformat()
        if "last_login" in user and user["last_login"]:
            if isinstance(user["last_login"], datetime):
                user["last_login"] = user["last_login"].isoformat()
        # Remove password hash
        if "hashed_password" in user:
            del user["hashed_password"]
    
    return {
        "users": users,
        "total": total,
        "page": page,
        "page_size": page_size
    }

@router.get("/scans", response_model=ScanListResponse)
async def get_scans_list(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    user_id: Optional[str] = None,
    risk: Optional[str] = None
):
    """Get list of scans with pagination and filtering"""
    db = get_db()
    
    # Build query
    query = {}
    if user_id:
        try:
            query["user_id"] = ObjectId(user_id)
        except:
            query["user_id"] = user_id  # In case it's stored as string
    
    if risk:
        query["risk"] = risk
    
    # Get total count
    total = await db.scans.count_documents(query)
    
    # Get paginated scans
    scans = await db.scans.find(query).skip((page - 1) * page_size).limit(page_size).to_list(page_size)
    
    # Convert ObjectId to str for JSON serialization
    for scan in scans:
        scan["_id"] = str(scan["_id"])
        if "user_id" in scan and not isinstance(scan["user_id"], str):
            scan["user_id"] = str(scan["user_id"])
        if "timestamp" in scan and isinstance(scan["timestamp"], datetime):
            scan["timestamp"] = scan["timestamp"].isoformat()
    
    return {
        "scans": scans,
        "total": total,
        "page": page,
        "page_size": page_size
    }

@router.get("/users/{user_id}")
async def get_user_details(user_id: str):
    """Get detailed information about a specific user"""
    db = get_db()
    
    try:
        # Convert string ID to ObjectId
        obj_id = ObjectId(user_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    user = await db.users.find_one({"_id": obj_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get user's scan history
    user_scans = await db.scans.find({"user_id": obj_id}).limit(20).to_list(20)
    
    # Convert ObjectId to str for JSON serialization
    user["_id"] = str(user["_id"])
    if "created_at" in user and isinstance(user["created_at"], datetime):
        user["created_at"] = user["created_at"].isoformat()
    if "last_login" in user and user["last_login"]:
        if isinstance(user["last_login"], datetime):
            user["last_login"] = user["last_login"].isoformat()
    
    # Remove password hash
    if "hashed_password" in user:
        del user["hashed_password"]
    
    # Process scans
    for scan in user_scans:
        scan["_id"] = str(scan["_id"])
        if "user_id" in scan and not isinstance(scan["user_id"], str):
            scan["user_id"] = str(scan["user_id"])
        if "timestamp" in scan and isinstance(scan["timestamp"], datetime):
            scan["timestamp"] = scan["timestamp"].isoformat()
    
    return {
        "user_details": user,
        "scan_history": user_scans
    }

@router.put("/users/{user_id}")
async def update_user(
    user_id: str, 
    user_data: UserUpdateRequest
):
    """Update user information"""
    db = get_db()
    
    try:
        # Convert string ID to ObjectId
        obj_id = ObjectId(user_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    # Check if user exists
    user = await db.users.find_one({"_id": obj_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prepare update data
    update_data = {k: v for k, v in user_data.dict().items() if v is not None}
    
    # Update user
    result = await db.users.update_one(
        {"_id": obj_id},
        {"$set": update_data}
    )
    
    if result.modified_count == 0:
        # No changes made
        return {"message": "No changes made to user"}
    
    # Get updated user
    updated_user = await db.users.find_one({"_id": obj_id})
    updated_user["_id"] = str(updated_user["_id"])
    
    # Remove password hash
    if "hashed_password" in updated_user:
        del updated_user["hashed_password"]
    
    return {
        "message": "User updated successfully",
        "user": updated_user
    }

@router.post("/users/create")
async def create_user(user_data: UserUpdateRequest):
    """Create a new user"""
    db = get_db()
    
    # Check if username or email already exists
    existing_user = await db.users.find_one({
        "$or": [
            {"username": user_data.username},
            {"email": user_data.email}
        ]
    })
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    # Create new user
    new_user = user_data.dict()
    
    # Add required fields
    new_user["created_at"] = datetime.utcnow()
    new_user["is_active"] = True
    
    # Hash password if provided
    if user_data.password:
        new_user["hashed_password"] = get_password_hash(user_data.password)
        del new_user["password"]  # Remove plain password
    
    # Insert user
    result = await db.users.insert_one(new_user)
    
    return {
        "message": "User created successfully",
        "user_id": str(result.inserted_id)
    }

@router.delete("/users/{user_id}")
async def deactivate_user(user_id: str):
    """Deactivate a user (soft delete)"""
    db = get_db()
    
    try:
        # Convert string ID to ObjectId
        obj_id = ObjectId(user_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    # Check if user exists
    user = await db.users.find_one({"_id": obj_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Don't allow deactivating admin users
    if user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Cannot deactivate admin users")
    
    # Deactivate user (soft delete)
    result = await db.users.update_one(
        {"_id": obj_id},
        {"$set": {"is_active": False}}
    )
    
    if result.modified_count == 0:
        return {"message": "User was already inactive"}
    
    return {"message": "User deactivated successfully"}