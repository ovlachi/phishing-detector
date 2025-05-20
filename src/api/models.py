"""
Pydantic models for user authentication and data validation
"""
from pydantic import BaseModel, Field, EmailStr, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
import re
from bson import ObjectId

from src.api.utils import PyObjectId


class UserBase(BaseModel):
    """Base user model with common fields"""
    username: str
    email: EmailStr
    full_name: str
    
    @validator('username')
    def username_must_be_valid(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', v):
            raise ValueError('Username must be 3-20 characters and contain only letters, numbers, underscores, and hyphens')
        return v


class UserCreate(UserBase):
    """Model for user creation"""
    password: str
    
    @validator('password')
    def password_must_be_strong(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(char.islower() for char in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least one number')
        return v


class UserInDB(UserBase):
    """Database model for user"""
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    hashed_password: str
    disabled: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    
    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


class User(UserBase):
    """User model returned to client"""
    id: str = Field(alias="_id")
    disabled: bool = False
    
    class Config:
        allow_population_by_field_name = True


class Token(BaseModel):
    """Token model for authentication"""
    access_token: str
    token_type: str
    username: str
    full_name: str


class TokenData(BaseModel):
    """Token data model"""
    username: Optional[str] = None


class ScanHistoryEntry(BaseModel):
    """Model for scan history entry"""
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    user_id: str
    url: str
    ip_address: Optional[str] = None
    hosting_provider: Optional[str] = None
    disposition: str
    classification: Optional[str] = None
    probabilities: Optional[Dict[str, float]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str = "Single Scan"
    brand: Optional[str] = "Unknown"

class UserUpdateRequest(BaseModel):
    """Model for user update requests"""
    username: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    full_name: Optional[str] = None
    premium: Optional[bool] = None
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None

class UserResponse(BaseModel):
    """Model for user responses"""
    id: str = Field(..., alias="_id")
    username: str
    email: str
    full_name: Optional[str] = None
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    premium: bool = False
    is_active: bool = True
    is_admin: bool = False
    
    class Config:
        allow_population_by_field_name = True
        json_encoders = {
            datetime: lambda dt: dt.isoformat() if dt else None
        }