"""
Authentication utilities for the Phishing Detector API
"""
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from src.api.models import User, TokenData, UserInDB
from src.api.database import get_user_by_username, update_user

# Security configuration
SECRET_KEY = "sddY@skQs`_E'#&q07G3K{%C-A)*YdVbuSe~!a{eVU-V)8:>Lf"  # Change this to a secure random key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash"""
    # bcrypt has a 72-byte limit, truncate if necessary
    plain_password = plain_password[:72]
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate a password hash"""
    # bcrypt has a 72-byte limit, truncate if necessary
    password = password[:72]
    return pwd_context.hash(password)


async def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """Authenticate a user by username and password"""
    user = await get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    
    # Update last login time
    await update_user(str(user["_id"]), {"last_login": datetime.utcnow()})
    
    # Convert to UserInDB model
    return UserInDB(**user)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Get the current user from a JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    user = await get_user_by_username(token_data.username)
    if user is None:
        raise credentials_exception
    
    return User(**user)


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Get the current active user"""
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def get_current_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Dependency to verify the user has admin privileges
    Raises HTTP 403 if the user is not an admin
    """
    # Check if the user has the is_admin flag set to True
    if not getattr(current_user, "is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions: admin access required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Log admin action for audit purposes
    print(f"Admin action by user: {current_user.username} (ID: {current_user.id})")
    
    return current_user


# Function to extract user from token in cookie (for templates)
async def get_user_from_cookie(cookie_token: str) -> Optional[User]:
    """Extract user from token cookie"""
    print(f"Processing cookie token: {cookie_token}")
    
    if not cookie_token or not cookie_token.startswith("Bearer "):
        print("Invalid token format")
        return None
    
    try:
        token = cookie_token.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        
        print(f"Username from token: {username}")
        
        if not username:
            return None
        
        user_data = await get_user_by_username(username)
        
        print(f"User data: {user_data}")
        
        if not user_data:
            return None
        
        # Properly convert ObjectId to string
        if '_id' in user_data and not isinstance(user_data['_id'], str):
            user_data['_id'] = str(user_data['_id'])
        
        # Convert the full dict to a User model
        try:
            user = User(**user_data)
            print(f"Successfully created User model for {user.username}")
            return user
        except Exception as validation_error:
            print(f"Error creating User model: {validation_error}")
            print(f"user_data keys: {user_data.keys()}")
            print(f"user_data _id type: {type(user_data.get('_id'))}")
            return None
            
    except Exception as e:
        print(f"Error extracting user from cookie: {str(e)}")
        import traceback
        traceback.print_exc()
        return None
    
async def get_user_from_token(token: str):
    """Extract user from auth header token"""
    print(f"get_user_from_token called with token: {token[:15]}...")
    
    
    # Remove any quotes from the token
    if token and token.startswith('"') and token.endswith('"'):
        token = token[1:-1]  # Remove surrounding quotes
        print(f"Removed quotes from token: {token[:15]}...")
    
    if not token or not token.startswith("Bearer "):
        print("Token does not start with 'Bearer '")
        return None
    
    try:
        token_value = token.split(" ")[1]
        print(f"Extracted token value: {token_value[:10]}...")
        
        payload = jwt.decode(token_value, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"Token payload: {payload}")
        
        username = payload.get("sub")
        print(f"Username from token: {username}")
        
        if not username:
            print("No username in token payload")
            return None
        
        print(f"Looking up user by username: {username}")
        user_data = await get_user_by_username(username)
        print(f"User lookup result: {user_data is not None}")
        
        if not user_data:
            print(f"No user found with username: {username}")
            return None
        
        # Convert ObjectId to string
        if '_id' in user_data and not isinstance(user_data['_id'], str):
            user_data['_id'] = str(user_data['_id'])
            print("Converted ObjectId to string")
        
        print("Creating User model from user_data")
        print(f"User data before User creation: {user_data}")
        print(f"User data contains is_admin: {'is_admin' in user_data}")
        print(f"User data is_admin value: {user_data.get('is_admin')}")
        from src.api.models import User
        user = User(**user_data)
        print(f"Created User model with username: {user.username}, id: {user.id}")
        
        return user
    except Exception as e:
        print(f"Exception in get_user_from_token: {str(e)}")
        import traceback
        traceback.print_exc()
        return None
    
    # =====================================================================
# New admin authentication dependency 
# =====================================================================

async def get_current_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Dependency to verify the user has admin privileges
    Raises HTTP 403 if the user is not an admin
    """
    # Check if the user has the is_admin flag set to True
    if not getattr(current_user, "is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions: admin access required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Log admin action for audit purposes
    print(f"Admin action by user: {current_user.username} (ID: {current_user.id})")
    
    return current_user

# Add this function to your auth.py file
async def create_admin_user():
    """
    Create an admin user if one doesn't exist yet
    This function should be called during application startup
    """
    from src.api.database import users_collection
    
    # Check if any admin user already exists
    admin_user = await users_collection.find_one({"is_admin": True})
    
    if not admin_user:
        print("No admin user found. Creating default admin user...")
        
        # Create admin user with secure password
        # IMPORTANT: Change this password in production!
        admin_password = os.getenv("ADMIN_PASSWORD", "PhishR@admin2025")  # Use env var or default
        hashed_password = get_password_hash(admin_password)
        
        admin_user_data = {
            "username": "admin",
            "email": "admin@phishr.com",
            "full_name": "PhishR Admin",
            "hashed_password": hashed_password,
            "created_at": datetime.utcnow(),
            "last_login": None,
            "premium": True,
            "is_active": True,
            "is_admin": True,
            "disabled": False  # Match your User model field
        }
        
        try:
            # Insert the admin user into the database
            result = await users_collection.insert_one(admin_user_data)
            
            if result.inserted_id:
                print(f"Default admin user created with ID: {result.inserted_id}")
                print(f"Username: admin | Initial password: {admin_password}")
                print("IMPORTANT: Change this password after first login!")
            else:
                print("Failed to create admin user")
        except Exception as e:
            print(f"Error creating admin user: {str(e)}")
    else:
        print("Admin user already exists - ID:", admin_user.get("_id"))

        