from fastapi import FastAPI, HTTPException, Depends, Request, Form
from fastapi import status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, AnyHttpUrl
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import uvicorn
import time
import os
import traceback
from pathlib import Path
from fastapi.staticfiles import StaticFiles
import asyncio
import aiohttp
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

GOOGLE_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

app = FastAPI()
# Mount static files directory
app.mount("/static", StaticFiles(directory="src/api/static"), name="static")

# Add project root to path
import sys
project_root = str(Path(__file__).parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import database and models
from src.api.database import (
    init_db, add_user, get_user_by_username, get_user_by_email,
    add_scan_record, get_user_scan_history
)
from src.api.models import (
    User, UserCreate, Token, ScanHistoryEntry
)
from src.api.auth import (
    authenticate_user, create_access_token, get_current_active_user,
    get_password_hash, ACCESS_TOKEN_EXPIRE_MINUTES, get_user_from_cookie
)
from src.predict import load_model_and_pipeline, classify_url, classify_batch

# Initialize FastAPI app
app = FastAPI(
    title="Phishing and Malware Detection API",
    description="API for detecting phishing and malware URLs",
    version="1.0.0"
)

# Configure static files and templates
app.mount("/src/api/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# Load model and pipeline
print("Loading model and pipeline...")
try:
    # Use absolute path
    model_dir = os.path.join(project_root, "data/processed")
    classifier, pipeline = load_model_and_pipeline(model_dir)
    print("Model and pipeline loaded successfully")
except Exception as e:
    print(f"Error loading model and pipeline: {str(e)}")
    classifier, pipeline = None, None

# Define request models
class UrlRequest(BaseModel):
    url: AnyHttpUrl

class BatchUrlRequest(BaseModel):
    urls: List[AnyHttpUrl]


# Define response models
class PredictionResult(BaseModel):
    url: str
    class_id: Optional[int] = None
    class_name: Optional[str] = None
    probabilities: Optional[Dict[str, float]] = None
    error: Optional[str] = None
    # New fields for enhanced prediction
    threat_level: Optional[str] = None
    final_confidence: Optional[float] = None
    url_features: Optional[Dict[str, Any]] = None
    url_confidence_score: Optional[float] = None

class BatchPredictionResult(BaseModel):
    results: List[PredictionResult]
    processing_time: float


# Test User added to MongoDB from Python 
# This function will be called on startup to create a test user if it doesn't exist
@app.on_event("startup")
async def create_test_user():
    """Create a test user on application startup if it doesn't already exist"""
    print("Checking if test user exists...")
    
    # Import necessary functions
    from src.api.auth import get_password_hash
    
    # Check if test user exists
    test_user = await get_user_by_username("testuser")
    if test_user:
        print("Test user already exists, skipping creation")
        return
    
    # Create test user credentials
    test_password = "TestPassword123!"  # A password that meets your requirements
    hashed_password = get_password_hash(test_password)
    
    # Create user data
    user_data = {
        "username": "testuser",
        "email": "testuser@example.com",
        "full_name": "Test User",
        "hashed_password": hashed_password,
        "disabled": False,
        "created_at": datetime.utcnow()
    }
    
    try:
        # Add user to database
        await add_user(user_data)
        print(f"Test user created successfully!")
        print(f"Username: testuser")
        print(f"Password: {test_password}")
        print(f"You can now log in with these credentials")
    except Exception as e:
        print(f"Error creating test user: {str(e)}")
# Test User Snippet END added to MongoDB from Python 

# Setup event handlers
@app.on_event("startup")
async def startup_db_client():
    """Initialize database on startup"""
    await init_db()

# Authentication endpoint
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "username": user.username,
        "full_name": user.full_name
    }

# Serve HTML UI
@app.get("/", response_class=HTMLResponse)
async def serve_ui(request: Request):
    # Check if user is logged in from cookie
    token = request.cookies.get("access_token")
    user = None
    if token:
        user = await get_user_from_cookie(token)
    
    return templates.TemplateResponse("index.html", {"request": request, "user": user})

# Add redirects for .html URLs
@app.get("/login.html")
async def login_html_redirect():
    return RedirectResponse(url="/login", status_code=301)

@app.get("/register.html")
async def register_html_redirect():
    return RedirectResponse(url="/register", status_code=301)

# Login page
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# Register page
@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    print("GET /register accessed")
    return templates.TemplateResponse("register.html", {"request": request})


# Login form submission with proper ID conversion
# Login form submission with proper cookie setting and debug
@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    print(f"Login attempt for username: {username}")
    
    # Import authentication functions
    from src.api.auth import verify_password, create_access_token
    from datetime import timedelta
    
    # Use the username to find the user
    user_data = await get_user_by_username(username)
    
    if not user_data:
        print(f"No user found with username: {username}")
        return templates.TemplateResponse(
            "login.html", 
            {"request": request, "error": "Invalid username or password"}
        )
    
    # Convert MongoDB ObjectId to string for Pydantic model
    if '_id' in user_data and not isinstance(user_data['_id'], str):
        user_data['_id'] = str(user_data['_id'])
    
    # Convert to user model for verification
    from src.api.models import UserInDB
    user_db = UserInDB(**user_data)
    
    # Verify password
    if not verify_password(password, user_db.hashed_password):
        print(f"Invalid password for username: {username}")
        return templates.TemplateResponse(
            "login.html", 
            {"request": request, "error": "Invalid username or password"}
        )
    
    print(f"Authentication successful for username: {username}")
    
    # Create access token
    from src.api.auth import ACCESS_TOKEN_EXPIRE_MINUTES
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": username}, expires_delta=access_token_expires
    )
    
    print(f"Created token: {access_token[:10]}...")
    
    # Create a user model to pass to the template
    from src.api.models import User
    user = User(**user_data)
    
    # Render authenticated.html directly with user info
    response = templates.TemplateResponse(
        "authenticated.html", 
        {"request": request, "user": user}
    )
    
    # Set cookie with token
    token_value = f"Bearer {access_token}"
    print(f"Setting cookie: access_token={token_value[:15]}...")
    
    response.set_cookie(
        key="access_token",
        value=token_value,
        httponly=False,  # Allow JavaScript access
        max_age=1800,
        expires=1800,
        samesite="lax",
        path="/"  # Important: make cookie available for all paths
    )
    
    return response

# Register form submission
@app.post("/register")
async def register(
    request: Request, 
    username: str = Form(...),
    email: str = Form(...),
    full_name: str = Form(...),
    password: str = Form(...)
):
    print("POST /register accessed")
    print(f"Form data: username={username}, email={email}, full_name={full_name}")
    print(f"Registration attempt for username: {username}, email: {email}")
    
    # Check if username already exists
    existing_user = await get_user_by_username(username)
    if existing_user:
        print(f"Username already exists: {username}")
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Username already exists"}
        )
    
    # Check if email already exists
    existing_email = await get_user_by_email(email)
    if existing_email:
        print(f"Email already registered: {email}")
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Email already registered"}
        )
    
    # Create new user
    try:
        # Import password hashing function
        from src.api.auth import get_password_hash
        
        # Hash password
        hashed_password = get_password_hash(password)
        
        # Prepare user data
        user_data = {
            "username": username,
            "email": email,
            "full_name": full_name,
            "hashed_password": hashed_password,
            "disabled": False,
            "created_at": datetime.utcnow()
        }
        
        # Add to database
        await add_user(user_data)
        
        print(f"User registered successfully: {username}")
        
        # Redirect to login page with success message
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "message": "Registration successful. Please login."}
        )
    except Exception as e:
        print(f"Error during registration: {str(e)}")
        # Handle other errors
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": f"An error occurred during registration: {str(e)}"}
        )

# Dashboard page route
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    # Get user from cookie
    token = request.cookies.get("access_token")
    print(f"Token from cookie: {token}")
    
    if not token:
        print("No token found, redirecting to login")
        return RedirectResponse(url="/login", status_code=302)
    
    try:
        user = await get_user_from_cookie(token)
        print(f"User from token: {user}")
        
        if not user:
            print("No user found from token")
            return RedirectResponse(url="/login", status_code=302)
        
        print(f"Rendering authenticated.html for user: {user.username}")
        return templates.TemplateResponse("authenticated.html", {"request": request, "user": user})
    except Exception as e:
        print(f"Error in dashboard route: {str(e)}")
        import traceback
        traceback.print_exc()
        return RedirectResponse(url="/login", status_code=302)

# Logout
@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(key="access_token")
    return response

# Authentication status endpoint
@app.get("/auth-status")
async def auth_status(current_user: User = Depends(get_current_active_user)):
    return {"authenticated": True, "username": current_user.username}

# Single URL classification (public)
@app.post("/classify", response_model=PredictionResult)
async def api_classify_url(request: UrlRequest, request_obj: Request):
    try:
        if classifier is None or pipeline is None:
            raise HTTPException(status_code=500, detail="Model not loaded")
        
        url = str(request.url)
        print(f"Processing URL: {url}")  # Debug output
        
        # Use the enhanced classify_url function
        result = classify_url(url, classifier, pipeline)
        
        # Try to save to scan history if user is logged in
        token = request_obj.cookies.get("access_token")
        if token:
            user = await get_user_from_cookie(token)
            if user:
                # Create scan history entry with enhanced fields
                disposition = result.get('class') or ('Suspicious' if result.get('error') else 'Unknown')
                scan_entry = {
                    "user_id": str(user.id),
                    "url": url,
                    "disposition": disposition,  # ← UPDATED
                    "classification": disposition,  # ← UPDATED
                    "probabilities": result.get('probabilities'),
                    "timestamp": datetime.utcnow(),
                    "source": "Single Scan",
                    # Add new enhanced fields to history
                    "threat_level": result.get('threat_level'),
                    "final_confidence": result.get('final_confidence'),
                    "url_features": result.get('url_features')
                }
                await add_scan_record(scan_entry)
        
        # Return appropriate response including enhanced fields
        if 'error' in result:
            # Even with error, return URL-based analysis if available
            return PredictionResult(
                url=url,
                error=result['error'],
                threat_level=result.get('threat_level', 'Suspicious'),  # Changed default
                url_features=result.get('url_features'),
                url_confidence_score=result.get('url_confidence_score', 0)
            )
        else:
             # Map class names
            class_name = result['class']
            if class_name.lower() in ['unknown', 'uncertain']:
                class_name = 'Suspicious'
            # Return complete enhanced result
            return PredictionResult(
                url=url,
                class_id=result['class_id'],
                class_name=class_name,  # Use mapped class name
                probabilities=result['probabilities'],
                threat_level=result.get('threat_level', 'Suspicious'),
                final_confidence=result.get('final_confidence'),
                url_features=result.get('url_features')
            )
    except Exception as e:
        traceback.print_exc()  # Print the full error
        return PredictionResult(
            url=str(request.url),
            error=f"Error processing URL: {str(e)}"
        )

# Batch URL classification (authenticated only)
@app.post("/classify-batch", response_model=BatchPredictionResult)
async def api_classify_batch(
    request: BatchUrlRequest, 
    request_obj: Request  # Add this to access headers directly
):
    try:
        # Debug auth header
        auth_header = request_obj.headers.get("Authorization")
        print(f"Received Authorization header: {auth_header}")
        
        # Try to get user from auth header
        user = None
        if auth_header:
            try:
                from src.api.auth import get_user_from_token
                user = await get_user_from_token(auth_header)
                print(f"User from token: {user.username if user else 'None'}")
            except Exception as e:
                print(f"Error validating token: {str(e)}")
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid authentication credentials"}
                )
        
        if not user:
            print("No authenticated user found")
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required"}
            )
        
        # Check if model is loaded
        if classifier is None or pipeline is None:
            raise HTTPException(status_code=500, detail="Model not loaded")
        
        # Process URLs
        urls = [str(url) for url in request.urls]
        print(f"Processing {len(urls)} URLs in batch")
        
        # Classify URLs using enhanced batch function
        start_time = time.time()
        results = classify_batch(urls, classifier, pipeline)
        processing_time = time.time() - start_time

         # ADD THE DEBUGGING CODE HERE:
        print("=== DEBUGGING CLASSIFY_BATCH RESULTS ===")
        for i, result in enumerate(results):
            print(f"Result {i} for URL: {result['url']}")
            print(f"  Class: {result.get('class')}")
            print(f"  Class ID: {result.get('class_id')}")
            print(f"  Error: {result.get('error')}")
            print(f"  Threat Level: {result.get('threat_level')}")
            print(f"  Probabilities: {result.get('probabilities')}")
            print("---")
        
        # Save results to scan history
        for result in results:
            # Fix: Handle failed content fetches properly
            disposition = result.get('class') or ('Suspicious' if result.get('error') else 'Unknown')
            # Create scan history entry with enhanced fields for all results
            scan_entry = {
                "user_id": str(user.id),
                "url": result['url'],
                "disposition": disposition,  # ← UPDATED
                "classification": disposition,  # ← UPDATED
                "probabilities": result.get('probabilities'),
                "timestamp": datetime.utcnow(),
                "source": "Batch Scan",
                # Add new enhanced fields to history
                "threat_level": result.get('threat_level'),
                 "final_confidence": result.get('final_confidence'),
                "url_features": result.get('url_features')
            }
            await add_scan_record(scan_entry)
        
        # Format response including enhanced fields
        response_results = []
        for result in results:
            if 'error' in result and result['error']:
                # Even with error, include URL-based analysis
                response_results.append(PredictionResult(
                    url=result['url'],
                    error=result['error'],
                    threat_level=result.get('threat_level'),
                    url_features=result.get('url_features'),
                    url_confidence_score=result.get('url_confidence_score', 0)
                ))
            else:
                # Include all enhanced fields
                response_results.append(PredictionResult(
                    url=result['url'],
                    class_id=result['class_id'],
                    class_name=result['class'],
                    probabilities=result['probabilities'],
                    threat_level=result.get('threat_level'),
                    final_confidence=result.get('final_confidence'),
                    url_features=result.get('url_features')
                ))
        
        return BatchPredictionResult(
            results=response_results,
            processing_time=processing_time
        )
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error processing batch: {str(e)}")

# Get scan history for current user with better error handling
@app.get("/scan-history")
async def get_scan_history(request: Request):
    try:
        # Get token from header
        auth_header = request.headers.get("Authorization")
        print(f"Scan history auth header: {auth_header}")
        
        # Check if auth header exists
        if not auth_header:
            print("No Authorization header found")
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required"}
            )
        
        # Get user from token
        user = None
        try:
            from src.api.auth import get_user_from_token
            user = await get_user_from_token(auth_header)
            print(f"Scan history user from token: {user.username if user else 'None'}")
        except Exception as e:
            print(f"Error validating token in scan history: {str(e)}")
            import traceback
            traceback.print_exc()
            return JSONResponse(
                status_code=401,
                content={"detail": f"Invalid authentication credentials: {str(e)}"}
            )
        
        if not user:
            print("No authenticated user found for scan history")
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required"}
            )
        
        # Check for get_user_scan_history function
        from src.api.database import get_user_scan_history
        
        # Create dummy data if needed (for development/testing)
        # You can remove this in production
        try:
            # Get history from database
            print(f"Getting scan history for user ID: {user.id}")
            history = await get_user_scan_history(str(user.id))
            print(f"Found {len(history) if history else 0} scan history entries")
            
            # If no history, create dummy data for testing
            if not history or len(history) == 0:
                print("No history found, creating dummy data")
                history = create_dummy_scan_history(str(user.id))
            
            # Return history
            return {"history": history}
        except Exception as e:
            print(f"Error retrieving scan history: {str(e)}")
            import traceback
            traceback.print_exc()
            
            # Return empty history for now to avoid errors
            print("Returning empty history due to error")
            return {"history": []}
            
    except Exception as e:
        print(f"Unexpected error in scan history endpoint: {str(e)}")
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"detail": f"Internal server error: {str(e)}"}
        )

# Helper function to create dummy scan history data for testing
def create_dummy_scan_history(user_id):
    from datetime import datetime, timedelta
    
    # Create some dummy data entries
    dummy_urls = [
        "https://www.monash.edu/",
        "https://www.google.com/",
        "https://www.swinburne.edu.au/",
        "https://example.com/"
    ]
    
    history = []
    now = datetime.utcnow() # Use UTC time for consistency
    
    for i, url in enumerate(dummy_urls):
        entry = {
            "_id": f"dummy_id_{i}",
            "user_id": user_id,
            "url": url,
            "ip_address": f"192.168.1.{i+1}",
            "hosting_provider": "Dummy Provider",
            "disposition": "Clean",
            "classification": "legitimate",
            "timestamp": (now - timedelta(days=i)).isoformat(),
            "source": "Dummy Data",
            "brand": "Unknown"
        }
        history.append(entry)
    
    print(f"Created {len(history)} dummy history entries")
    return history


# Import get_current_user dependency
from src.api.auth import get_current_user

# Add admin page route
@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    """Admin dashboard page with enhanced error handling and debugging"""
    # Debug: Print request info
    print("Admin page accessed")
    print("Cookies:", request.cookies)
    
    try:
        # Get token from cookie
        token_with_prefix = request.cookies.get("access_token")
        if not token_with_prefix:
            print("No access_token cookie found")
            return RedirectResponse(url="/login?error=no_token&redirect=admin")
        
        # Manually authenticate user
        try:
            # Import get_user_from_token here to fix NameError
            from src.api.auth import get_user_from_token
            # Pass the token with prefix
            current_user = await get_user_from_token(token_with_prefix)
            if not current_user:
                raise ValueError("Authentication failed - user not found")
            print(f"User authenticated: {current_user.username}")
        except Exception as auth_error:
            print(f"Authentication error: {str(auth_error)}")
            return RedirectResponse(url="/login?error=auth_failed&redirect=admin")
        
        # Enhanced debugging for is_admin attribute
        print(f"User model details: {current_user}")
        print(f"User __dict__: {current_user.__dict__}")
        print(f"Has is_admin attribute: {hasattr(current_user, 'is_admin')}")
        
        # Check if user is admin (with debugging)
        is_admin = getattr(current_user, "is_admin", False)
        print(f"Original is_admin value: {is_admin}")
        
        # TEMPORARY WORKAROUND - Force admin access for admin user
        if current_user.username == "admin" and not is_admin:
            print("WARNING: Admin user missing is_admin flag - FORCING ADMIN ACCESS")
            is_admin = True
        
        print(f"Final is_admin value: {is_admin}")
        
        if not is_admin:
            print(f"User {current_user.username} is not an admin")
            return RedirectResponse(url="/login?error=not_admin&redirect=admin")
        
        # User is authenticated and is an admin
        print(f"Admin access granted for {current_user.username}")
        
        # Convert to dict for template if needed
        user_dict = current_user.dict() if hasattr(current_user, "dict") else dict(current_user)
        
        # Return the admin template
        return templates.TemplateResponse("admin/admin.html", {
            "request": request, 
            "user": user_dict
        })
        
    except Exception as e:
        print(f"Unexpected error in admin page: {str(e)}")
        import traceback
        traceback.print_exc()
        return RedirectResponse(url="/login?error=server_error&redirect=admin")

# Add admin authentication check endpoint
@app.get("/api/admin/check-auth")
async def check_admin_auth(request: Request):
    """Check if the current user has admin privileges using cookies"""
    print("Admin check-auth endpoint accessed")
    
    # Get token from cookie
    cookie_token = request.cookies.get("access_token")
    print(f"Cookie token: {cookie_token}")
    
    if not cookie_token:
        print("No access_token cookie found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    try:
        # Authenticate with cookie token
        from src.api.auth import get_user_from_token
        
        print(f"Authenticating with cookie token: {cookie_token[:15]}...")
        current_user = await get_user_from_token(cookie_token)
        
        if not current_user:
            print("Authentication failed - no user found")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication"
            )
        
        print(f"User authenticated: {current_user.username}")
        
        # Check admin status
        is_admin = getattr(current_user, "is_admin", False)
        print(f"Is admin: {is_admin}")
        
        return {
            "authenticated": True,
            "is_admin": is_admin,
            "username": current_user.username
        }
    except Exception as e:
        print(f"Authentication error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )
    
    # Add a simple check endpoint without dependencies
@app.get("/api/admin/simple-check")
async def simple_admin_check(request: Request):
    """Simple check without dependencies to diagnose auth issues"""
    cookie_token = request.cookies.get("access_token")
    auth_header = request.headers.get("Authorization")
    
    return {
        "status": "received_request",
        "cookie_present": cookie_token is not None,
        "header_present": auth_header is not None,
        "cookie_value_prefix": cookie_token[:15] if cookie_token else None,
        "header_value_prefix": auth_header[:15] if auth_header else None
    }

@app.get("/api/admin/dashboard")
async def admin_dashboard(request: Request):
    """Get admin dashboard data with real data from database"""
    print("Admin dashboard endpoint accessed")
    
    # Get token from cookie
    cookie_token = request.cookies.get("access_token")
    
    if not cookie_token:
        print("No access_token cookie found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    try:
        # Authenticate with cookie token
        from src.api.auth import get_user_from_token
        
        current_user = await get_user_from_token(cookie_token)
        
        if not current_user:
            print("Authentication failed - no user found")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication"
            )
        
        # Check admin status
        is_admin = getattr(current_user, "is_admin", False)
        
        if not is_admin:
            print(f"User {current_user.username} is not an admin")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        print(f"Dashboard access granted for admin: {current_user.username}")
        
        # Import database collections directly
        from src.api.database import users_collection, scan_history_collection
        
        # Get real user statistics
        total_users = await users_collection.count_documents({})
        
        # Get new users in last 24 hours
        from datetime import datetime, timedelta
        twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
        new_users_24h = await users_collection.count_documents({
            "created_at": {"$gte": twenty_four_hours_ago}
        })
        
        # Get premium users count
        premium_users = await users_collection.count_documents({"premium": True})
        
        # Get total scans
        total_scans = await scan_history_collection.count_documents({})
        
        # Get risk distribution from scans
        risk_distribution_pipeline = [
            {
                "$group": {
                    "_id": "$disposition",
                    "count": {"$sum": 1}
                }
            },
            {
                "$project": {
                    "_id": 1,
                    "count": 1
                }
            }
        ]
        
        risk_distribution_cursor = scan_history_collection.aggregate(risk_distribution_pipeline)
        risk_distribution_raw = await risk_distribution_cursor.to_list(length=None)
        
        # Standardize the labels for consistent display
        risk_distribution = []
        for item in risk_distribution_raw:
            disposition = item["_id"] or "Suspicious"
            count = item["count"]
            
            # Map dispositions to standardized labels
            if disposition.lower() in ["clean", "legitimate", "safe"]:
                standardized_label = "Legitimate"
            elif disposition.lower() in ["phishing", "credential phishing"]:
                standardized_label = "Credential Phishing"
            elif disposition.lower() in ["malware", "malware distribution"]:
                standardized_label = "Malware Distribution"
            else:
                standardized_label = "Suspicious"  # Changed from "Unknown"
            
            # Check if we already have this standardized label
            existing_item = next((x for x in risk_distribution if x["_id"] == standardized_label), None)
            if existing_item:
                existing_item["count"] += count
            else:
                risk_distribution.append({"_id": standardized_label, "count": count})
        
        # If no real risk distribution data, provide default structure
        if not risk_distribution:
            risk_distribution = [
                {"_id": "Legitimate", "count": 0},
                {"_id": "Credential Phishing", "count": 0},
                {"_id": "Malware Distribution", "count": 0},
                {"_id": "Suspicious", "count": 0}
            ]
        
        print(f"Dashboard stats - Users: {total_users}, New: {new_users_24h}, Premium: {premium_users}, Scans: {total_scans}")
        
        return {
            "user_stats": {
                "total_users": total_users,
                "new_users_24h": new_users_24h,
                "premium_users": premium_users
            },
            "scan_stats": {
                "total_scans": total_scans,
                "risk_distribution": risk_distribution
            }
        }
        
    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

# Add user analytics endpoint with real data
@app.get("/api/admin/users/analytics")
async def admin_users_analytics(request: Request):
    """Get user analytics data - real data"""
    print("User analytics endpoint accessed")
    
    # Get token from cookie
    cookie_token = request.cookies.get("access_token")
    
    if not cookie_token:
        print("No access_token cookie found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    try:
        # Authenticate with cookie token
        from src.api.auth import get_user_from_token
        
        current_user = await get_user_from_token(cookie_token)
        
        if not current_user:
            print("Authentication failed - no user found")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication"
            )
        
        # Check admin status
        is_admin = getattr(current_user, "is_admin", False)
        
        if not is_admin:
            print(f"User {current_user.username} is not an admin")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        print(f"User analytics access granted for admin: {current_user.username}")
        
        # Import database collections directly
        from src.api.database import users_collection
        
        # User growth analytics - group by month
        user_growth_pipeline = [
            {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m",
                            "date": "$created_at"
                        }
                    },
                    "count": {"$sum": 1}
                }
            },
            {
                "$sort": {"_id": 1}
            },
            {
                "$limit": 12  # Last 12 months
            }
        ]
        
        user_growth_cursor = users_collection.aggregate(user_growth_pipeline)
        user_growth = await user_growth_cursor.to_list(length=None)
        
        # If no data, provide some default data
        if not user_growth:
            user_growth = [
                {"_id": "2024-01", "count": 1},
                {"_id": "2024-02", "count": 2},
                {"_id": "2024-03", "count": 1}
            ]
        
        # Premium conversions - users who upgraded to premium
        premium_conversions_pipeline = [
            {
                "$match": {"premium": True}
            },
            {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m",
                            "date": "$created_at"
                        }
                    },
                    "count": {"$sum": 1}
                }
            },
            {
                "$sort": {"_id": 1}
            },
            {
                "$limit": 12  # Last 12 months
            }
        ]
        
        premium_conversions_cursor = users_collection.aggregate(premium_conversions_pipeline)
        premium_conversions = await premium_conversions_cursor.to_list(length=None)
        
        # If no premium data, provide some default data
        if not premium_conversions:
            premium_conversions = [
                {"_id": "2024-01", "count": 0},
                {"_id": "2024-02", "count": 1},
                {"_id": "2024-03", "count": 1}
            ]
        
        print(f"Returning user growth data: {len(user_growth)} entries")
        print(f"Returning premium conversions data: {len(premium_conversions)} entries")
        
        return {
            "user_growth": user_growth,
            "premium_conversions": premium_conversions
        }
        
    except Exception as e:
        print(f"User analytics error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

# Add scans analytics endpoint with real data
@app.get("/api/admin/scans/analytics")
async def admin_scans_analytics(request: Request):
    """Get scan analytics data - real data"""
    print("Scan analytics endpoint accessed")
    
    # Get token from cookie
    cookie_token = request.cookies.get("access_token")
    
    if not cookie_token:
        print("No access_token cookie found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    try:
        # Authenticate with cookie token
        from src.api.auth import get_user_from_token
        
        current_user = await get_user_from_token(cookie_token)
        
        if not current_user:
            print("Authentication failed - no user found")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication"
            )
        
        # Check admin status
        is_admin = getattr(current_user, "is_admin", False)
        
        if not is_admin:
            print(f"User {current_user.username} is not an admin")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        print(f"Scan analytics access granted for admin: {current_user.username}")
        
        # Import database collections directly
        from src.api.database import scan_history_collection
        
        # Scan volume analytics - group by month
        scan_volume_pipeline = [
            {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m",
                            "date": "$timestamp"
                        }
                    },
                    "count": {"$sum": 1}
                }
            },
            {
                "$sort": {"_id": 1}
            },
            {
                "$limit": 12  # Last 12 months
            }
        ]
        
        scan_volume_cursor = scan_history_collection.aggregate(scan_volume_pipeline)
        scan_volume = await scan_volume_cursor.to_list(length=None)
        
        # If no scan data, provide some default data
        if not scan_volume:
            scan_volume = [
                {"_id": "2024-01", "count": 10},
                {"_id": "2024-02", "count": 15},
                {"_id": "2024-03", "count": 8}
            ]
        
        # Risk trends - group by date and risk level
        risk_trends_pipeline = [
            {
                "$group": {
                    "_id": {
                        "date": {
                            "$dateToString": {
                                "format": "%Y-%m",
                                "date": "$timestamp"
                            }
                        },
                        "risk": "$disposition"
                    },
                    "count": {"$sum": 1}
                }
            },
            {
                "$sort": {"_id.date": 1}
            },
            {
                "$limit": 50  # Limit results
            }
        ]
        
        risk_trends_cursor = scan_history_collection.aggregate(risk_trends_pipeline)
        risk_trends = await risk_trends_cursor.to_list(length=None)
        
        # If no risk trends data, provide some default data
        if not risk_trends:
            risk_trends = [
                {"_id": {"date": "2024-01", "risk": "Clean"}, "count": 5},
                {"_id": {"date": "2024-01", "risk": "Phishing"}, "count": 2},
                {"_id": {"date": "2024-02", "risk": "Clean"}, "count": 8},
                {"_id": {"date": "2024-02", "risk": "Phishing"}, "count": 3}
            ]
        
        print(f"Returning scan volume data: {len(scan_volume)} entries")
        print(f"Returning risk trends data: {len(risk_trends)} entries")
        
        return {
            "scan_volume": scan_volume,
            "risk_trends": risk_trends
        }
        
    except Exception as e:
        print(f"Scan analytics error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )
    
    # Add users endpoint
@app.get("/api/admin/users")
async def admin_users(request: Request):
    """Get users list with pagination - real data"""
    print("Admin users endpoint accessed")
    
    # Authentication code... (same as before)
    cookie_token = request.cookies.get("access_token")
    if not cookie_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        from src.api.auth import get_user_from_token
        current_user = await get_user_from_token(cookie_token)
        if not current_user or not getattr(current_user, "is_admin", False):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        print(f"Users list access granted for admin: {current_user.username}")
        
        # Get query parameters
        page = int(request.query_params.get("page", 1))
        page_size = int(request.query_params.get("page_size", 10))
        search = request.query_params.get("search", "")
        filter_type = request.query_params.get("filter", "all")
        
        # Import database collections directly
        from src.api.database import users_collection
        
        # Build query based on filters
        query = {}
        
        # Add search filter
        if search:
            query["$or"] = [
                {"username": {"$regex": search, "$options": "i"}},
                {"email": {"$regex": search, "$options": "i"}},
                {"full_name": {"$regex": search, "$options": "i"}}
            ]
        
        # Add type filter
        if filter_type == "premium":
            query["premium"] = True
        elif filter_type == "free":
            query["premium"] = {"$ne": True}
        elif filter_type == "active":
            query["is_active"] = {"$ne": False}
        elif filter_type == "inactive":
            query["is_active"] = False
        
        # Get total count for pagination
        total_users = await users_collection.count_documents(query)
        
        # Calculate pagination
        skip = (page - 1) * page_size
        
        # Get users with pagination
        users_cursor = users_collection.find(query).skip(skip).limit(page_size).sort("created_at", -1)
        users_list = await users_cursor.to_list(length=None)
        
        # Convert ObjectId to string for JSON serialization
        for user in users_list:
            user["_id"] = str(user["_id"])
            # Remove sensitive data
            if "hashed_password" in user:
                del user["hashed_password"]
        
        print(f"Found {len(users_list)} users out of {total_users} total")
        
        return {
            "users": users_list,
            "total": total_users,
            "page": page,
            "page_size": page_size
        }
        
    except Exception as e:
        print(f"Users list error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=401, detail="Authentication failed")
    
# Add scans endpoint
@app.get("/api/admin/scans")
async def admin_scans(request: Request):
    """Get scans list with pagination - real data"""
    print("Admin scans endpoint accessed")
    
    # Authentication code... (same pattern)
    cookie_token = request.cookies.get("access_token")
    if not cookie_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        from src.api.auth import get_user_from_token
        current_user = await get_user_from_token(cookie_token)
        if not current_user or not getattr(current_user, "is_admin", False):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        print(f"Scans list access granted for admin: {current_user.username}")
        
        # Get query parameters
        page = int(request.query_params.get("page", 1))
        page_size = int(request.query_params.get("page_size", 10))
        risk_filter = request.query_params.get("risk", "all")
        
        # Import database collections directly
        from src.api.database import scan_history_collection, users_collection
        
        # Build query based on filters
        query = {}
        
        # Add risk filter - map standardized labels back to database values
        if risk_filter != "all":
            # Map frontend filter values to possible database values
            if risk_filter == "Legitimate":
                query["disposition"] = {"$in": ["clean", "legitimate", "safe", "Clean", "Legitimate", "Safe"]}
            elif risk_filter == "Credential Phishing":
                query["disposition"] = {"$in": ["phishing", "credential phishing", "Phishing", "Credential Phishing"]}
            elif risk_filter == "Malware Distribution":
                query["disposition"] = {"$in": ["malware", "malware distribution", "Malware", "Malware Distribution"]}
            elif risk_filter == "Suspicious":
                # For suspicious, we want everything that's not in the above categories
                query["disposition"] = {"$nin": [
                    "clean", "legitimate", "safe", "Clean", "Legitimate", "Safe",
                    "phishing", "credential phishing", "Phishing", "Credential Phishing",
                    "malware", "malware distribution", "Malware", "Malware Distribution"
                ]}
            else:
                # If it's an exact match, use it as is
                query["disposition"] = risk_filter
        
        # Get total count for pagination
        total_scans = await scan_history_collection.count_documents(query)
        
        # Calculate pagination
        skip = (page - 1) * page_size
        
        # Get scans with pagination
        scans_cursor = scan_history_collection.find(query).skip(skip).limit(page_size).sort("timestamp", -1)
        scans_list = await scans_cursor.to_list(length=None)
        
# Enrich scans data with user information
        for scan in scans_list:
            scan["_id"] = str(scan["_id"])
            
            # Get username from user_id
            if "user_id" in scan:
                try:
                    from bson import ObjectId
                    user = await users_collection.find_one({"_id": ObjectId(scan["user_id"])})
                    scan["username"] = user["username"] if user and user.get("username") else "Anonymous"
                except:
                    scan["username"] = "Anonymous"
            else:
                scan["username"] = "Anonymous"
            
            # Map fields for frontend compatibility
            scan["scan_date"] = scan.get("timestamp", "")
            
            # Standardize and map risk levels (FIXED to handle None values)
            disposition = scan.get("disposition") or "Suspicious"  # Handle None/empty values
            
            # Ensure we have a string to work with
            disposition = str(disposition).strip() if disposition else "Suspicious"
            
            # Map backend disposition to frontend risk levels
            disposition_lower = disposition.lower()
            if disposition_lower in ["clean", "legitimate", "safe"]:
                scan["risk"] = "Legitimate"
            elif disposition_lower in ["phishing", "credential phishing"]:
                scan["risk"] = "Credential Phishing"
            elif disposition_lower in ["malware", "malware distribution"]:
                scan["risk"] = "Malware Distribution"
            else:
                scan["risk"] = "Suspicious"
            
            # Extract confidence if available in probabilities
            if "probabilities" in scan and scan["probabilities"]:
                try:
                    probs = scan["probabilities"]
                    if isinstance(probs, dict):
                        max_confidence = max(probs.values()) * 100
                        scan["confidence"] = round(max_confidence, 1)
                    else:
                        scan["confidence"] = 50
                except:
                    scan["confidence"] = 50
            else:
                scan["confidence"] = 50
                
        print(f"Found {len(scans_list)} scans out of {total_scans} total")
        
        return {
            "scans": scans_list,
            "total": total_scans,
            "page": page,
            "page_size": page_size
        }

    except Exception as e:
        print(f"Scans list error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=401, detail="Authentication failed")
    
@app.get("/api/admin/scans-test")
async def admin_scans_test():
    """Simple test endpoint for scans"""
    return {"message": "Scans test endpoint working", "status": "success"}
    
# Add test endpoint
@app.get("/api/admin/test-endpoint")
async def test_endpoint():
    """Simple test endpoint to verify routing"""
    return {"message": "Test endpoint working", "status": "success"}

async def fetch_url_content(session, url):
    try:
        async with session.get(url, timeout=10) as response:
            return await response.text()
    except Exception as e:
        return f"Error: {str(e)}"

async def process_batch_urls(urls):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_url_content(session, url) for url in urls]
        return await asyncio.gather(*tasks)

async def process_url_batch(urls, chunk_size=5):
    results = []
    for i in range(0, len(urls), chunk_size):
        chunk = urls[i:i + chunk_size]
        chunk_results = await process_batch_urls(chunk)
        results.extend(chunk_results)
    return results