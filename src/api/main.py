from fastapi import FastAPI, HTTPException, Depends, Request, Form
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
                scan_entry = {
                    "user_id": str(user.id),
                    "url": url,
                    "disposition": result.get('class', 'Unknown'),
                    "classification": result.get('class', 'Unknown'),
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
                threat_level=result.get('threat_level'),
                url_features=result.get('url_features'),
                url_confidence_score=result.get('url_confidence_score', 0)
            )
        else:
            # Return complete enhanced result
            return PredictionResult(
                url=url,
                class_id=result['class_id'],
                class_name=result['class'],
                probabilities=result['probabilities'],
                threat_level=result.get('threat_level'),
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
        
        # Save results to scan history
        for result in results:
            # Create scan history entry with enhanced fields for all results
            scan_entry = {
                "user_id": str(user.id),
                "url": result['url'],
                "disposition": result.get('class', 'Unknown'),
                "classification": result.get('class', 'Unknown'),
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
    now = datetime.utcnow()
    
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

# Import the admin router
from .admin import router as admin_router

# Add the admin router to the app
app.include_router(admin_router, prefix="/api")

# Import get_current_user dependency
from src.api.auth import get_current_user

# Add admin page route
@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request, current_user: dict = Depends(get_current_user)):
    """Admin dashboard page"""
    # Check if user is admin
    if not current_user.get("is_admin", False):
        return RedirectResponse(url="/login?error=unauthorized")
    
    return templates.TemplateResponse("admin/admin.html", {"request": request, "user": current_user})

# Add admin authentication check endpoint
@app.get("/api/admin/check-auth")
async def check_admin_auth(current_user: dict = Depends(get_current_user)):
    """Check if the current user has admin privileges"""
    is_admin = current_user.get("is_admin", False)
    return {"authenticated": True, "is_admin": is_admin}