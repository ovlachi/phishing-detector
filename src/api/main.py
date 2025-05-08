from fastapi import FastAPI, HTTPException, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, AnyHttpUrl
from datetime import datetime, timedelta
from typing import List, Optional, Dict
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

class BatchPredictionResult(BaseModel):
    results: List[PredictionResult]
    processing_time: float

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
    return templates.TemplateResponse("register.html", {"request": request})


# Login form submission for email-based authentication
@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    print(f"Login attempt for username: {username}")
    
    # Import authentication functions
    from src.api.auth import verify_password
    
    # Use the username to find the user
    user_data = await get_user_by_username(username)
    
    if not user_data:
        print(f"No user found with username: {username}")
        return templates.TemplateResponse(
            "login.html", 
            {"request": request, "error": "Invalid username or password"}
        )
    
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
    
    # Create a user model to pass to the template
    from src.api.models import User
    user = User(**user_data)
    
    # Render authenticated.html directly with user info
    return templates.TemplateResponse(
        "authenticated.html", 
        {"request": request, "user": user}
    )

# Register form submission
# Register form submission
@app.post("/register")
async def register(
    request: Request, 
    username: str = Form(...),
    email: str = Form(...),
    full_name: str = Form(...),
    password: str = Form(...)
):
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

# Dashboard page
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    # Get user from cookie
    token = request.cookies.get("access_token")
    
    print(f"Token from cookie: {token}")  # Add this debug line
    
    if not token:
        print("No token found in cookies")  # Add this debug line
        return RedirectResponse(url="/login", status_code=302)
    
    try:
        user = await get_user_from_cookie(token)
        
        print(f"User from token: {user}")  # Add this debug line
        
        if not user:
            print("No user found from token")  # Add this debug line
            return RedirectResponse(url="/login", status_code=302)
        
        return templates.TemplateResponse("authenticated.html", {"request": request, "user": user})
    except Exception as e:
        print(f"Authentication error: {str(e)}")  # Add this debug line
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
        
        result = classify_url(url, classifier, pipeline)
        
        # Try to save to scan history if user is logged in
        token = request_obj.cookies.get("access_token")
        if token:
            user = await get_user_from_cookie(token)
            if user and 'error' not in result:
                # Create scan history entry
                scan_entry = {
                    "user_id": str(user.id),
                    "url": url,
                    "disposition": result.get('class', 'Unknown'),
                    "classification": result.get('class', 'Unknown'),
                    "probabilities": result.get('probabilities'),
                    "timestamp": datetime.utcnow(),
                    "source": "Single Scan"
                }
                await add_scan_record(scan_entry)
        
        if 'error' in result:
            return PredictionResult(
                url=url,
                error=result['error']
            )
        else:
            return PredictionResult(
                url=url,
                class_id=result['class_id'],
                class_name=result['class'],
                probabilities=result['probabilities']
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
    current_user: User = Depends(get_current_active_user)
):
    try:
        if classifier is None or pipeline is None:
            raise HTTPException(status_code=500, detail="Model not loaded")
        
        urls = [str(url) for url in request.urls]
        
        start_time = time.time()
        results = classify_batch(urls, classifier, pipeline)
        processing_time = time.time() - start_time
        
        # Save results to scan history
        for result in results:
            if 'error' not in result:
                # Create scan history entry
                scan_entry = {
                    "user_id": str(current_user.id),
                    "url": result['url'],
                    "disposition": result.get('class', 'Unknown'),
                    "classification": result.get('class', 'Unknown'),
                    "probabilities": result.get('probabilities'),
                    "timestamp": datetime.utcnow(),
                    "source": "Batch Scan"
                }
                await add_scan_record(scan_entry)
        
        response_results = []
        for result in results:
            if 'error' in result and result['error']:
                response_results.append(PredictionResult(
                    url=result['url'],
                    error=result['error']
                ))
            else:
                response_results.append(PredictionResult(
                    url=result['url'],
                    class_id=result['class_id'],
                    class_name=result['class'],
                    probabilities=result['probabilities']
                ))
        
        return BatchPredictionResult(
            results=response_results,
            processing_time=processing_time
        )
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error processing batch: {str(e)}")

# Get scan history for current user
@app.get("/scan-history")
async def get_scan_history(current_user: User = Depends(get_current_active_user)):
    try:
        # Get history from database
        history = await get_user_scan_history(str(current_user.id))
        return {"history": history}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving scan history: {str(e)}")

# User info endpoint
@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)


    