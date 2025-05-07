from fastapi import FastAPI, HTTPException, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, AnyHttpUrl
from datetime import timedelta
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

from src.api.auth import (
    Token, User, authenticate_user, create_access_token, 
    get_current_active_user, ACCESS_TOKEN_EXPIRE_MINUTES, fake_users_db,
    get_password_hash
)
from src.predict import load_model_and_pipeline, classify_url, classify_batch

# Initialize FastAPI app
app = FastAPI(
    title="Phishing and Malware Detection API",
    description="API for detecting phishing and malware URLs",
    version="1.0.0"
)

# Configure static files and templates
# Updated static files path to match the path used in HTML files
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

# Authentication endpoint
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
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
    return {"access_token": access_token, "token_type": "bearer"}

# Serve HTML UI
@app.get("/", response_class=HTMLResponse)
async def serve_ui(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Login page
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# Register page
@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

# Login form submission
@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = authenticate_user(fake_users_db, username, password)
    if not user:
        return templates.TemplateResponse(
            "login.html", 
            {"request": request, "error": "Invalid username or password"}
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    # Change redirect from "/" to "/authenticated.html"
    response = RedirectResponse(url="/authenticated.html", status_code=303)
    # Modified cookie settings for JavaScript access
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=False,  # Allow JavaScript access
        max_age=1800,
        expires=1800,
        samesite="lax"
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
    # Check if username already exists
    if username in fake_users_db:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Username already exists"}
        )
    
    # Create new user
    hashed_password = get_password_hash(password)
    fake_users_db[username] = {
        "username": username,
        "email": email,
        "full_name": full_name,
        "hashed_password": hashed_password,
        "disabled": False
    }
    
    # Redirect to login page with success message
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "message": "Registration successful. Please login."}
    )

# Logout
@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(key="access_token")
    return response

# Authenticated page
@app.get("/authenticated.html", response_class=HTMLResponse)
async def authenticated_page(request: Request):
    # Get the token from the cookie
    token = request.cookies.get("access_token")
    
    if not token:
        # If no token is present, redirect to login
        return RedirectResponse(url="/login", status_code=302)
    
    try:
        # Try to extract the user from the token
        token_type, access_token = token.split()
        user = None
        
        # Extract username from token and get user
        from jose import jwt
        from src.api.auth import SECRET_KEY, ALGORITHM, get_user
        
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username:
            user = get_user(username)
        
        if not user:
            raise Exception("Invalid user")
        
        # Render the template with the user
        return templates.TemplateResponse("authenticated.html", {"request": request, "user": user})
    
    except Exception as e:
        # If token validation fails, redirect to login
        print(f"Authentication error: {str(e)}")
        return RedirectResponse(url="/login", status_code=302)

# Authentication status endpoint
@app.get("/auth-status")
async def auth_status(current_user: User = Depends(get_current_active_user)):
    return {"authenticated": True, "username": current_user.username}

# Single URL classification (public)
@app.post("/classify", response_model=PredictionResult)
async def api_classify_url(request: UrlRequest):
    try:
        if classifier is None or pipeline is None:
            raise HTTPException(status_code=500, detail="Model not loaded")
        
        url = str(request.url)
        print(f"Processing URL: {url}")  # Debug output
        
        result = classify_url(url, classifier, pipeline)
        
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

# User info endpoint
@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)