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
from pathlib import Path
from src.api.auth import (
    Token, User, authenticate_user, create_access_token, 
    get_current_active_user, ACCESS_TOKEN_EXPIRE_MINUTES, fake_users_db,
    get_password_hash  # Add this import
)

# Add project root to path
import sys
project_root = str(Path(__file__).parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.api.auth import (
    Token, User, authenticate_user, create_access_token, 
    get_current_active_user, ACCESS_TOKEN_EXPIRE_MINUTES, fake_users_db
)
from src.predict import load_model_and_pipeline, classify_url, classify_batch

# Initialize FastAPI app
app = FastAPI(
    title="Phishing and Malware Detection API",
    description="API for detecting phishing and malware URLs",
    version="1.0.0"
)

# Configure static files and templates
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# Load model and pipeline
print("Loading model and pipeline...")
try:
    # Use absolute path
    import os
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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
    
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=1800,
        expires=1800,
    )
    return response

# Logout
@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(key="access_token")
    return response

# Health check endpoint
@app.get("/health")
def health_check():
    return {"status": "ok", "message": "Phishing and Malware Detection API is running"}

# Single URL classification (public)
@app.post("/classify", response_model=PredictionResult)
async def api_classify_url(request: UrlRequest):
    try:
        if classifier is None or pipeline is None:
            raise HTTPException(status_code=500, detail="Model not loaded")
        
        url = str(request.url)
        print(f"Processing URL: {url}")  # Add debug output
        
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
        import traceback
        traceback.print_exc()  # Print the full error to your console
        return PredictionResult(
            url=url,
            error=f"Error processing URL: {str(e)}"
        )

# Batch URL classification (authenticated only)
@app.post("/classify-batch", response_model=BatchPredictionResult)
async def api_classify_batch(
    request: BatchUrlRequest, 
    current_user: User = Depends(get_current_active_user)
):
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

# User info endpoint
@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)