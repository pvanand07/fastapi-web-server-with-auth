from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from supabase import create_client
from jose import jwt, JWTError
import os
from datetime import datetime, timedelta
import logging
from pydantic import BaseModel

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Configuration variables (use environment variables in production)
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")

# URL variables
APP_URL = 'https://www.app.com'

# Initialize Supabase client
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Initialize Jinja2Templates
templates = Jinja2Templates(directory="templates")

def create_jwt(payload):
    exp = datetime.utcnow() + timedelta(hours=24)
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256', headers={'exp': exp})

class TokenRequest(BaseModel):
    token: str

@app.get("/google_auth_url")
async def google_auth_url():
    params = {
        'provider': 'google',
        'redirect_to': 'http://localhost:8501',
        'flow': 'implicit',
        'scope': 'email profile'
    }
    query_string = "&".join([f"{k}={v}" for k, v in params.items()])
    auth_url = f"{SUPABASE_URL}/auth/v1/authorize?{query_string}"
    logging.debug(f"Redirecting to: {auth_url}")
    return JSONResponse(content={"url": auth_url})

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    logging.debug("Rendering index.html")
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    logging.debug("Rendering login.html")
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/waitlist", response_class=HTMLResponse)
async def waitlist(request: Request):
    logging.debug("Rendering waitlist.html")
    return templates.TemplateResponse("waitlist.html", {"request": request})

@app.post("/check_status")
async def check_status(token_request: TokenRequest, response: Response):
    logging.debug(f"Received request to /check_status with token: {token_request.token}")
    
    if not token_request.token:
        logging.debug("No token provided, redirecting to login")
        return JSONResponse(content={'route': '/login'})

    try:
        # Try to verify JWT, if it fails, decode without verification
        try:
            payload = jwt.decode(token_request.token, JWT_SECRET, algorithms=['HS256'])
        except JWTError:
            payload = jwt.decode(token_request.token, 'dummy_key', options={"verify_signature": False,"verify_aud": False})
        
        user_email = payload.get('email')
        if not user_email:
            raise ValueError("No email in token")

        logging.debug(f"Decoded email from token: {user_email}")

        # Check email in Supabase
        response = supabase.table('email_allowlist').select('email').eq('email', user_email).execute()
        user_valid = len(response.data) > 0
        
        new_token = create_jwt({'authenticated': True, 'valid': user_valid})
        content = {'url': APP_URL} if user_valid else {'route': '/waitlist'}

    except Exception as e:
        logging.debug(f"Error processing token: {str(e)}")
        content = {'route': '/login'}
        new_token = ''

    logging.debug(f"Redirecting to: {content}")
    
    response = JSONResponse(content=content)
    if new_token:
        response.set_cookie(key='auth_token', value=new_token, httponly=True, secure=True, samesite='strict', max_age=86400)
    return response

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860, reload=True, debug=True)
