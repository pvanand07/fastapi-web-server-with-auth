from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from supabase import create_client
from jose import jwt
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

def verify_jwt(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except:
        return None

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
    logging.debug("Received request to /check_status")
    token = token_request.token
    logging.debug(f"Received token: {token}")
    
    if not token:
        logging.debug("No token provided, redirecting to login")
        return JSONResponse(content={'route': '/login'})

    jwt_payload = verify_jwt(token)
    if jwt_payload:
        logging.debug(f"Valid JWT payload: {jwt_payload}")
        if jwt_payload.get('authenticated') and jwt_payload.get('valid'):
            return JSONResponse(content={'url': APP_URL})
        elif jwt_payload.get('authenticated') and not jwt_payload.get('valid'):
            return JSONResponse(content={'route': '/waitlist'})
        else:
            return JSONResponse(content={'route': '/login'})

    try:
        user_email = jwt.decode(token, options={"verify_signature": False})['email']
        logging.debug(f"Decoded email from token: {user_email}")
    except:
        logging.debug("Failed to decode email from token")
        return JSONResponse(content={'route': '/login'})

    if not user_email:
        logging.debug("No email in token")
        return JSONResponse(content={'route': '/login'})

    logging.debug("Checking email in Supabase")
    response = supabase.table('email_allowlist').select('email').eq('email', user_email).execute()
    logging.debug(f"Supabase response: {response}")
    
    user_authenticated = True
    user_valid = len(response.data) > 0
    new_token = create_jwt({'authenticated': user_authenticated, 'valid': user_valid})
    logging.debug(f"Created new token: {new_token}")
    
    if user_authenticated and user_valid:
        content = {'url': APP_URL}
    elif user_authenticated and not user_valid:
        content = {'route': '/waitlist'}
    else:
        content = {'route': '/login'}

    logging.debug(f"Redirecting to: {content}")
    
    response = JSONResponse(content=content)
    response.set_cookie(key='auth_token', value=new_token, httponly=True, secure=True, samesite='strict', max_age=86400)
    return response

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860, reload=True, debug=True)
