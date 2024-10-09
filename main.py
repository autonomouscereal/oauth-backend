# main.py
import sys

from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Header
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
import uuid
import logging
import hashlib
import base64
import urllib.parse

from db_helper import DBHelper
from models import User, OAuth2Client, OAuth2AuthorizationCode, TokenRequest
from credential_manager import CredentialManager

# Configure logging to write to stdout only
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s',
                    handlers=[
                        logging.StreamHandler(sys.stdout)
                    ])


class OriginLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        origin = request.headers.get('origin')
        logging.info(f"Incoming request from origin: {origin}")
        response = await call_next(request)
        return response



app = FastAPI()

# Add this middleware before CORSMiddleware
app.add_middleware(OriginLoggingMiddleware)

# CORS configuration
origins = [
    "http://localhost:3300",  # Frontend origin
    "http://localhost:3000",  # If applicable, e.g., React default port
    # Add other specific origins as needed
]

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,       # Specify allowed origins
    allow_credentials=True,     # Allow credentials (cookies, authorization headers)
    allow_methods=["*"],         # Allow all HTTP methods
    allow_headers=["*"],         # Allow all headers
)


# Session middleware
app.add_middleware(SessionMiddleware, secret_key=CredentialManager.get_secret_key())




# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
SECRET_KEY = CredentialManager.get_secret_key()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Initialize DBHelper
db_helper = DBHelper()

@app.on_event("startup")
async def startup():
    await db_helper.init_db()
    try:
        client_id_signup = 'a1b2c3d4-5678-90ab-cdef-1234567890ab'
        client_secret_signup = 'b2c3d4e5-6789-01ab-cdef-2345678901bc'
        redirect_uri_signup = 'http://localhost:3000/callback'
        existing_client = await db_helper.get_client_by_id(client_id_signup)
        if not existing_client:
            await db_helper.add_client(client_id_signup, client_secret_signup, redirect_uri_signup)

        client_id_password_vault = 'a1b2c3d4-5678-90ab-cdef-1234567890ac'
        client_secret_password_vault = 'b2c3d4e5-6789-01ab-cdef-2345678901bc'
        redirect_uri_password_vault = 'http://localhost:3300/callback'
        existing_client2 = await db_helper.get_client_by_id(client_id_password_vault)
        if not existing_client2:
            await db_helper.add_client(client_id_password_vault, client_secret_password_vault, redirect_uri_password_vault)
    except Exception as e:
        logging.error(e)

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependency function to get the current user
async def get_current_user(request: Request):
    user_id = request.session.get('user_id')
    if user_id:
        user = await db_helper.get_user_by_id(user_id)
        if user:
            return user
    raise HTTPException(status_code=401, detail="Not authenticated")

# Routes

import json

@app.get("/authorize")
async def authorize(request: Request,
                    response_type: str,
                    client_id: str,
                    redirect_uri: str,
                    scope: Optional[str] = None,
                    state: Optional[str] = None,
                    code_challenge: Optional[str] = None,
                    code_challenge_method: Optional[str] = None):
    # Validate client
    client = await db_helper.get_client_by_id(client_id)
    if not client:
        logging.error(f"Invalid client_id: {client_id}")
        raise HTTPException(status_code=400, detail="Invalid client_id")

    # Validate redirect_uri
    redirect_uris = client['redirect_uris'].split(',')
    if redirect_uri not in redirect_uris:
        logging.error(f"Invalid redirect_uri: {redirect_uri}")
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    # Check response_type
    if response_type != 'code':
        logging.error(f"Unsupported response_type: {response_type}")
        raise HTTPException(status_code=400, detail="Unsupported response_type")

    # PKCE parameters
    if not code_challenge or not code_challenge_method:
        logging.error("Missing PKCE parameters")
        raise HTTPException(status_code=400, detail="Missing PKCE parameters")

    # Parse state to extract original state and next_url
    try:
        state_data = json.loads(state)
        original_state = state_data.get('state')
        next_url = state_data.get('nextUrl')
    except Exception as e:
        logging.error(f"Invalid state parameter: {state}")
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    # Check if user is authenticated
    user_id = request.session.get('user_id')
    if not user_id:
        # Store parameters in session to use after login
        request.session['auth_request'] = {
            'response_type': response_type,
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'state': original_state,  # Store only the original state
            'state_json': state,  # Store the full state JSON string
            'code_challenge': code_challenge,
            'code_challenge_method': code_challenge_method,
            'next_url': next_url  # Store next_url separately
        }
        return RedirectResponse(url="/login")
    else:
        # User is authenticated
        user = await db_helper.get_user_by_id(user_id)
        if not user:
            # User not found, clear session
            request.session.clear()
            request.session['auth_request'] = {
                'response_type': response_type,
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'scope': scope,
                'state': original_state,  # Store only the original state
                'state_json': state,  # Store the full state JSON string
                'code_challenge': code_challenge,
                'code_challenge_method': code_challenge_method,
                'next_url': next_url  # Store next_url separately
            }
            return RedirectResponse(url="/login")

    # Generate authorization code
    code = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(minutes=10)  # Authorization code expires in 10 minutes
    await db_helper.save_authorization_code(OAuth2AuthorizationCode(
        code=code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        user_id=user['id'],
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        expires_at=expires_at
    ))

    # Redirect back to client with authorization code
    params = {'code': code}
    if original_state:
        params['state'] = original_state
    redirect_with_params = f"{redirect_uri}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url=redirect_with_params)



@app.get("/login")
async def login_get(request: Request):
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login / Sign Up</title>
        <style>
        /* Include your CSS styles here */
        .signup-container {
            background: linear-gradient(135deg, #6e8efb, #a777e3);
            max-width: 400px;
            margin: 50px auto;
            padding: 40px 30px;
            border-radius: 10px;
            box-shadow: 0 15px 25px rgba(0, 0, 0, 0.2);
            color: #fff;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            animation: fadeIn 1s ease-in-out;
        }

        @keyframes fadeIn {
            from {
            opacity: 0;
            transform: translateY(-10%);
            }
            to {
            opacity: 1;
            transform: translateY(0);
            }
        }

        .signup-container h2 {
            text-align: center;
            margin-bottom: 30px;
            font-size: 32px;
        }

        .signup-container form {
            display: flex;
            flex-direction: column;
        }

        .signup-container label {
            font-size: 18px;
            margin-bottom: 5px;
        }

        .signup-container input {
            width: 100%;
            padding: 12px 15px;
            font-size: 16px;
            border: none;
            border-radius: 25px;
            margin-bottom: 20px;
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
            outline: none;
        }

        .signup-container input::placeholder {
            color: rgba(255, 255, 255, 0.7);
        }

        .signup-container input:focus {
            background: rgba(255, 255, 255, 0.2);
        }

        .input-error {
            border: 2px solid #ff4d4d !important;
        }

        .signup-container .password-toggle {
            position: absolute;
            right: 15px;
            top: 55%;
            transform: translateY(-50%);
            cursor: pointer;
            color: #fff;
            font-size: 14px;
        }

        .signup-container button {
            padding: 12px 15px;
            font-size: 18px;
            cursor: pointer;
            border: none;
            border-radius: 25px;
            background: #fff;
            color: #6e8efb;
            font-weight: bold;
            transition: background 0.3s, color 0.3s;
        }

        .signup-container button:hover {
            background: #6e8efb;
            color: #fff;
        }

        .signup-container p {
            text-align: center;
            font-size: 16px;
            margin-top: 20px;
            background: rgba(255, 255, 255, 0.1);
            padding: 10px;
            border-radius: 5px;
        }

        /* Responsive Design */
        @media (max-width: 500px) {
            .signup-container {
            padding: 30px 20px;
            margin: 20px;
            }
        }
        </style>
    </head>
    <body>
        <div class="signup-container">
            <h2>Login / Sign Up</h2>
            <form method="post" action="/login">
                <label for="email">Email:</label>
                <input type="email" name="email" id="email" required placeholder="Enter your email" />

                <label for="password">Password:</label>
                <input type="password" name="password" id="password" required placeholder="Enter your password" />

                <button type="submit">Login / Sign Up</button>
            </form>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)

@app.post("/login")
async def login_post(request: Request, email: str = Form(...), password: str = Form(...)):
    user = await db_helper.get_user_by_email(email)
    if user:
        if not verify_password(password, user['hashed_password']):
            logging.error(f"Invalid credentials for {email}")
            raise HTTPException(status_code=400, detail="Invalid credentials")
    else:
        # Register new user
        hashed_password = get_password_hash(password)
        await db_helper.add_user(email, hashed_password)
        user = await db_helper.get_user_by_email(email)
        logging.info(f"New user registered: {email}")

    # Authenticate user
    request.session['user_id'] = user['id']
    logging.info(f"User '{user['email']}' authenticated successfully with user_id '{user['id']}'.")

    # Retrieve auth_request from session
    auth_request = request.session.pop('auth_request', None)
    if auth_request:
        # Redirect back to /authorize with stored parameters to continue the OAuth2 flow
        redirect_url = f"/authorize?response_type={urllib.parse.quote(auth_request['response_type'])}" \
                       f"&client_id={urllib.parse.quote(auth_request['client_id'])}" \
                       f"&redirect_uri={urllib.parse.quote(auth_request['redirect_uri'])}" \
                       f"&scope={urllib.parse.quote(auth_request['scope'] or '')}" \
                       f"&state={urllib.parse.quote(auth_request['state_json'] or '')}" \
                       f"&code_challenge={urllib.parse.quote(auth_request['code_challenge'])}" \
                       f"&code_challenge_method={urllib.parse.quote(auth_request['code_challenge_method'])}"
        logging.info(f"Redirecting user '{user['email']}' to authorization endpoint with URL: {redirect_url}")
        return RedirectResponse(url=redirect_url, status_code=303)
    else:
        # No auth_request found, redirect to 'next_url' if present
        next_url = request.session.pop('next_url', '/')
        logging.info(f"Redirecting user '{user['email']}' to next URL: {next_url}")
        return RedirectResponse(url=next_url, status_code=303)




@app.post("/token")
async def token(request: Request,
                grant_type: str = Form(...),
                code: str = Form(None),
                redirect_uri: str = Form(None),
                client_id: str = Form(None),
                code_verifier: str = Form(None)):
    logging.info("Received /token request")
    logging.info(f"Parameters - grant_type: {grant_type}, code: {code}, redirect_uri: {redirect_uri}, client_id: {client_id}, code_verifier: {code_verifier}")

    if grant_type != 'authorization_code':
        logging.error(f"Unsupported grant_type: {grant_type}")
        raise HTTPException(status_code=400, detail="Unsupported grant_type")

    if not code or not redirect_uri or not client_id or not code_verifier:
        logging.error("Missing parameters in token request")
        raise HTTPException(status_code=400, detail="Missing parameters")

    # Validate client
    client = await db_helper.get_client_by_id(client_id)
    if not client:
        logging.error(f"Invalid client_id: {client_id}")
        raise HTTPException(status_code=400, detail="Invalid client_id")

    # Retrieve authorization code
    auth_code = await db_helper.get_authorization_code(code)
    if not auth_code:
        logging.error(f"Invalid or expired authorization code: {code}")
        raise HTTPException(status_code=400, detail="Invalid or expired authorization code")

    if auth_code['client_id'] != client_id or auth_code['redirect_uri'] != redirect_uri:
        logging.error("Authorization code does not match client or redirect_uri")
        raise HTTPException(status_code=400, detail="Invalid authorization code")

    if auth_code['expires_at'] < datetime.now(timezone.utc):
        logging.error("Authorization code has expired")
        await db_helper.delete_authorization_code(code)
        raise HTTPException(status_code=400, detail="Authorization code expired")

    # Verify PKCE code_challenge
    code_challenge_method = auth_code['code_challenge_method']
    code_challenge = auth_code['code_challenge']
    if code_challenge_method == 'S256':
        new_code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip("=")
    elif code_challenge_method == 'plain':
        new_code_challenge = code_verifier
    else:
        logging.error(f"Unsupported code_challenge_method: {code_challenge_method}")
        raise HTTPException(status_code=400, detail="Invalid code_challenge_method")

    if new_code_challenge != code_challenge:
        logging.error("Invalid code_verifier")
        raise HTTPException(status_code=400, detail="Invalid code_verifier")

    # Generate access token
    user = await db_helper.get_user_by_id(auth_code['user_id'])
    access_token = create_token(
        data={"sub": str(user['id']), "email": user['email']},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    # Optionally, generate a refresh token
    refresh_token = str(uuid.uuid4())
    refresh_expires_at = datetime.utcnow() + timedelta(days=7)
    await db_helper.save_refresh_token(user['id'], refresh_token, refresh_expires_at)

    # Delete authorization code
    await db_helper.delete_authorization_code(code)

    logging.info(f"Issued access_token and refresh_token for user_id: {user['id']}")

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "refresh_token": refresh_token
    }


@app.post("/token/refresh")
async def token_refresh(refresh_token: str = Form(...)):
    # Retrieve refresh token
    token_data = await db_helper.get_refresh_token(refresh_token)
    if not token_data:
        logging.error(f"Invalid refresh token: {refresh_token}")
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    if token_data['expires_at'] < datetime.utcnow():
        logging.error("Refresh token has expired")
        await db_helper.delete_refresh_token(refresh_token)
        raise HTTPException(status_code=400, detail="Refresh token expired")

    # Generate new access token
    user = await db_helper.get_user_by_id(token_data['user_id'])
    access_token = create_token(
        data={"sub": str(user['id']), "email": user['email']},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    # Optionally, rotate refresh token
    new_refresh_token = str(uuid.uuid4())
    refresh_expires_at = datetime.utcnow() + timedelta(days=7)
    await db_helper.save_refresh_token(user['id'], new_refresh_token, refresh_expires_at)
    await db_helper.delete_refresh_token(refresh_token)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "refresh_token": new_refresh_token
    }

async def get_token_from_header(authorization: str = Header(...)):
    if authorization.startswith("Bearer "):
        return authorization[len("Bearer "):]
    raise HTTPException(status_code=401, detail="Invalid authorization header")

@app.get("/protected-resource")
async def protected_resource(token: str = Depends(get_token_from_header)):
    # Decode and verify token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = await db_helper.get_user_by_id(int(user_id))
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return {"email": user['email']}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Additional endpoints for client registration, etc., can be added as needed

@app.post("/login_or_signup")
async def login_or_signup(request: Request, email: str = Form(...), password: str = Form(...), next: Optional[str] = None):
    logging.info(f"Login/Signup attempt for {email}")
    user = await db_helper.get_user_by_email(email)
    if user:
        # User exists, attempt to authenticate
        if not verify_password(password, user['hashed_password']):
            logging.warning(f"Invalid password for {email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
            )
        else:
            logging.info(f"User {email} logged in successfully")
    else:
        # User does not exist, create account
        hashed_password = get_password_hash(password)
        try:
            await db_helper.add_user(email, hashed_password)
            user = await db_helper.get_user_by_email(email)
            logging.info(f"User {email} registered and logged in successfully")
        except Exception as e:
            logging.error(f"Registration error for {email}: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

    # Set user in session
    request.session['user_id'] = user['id']
    # Redirect back to the original authorization request
    next_url = request.query_params.get('next') or '/'
    return RedirectResponse(url=next_url)

@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    logging.info("User logged out successfully")
    return {"msg": "Logged out successfully"}

# Example protected resource using the dependency
@app.get("/users/me")
async def read_users_me(user: dict = Depends(get_current_user)):
    logging.info(f"User data requested for {user['email']}")
    return {
        "email": user['email'],
        "id": user['id'],
    }

# Additional endpoints for roles and permissions can be added as needed

@app.post("/roles")
async def create_role(role_name: str):
    try:
        await db_helper.create_role(role_name)
        logging.info(f"Role '{role_name}' created successfully")
        return {"msg": f"Role '{role_name}' created successfully"}
    except Exception as e:
        logging.error(f"Role creation error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/permissions")
async def create_permission(permission_name: str):
    try:
        await db_helper.create_permission(permission_name)
        logging.info(f"Permission '{permission_name}' created successfully")
        return {"msg": f"Permission '{permission_name}' created successfully"}
    except Exception as e:
        logging.error(f"Permission creation error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/roles/{role_name}/permissions")
async def assign_permission_to_role(role_name: str, permission_name: str):
    try:
        role = await db_helper.get_role_by_name(role_name)
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")

        permission = await db_helper.get_permission_by_name(permission_name)
        if not permission:
            raise HTTPException(status_code=404, detail="Permission not found")

        await db_helper.assign_permission_to_role(role['id'], permission['id'])
        logging.info(f"Assigned permission '{permission_name}' to role '{role_name}'")
        return {"msg": f"Permission '{permission_name}' assigned to role '{role_name}'"}
    except Exception as e:
        logging.error(f"Error assigning permission to role: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/users/{email}/roles")
async def assign_role_to_user(email: str, role_name: str):
    try:
        user = await db_helper.get_user_by_email(email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        role = await db_helper.get_role_by_name(role_name)
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")

        await db_helper.assign_role_to_user(user['id'], role['id'])
        logging.info(f"Assigned role '{role_name}' to user '{email}'")
        return {"msg": f"Role '{role_name}' assigned to user '{email}'"}
    except Exception as e:
        logging.error(f"Error assigning role to user: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/users/{email}/permissions")
async def get_user_permissions(email: str):
    try:
        user = await db_helper.get_user_by_email(email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        permission_names = await db_helper.get_user_permissions(user['id'])
        logging.info(f"Retrieved permissions for user '{email}'")
        return {"email": email, "permissions": permission_names}
    except Exception as e:
        logging.error(f"Error retrieving user permissions: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
