import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
import pyotp
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents
from schemas import User

# App and CORS
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security settings
SECRET_KEY = os.getenv("JWT_SECRET", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# Pydantic models
class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None
    role: Optional[str] = "trader"

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    mfa_required: bool = False

class EnableMFAResponse(BaseModel):
    secret: str
    uri: str

class VerifyMFARequest(BaseModel):
    email: EmailStr
    code: str

# Helpers

def get_collection(name: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    return db[name]


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


# Basic routes
@app.get("/")
def read_root():
    return {"message": "Trading Platform Backend running"}

@app.get("/test")
def test_database():
    info = {
        "backend": "running",
        "database": "connected" if db is not None else "not-configured",
    }
    if db is not None:
        try:
            info["collections"] = db.list_collection_names()
        except Exception as e:
            info["collections_error"] = str(e)
    return info


# Auth endpoints
@app.post("/auth/signup", response_model=TokenResponse)
def signup(payload: SignupRequest):
    users = get_collection("user")
    existing = users.find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_doc = User(
        email=payload.email,
        name=payload.name,
        role=(payload.role if payload.role in {"trader", "admin", "developer"} else "trader"),
        password_hash=hash_password(payload.password),
        mfa_enabled=False,
    ).model_dump()

    user_doc["created_at"] = datetime.now(timezone.utc)
    user_doc["updated_at"] = datetime.now(timezone.utc)

    users.insert_one(user_doc)

    token = create_access_token({"sub": payload.email, "role": user_doc["role"]})
    return TokenResponse(access_token=token, mfa_required=False)


@app.post("/auth/token", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    users = get_collection("user")
    user = users.find_one({"email": form_data.username})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if user.get("mfa_enabled"):
        # Return short-lived token indicating MFA step required
        temp_token = create_access_token({"sub": user["email"], "mfa": True}, expires_delta=timedelta(minutes=5))
        return TokenResponse(access_token=temp_token, mfa_required=True)

    token = create_access_token({"sub": user["email"], "role": user.get("role", "trader")})
    return TokenResponse(access_token=token, mfa_required=False)


@app.post("/auth/enable-mfa", response_model=EnableMFAResponse)
def enable_mfa(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    users = get_collection("user")
    user = users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="Flames.Trade")

    users.update_one({"email": email}, {"$set": {"mfa_enabled": True, "mfa_secret": secret, "updated_at": datetime.now(timezone.utc)}})

    return EnableMFAResponse(secret=secret, uri=uri)


@app.post("/auth/verify-mfa", response_model=TokenResponse)
def verify_mfa(body: VerifyMFARequest):
    users = get_collection("user")
    user = users.find_one({"email": body.email})
    if not user or not user.get("mfa_enabled") or not user.get("mfa_secret"):
        raise HTTPException(status_code=400, detail="MFA not enabled for user")

    totp = pyotp.TOTP(user["mfa_secret"])
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid code")

    token = create_access_token({"sub": user["email"], "role": user.get("role", "trader")})
    return TokenResponse(access_token=token, mfa_required=False)


# Example protected route with role-based access
from fastapi import Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
security = HTTPBearer()


def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("mfa"):
            raise HTTPException(status_code=401, detail="MFA verification required")
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    users = get_collection("user")
    user = users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def require_roles(*roles):
    def checker(user = Depends(get_current_user)):
        if user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return checker


@app.get("/auth/me")
def me(user = Depends(get_current_user)):
    return {"email": user.get("email"), "name": user.get("name"), "role": user.get("role")}


@app.get("/admin/overview")
def admin_overview(user = Depends(require_roles("admin"))):
    return {"status": "ok", "admin": True}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
