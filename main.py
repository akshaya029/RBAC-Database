import os
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm, HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Table, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship, declarative_base

# Load environment variables
load_dotenv()

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# JWT Config
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# Password Hashing
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)

app = FastAPI(title="Swiggy/Zomato RBAC API")

# --- MODELS ---
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("role_id", Integer, ForeignKey("roles.id"))
)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True)
    email = Column(String(100), unique=True)
    full_name = Column(String(100))
    password_hash = Column(String(255))
    roles = relationship("Role", secondary=user_roles, back_populates="users")

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True)
    users = relationship("User", secondary=user_roles, back_populates="roles")

Base.metadata.create_all(bind=engine)

# --- SCHEMAS ---
class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str
    full_name: str
    roles: List[str]

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: Optional[datetime]

# --- HELPERS ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_pw, hashed_pw):
    return pwd_context.verify(plain_pw, hashed_pw)

def hash_password(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    now = datetime.utcnow()
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": now})
    token = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, expire

def decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# --- AUTH DEPENDENCIES ---
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme), db=Depends(get_db)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = credentials.credentials
    payload = decode_token(token)
    username = payload.get("sub")
    user = db.query(User).filter_by(username=username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_role(role_name: str):
    def role_checker(user: User = Depends(get_current_user)):
        if role_name not in [r.name for r in user.roles]:
            raise HTTPException(status_code=403, detail=f"Access forbidden: requires {role_name} role")
        return user
    return role_checker

# --- ROUTES ---
@app.post("/register")
def register_user(request: RegisterRequest, db: SessionLocal = Depends(get_db)):
    if db.query(User).filter_by(username=request.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    
    user = User(
        username=request.username,
        email=request.email,
        full_name=request.full_name,
        password_hash=hash_password(request.password)
    )
    
    for role_name in request.roles:
        role = db.query(Role).filter_by(name=role_name).first()
        if not role:
            role = Role(name=role_name)
            db.add(role)
        user.roles.append(role)
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return {"message": f"User {user.username} registered successfully."}

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: SessionLocal = Depends(get_db)):
    user = db.query(User).filter_by(username=form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    roles = [r.name for r in user.roles]
    token_data = {"sub": user.username, "roles": roles}
    token, expires = create_access_token(token_data)
    return Token(access_token=token, expires_at=expires)

@app.get("/restaurants")
def get_restaurants(current_user: User = Depends(require_role("restaurant_owner"))):
    return {"message": f"Welcome {current_user.username}! You can manage your restaurant menu."}

@app.get("/orders")
def get_orders(current_user: User = Depends(require_role("customer"))):
    return {"message": f"Hello {current_user.username}, here are your orders!"}

@app.get("/admin/dashboard")
def admin_dashboard(current_user: User = Depends(require_role("admin"))):
    return {"message": f"Welcome Admin {current_user.username}, you can manage everything."}
