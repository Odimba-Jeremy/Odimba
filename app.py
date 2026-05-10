"""
iHub Backend — monolithic FastAPI app.

Run:
    Development: uvicorn app:app --reload
    Production:  gunicorn -k uvicorn.workers.UvicornWorker app:app

Swagger UI: http://localhost:10000/docs
"""

import os
import time
import uvicorn
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from jose import jwt, JWTError
from passlib.context import CryptContext
from supabase import create_client, Client

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SUPABASE_URL = "https://figmeixteescztmmprmi.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZpZ21laXh0ZWVzY3p0bW1wcm1pIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NTM4NjA2MCwiZXhwIjoyMDkwOTYyMDYwfQ.zMIDYvm-Bwv0EUQzME3nZR8ZPoSwTMCaybHRnw_-7Ew"

SECRET_KEY = "ihub_super_secret_key_2024_change_me_production"

GROQ_API_KEY = "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"
GROQ_MODEL = "llama-3.1-8b-instant"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

PORT = int(os.environ.get("PORT", 10000))
DEBUG = os.environ.get("DEBUG", "False").lower() == "true"

TOKEN_EXPIRY = 86400 * 7  # 7 days, in seconds
CACHE_TIMEOUT = 300       # 5 minutes
JWT_ALGORITHM = "HS256"

# CORS
CORS_ORIGINS = ["*"]

# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------
def create_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=TOKEN_EXPIRY)).timestamp()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
        )


# ---------------------------------------------------------------------------
# In-memory cache (TTL)
# ---------------------------------------------------------------------------
_cache: Dict[str, Tuple[Any, float]] = {}


def cache_get(key: str) -> Optional[Any]:
    item = _cache.get(key)
    if not item:
        return None
    value, expires_at = item
    if time.time() > expires_at:
        _cache.pop(key, None)
        return None
    return value


def cache_set(key: str, value: Any, ttl: int = CACHE_TIMEOUT) -> None:
    _cache[key] = (value, time.time() + ttl)


def cache_delete(key: str) -> None:
    _cache.pop(key, None)


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------
def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Dict[str, Any]:
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    payload = decode_token(creds.credentials)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    cache_key = f"user:{user_id}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    res = supabase.table("app_users").select("id,email,username,created_at").eq("id", user_id).limit(1).execute()
    if not res.data:
        raise HTTPException(status_code=401, detail="User not found")

    user = res.data[0]
    cache_set(cache_key, user, ttl=60)
    return user


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------
class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)
    username: Optional[str] = Field(default=None, max_length=64)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = TOKEN_EXPIRY
    user: Dict[str, Any]


class ItemIn(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    content: Optional[Dict[str, Any]] = None


class ConversationIn(BaseModel):
    title: Optional[str] = Field(default=None, max_length=255)


class ChatMessageIn(BaseModel):
    content: str = Field(min_length=1, max_length=8000)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="iHub Backend",
    version="1.0.0",
    description="Monolithic FastAPI backend: Auth (JWT) + Supabase CRUD + Groq chat + cache.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/")
def root():
    return {
        "name": "iHub Backend",
        "version": "1.0.0",
        "status": "ok",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": int(time.time())}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
@app.post("/auth/register", response_model=TokenOut, status_code=201)
def register(payload: RegisterIn):
    existing = supabase.table("app_users").select("id").eq("email", payload.email).limit(1).execute()
    if existing.data:
        raise HTTPException(status_code=409, detail="Email already registered")

    new_user = {
        "email": payload.email,
        "password_hash": hash_password(payload.password),
        "username": payload.username,
    }
    res = supabase.table("app_users").insert(new_user).execute()
    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to create user")

    user = res.data[0]
    user_response = {k: v for k, v in user.items() if k != "password_hash"}
    token = create_token(user["id"])
    return TokenOut(access_token=token, user=user_response)


@app.post("/auth/login", response_model=TokenOut)
def login(payload: LoginIn):
    res = (
        supabase.table("app_users")
        .select("id,email,username,password_hash,created_at")
        .eq("email", payload.email)
        .limit(1)
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user = res.data[0]
    if not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_response = {k: v for k, v in user.items() if k != "password_hash"}
    token = create_token(user["id"])
    return TokenOut(access_token=token, user=user_response)


@app.get("/auth/me")
def me(current_user: Dict[str, Any] = Depends(get_current_user)):
    return current_user


# ---------------------------------------------------------------------------
# Items CRUD (cached)
# ---------------------------------------------------------------------------
@app.get("/items")
def list_items(current_user: Dict[str, Any] = Depends(get_current_user)):
    cache_key = f"items:{current_user['id']}"
    cached = cache_get(cache_key)
    if cached is not None:
        return {"items": cached, "cached": True}

    res = (
        supabase.table("items")
        .select("*")
        .eq("user_id", current_user["id"])
        .order("created_at", desc=True)
        .execute()
    )
    items = res.data or []
    cache_set(cache_key, items)
    return {"items": items, "cached": False}


@app.post("/items", status_code=201)
def create_item(payload: ItemIn, current_user: Dict[str, Any] = Depends(get_current_user)):
    new_item = {
        "user_id": current_user["id"],
        "title": payload.title,
        "content": payload.content,
    }
    res = supabase.table("items").insert(new_item).execute()
    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to create item")
    cache_delete(f"items:{current_user['id']}")
    return res.data[0]


@app.get("/items/{item_id}")
def get_item(item_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    res = (
        supabase.table("items")
        .select("*")
        .eq("id", item_id)
        .eq("user_id", current_user["id"])
        .limit(1)
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Item not found")
    return res.data[0]


@app.put("/items/{item_id}")
def update_item(
    item_id: str,
    payload: ItemIn,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    update = {
        "title": payload.title,
        "content": payload.content,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    res = (
        supabase.table("items")
        .update(update)
        .eq("id", item_id)
        .eq("user_id", current_user["id"])
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Item not found")
    cache_delete(f"items:{current_user['id']}")
    return res.data[0]


@app.delete("/items/{item_id}", status_code=204)
def delete_item(item_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    res = (
        supabase.table("items")
        .delete()
        .eq("id", item_id)
        .eq("user_id", current_user["id"])
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Item not found")
    cache_delete(f"items:{current_user['id']}")
    return None


# ---------------------------------------------------------------------------
# Chat (Groq)
# ---------------------------------------------------------------------------
def _ensure_conversation_owned(conv_id: str, user_id: str) -> Dict[str, Any]:
    res = (
        supabase.table("conversations")
        .select("*")
        .eq("id", conv_id)
        .eq("user_id", user_id)
        .limit(1)
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return res.data[0]


def _call_groq_sync(messages: List[Dict[str, str]]) -> str:
    """Version synchrone pour Gunicorn"""
    if not GROQ_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="GROQ_API_KEY is not configured on the server",
        )

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    body = {
        "model": GROQ_MODEL,
        "messages": messages,
        "temperature": 0.7,
    }
    try:
        with httpx.Client(timeout=60.0) as client:
            r = client.post(GROQ_API_URL, headers=headers, json=body)
        if r.status_code >= 400:
            raise HTTPException(
                status_code=502,
                detail=f"Groq API error {r.status_code}: {r.text[:300]}",
            )
        data = r.json()
        return data["choices"][0]["message"]["content"]
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Groq request failed: {exc}")


@app.post("/chat/conversations", status_code=201)
def create_conversation(
    payload: ConversationIn,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    res = (
        supabase.table("conversations")
        .insert({"user_id": current_user["id"], "title": payload.title or "New conversation"})
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to create conversation")
    return res.data[0]


@app.get("/chat/conversations")
def list_conversations(current_user: Dict[str, Any] = Depends(get_current_user)):
    res = (
        supabase.table("conversations")
        .select("*")
        .eq("user_id", current_user["id"])
        .order("created_at", desc=True)
        .execute()
    )
    return {"conversations": res.data or []}


@app.get("/chat/conversations/{conv_id}/messages")
def list_messages(conv_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    _ensure_conversation_owned(conv_id, current_user["id"])
    res = (
        supabase.table("messages")
        .select("*")
        .eq("conversation_id", conv_id)
        .order("created_at", asc=False)
        .execute()
    )
    return {"messages": res.data or []}


@app.post("/chat/conversations/{conv_id}/messages")
def send_message(
    conv_id: str,
    payload: ChatMessageIn,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    _ensure_conversation_owned(conv_id, current_user["id"])

    # Save user message
    supabase.table("messages").insert(
        {"conversation_id": conv_id, "role": "user", "content": payload.content}
    ).execute()

    # Build history for Groq
    hist = (
        supabase.table("messages")
        .select("role,content")
        .eq("conversation_id", conv_id)
        .order("created_at", asc=False)
        .execute()
    )
    # Inverser les messages pour l'ordre chronologique
    messages = [{"role": m["role"], "content": m["content"]} for m in reversed(hist.data or [])]

    # Call Groq (version synchrone)
    assistant_content = _call_groq_sync(messages)

    # Save assistant message
    saved = (
        supabase.table("messages")
        .insert(
            {
                "conversation_id": conv_id,
                "role": "assistant",
                "content": assistant_content,
            }
        )
        .execute()
    )
    return saved.data[0] if saved.data else {"role": "assistant", "content": assistant_content}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=10000, reload=False)
