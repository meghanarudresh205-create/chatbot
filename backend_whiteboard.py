"""
Multi-Tenant Collaborative Whiteboard SaaS — Backend (Render-ready)
FastAPI + WebSocket + SQLite

Deploy on Render:
  Build:  pip install -r requirements.txt
  Start:  uvicorn backend_whiteboard:app --host 0.0.0.0 --port $PORT

Environment variables (set in Render dashboard):
  SECRET_KEY   — random secret for JWT signing (Render can auto-generate)
"""

import json
import os
import sqlite3
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# ── CONFIG ──────────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-in-production-32c!")
ALGORITHM  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8

app = FastAPI(title="Whiteboard SaaS API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Tighten to your frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_ctx       = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# ── DATABASE ─────────────────────────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", "whiteboard.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
            plan TEXT DEFAULT 'free', created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id),
            email TEXT NOT NULL UNIQUE, hashed_pw TEXT NOT NULL,
            role TEXT DEFAULT 'member', created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS boards (
            id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id),
            owner_id TEXT NOT NULL REFERENCES users(id), title TEXT NOT NULL,
            is_public INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS board_elements (
            id TEXT PRIMARY KEY, board_id TEXT NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
            type TEXT NOT NULL, data TEXT NOT NULL, created_by TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS board_members (
            board_id TEXT NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
            user_id TEXT NOT NULL REFERENCES users(id),
            permission TEXT DEFAULT 'edit', PRIMARY KEY (board_id, user_id)
        );
        """)
    print("✅ Database initialized")


init_db()

# ── MODELS ───────────────────────────────────────────────────────────────────
class TenantCreate(BaseModel):
    name: str; admin_email: str; admin_password: str

class UserCreate(BaseModel):
    email: str; password: str; role: str = "member"

class BoardCreate(BaseModel):
    title: str; is_public: bool = False

class BoardElementCreate(BaseModel):
    type: str; data: Dict[str, Any]

class BoardElementUpdate(BaseModel):
    data: Dict[str, Any]

class Token(BaseModel):
    access_token: str; token_type: str
    user_id: str; tenant_id: str; role: str

# ── AUTH HELPERS ──────────────────────────────────────────────────────────────
def hash_password(pw): return pwd_ctx.hash(pw)
def verify_password(plain, hashed): return pwd_ctx.verify(plain, hashed)

def create_token(data):
    p = data.copy()
    p["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(p, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    payload = decode_token(token)
    user = db.execute("SELECT * FROM users WHERE id=?", (payload["sub"],)).fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return dict(user)

# ── TENANTS ───────────────────────────────────────────────────────────────────
@app.post("/tenants", status_code=201)
def create_tenant(body: TenantCreate, db=Depends(get_db)):
    tid, uid = str(uuid.uuid4()), str(uuid.uuid4())
    try:
        db.execute("INSERT INTO tenants(id,name) VALUES(?,?)", (tid, body.name))
        db.execute("INSERT INTO users(id,tenant_id,email,hashed_pw,role) VALUES(?,?,?,?,?)",
                   (uid, tid, body.admin_email, hash_password(body.admin_password), "admin"))
        db.commit()
    except sqlite3.IntegrityError as e:
        raise HTTPException(400, f"Name or email already taken: {e}")
    return {"tenant_id": tid, "user_id": uid}

@app.get("/tenants/{tenant_id}")
def get_tenant(tenant_id: str, db=Depends(get_db), user=Depends(get_current_user)):
    if user["tenant_id"] != tenant_id: raise HTTPException(403, "Access denied")
    row = db.execute("SELECT * FROM tenants WHERE id=?", (tenant_id,)).fetchone()
    if not row: raise HTTPException(404)
    return dict(row)

# ── AUTH ──────────────────────────────────────────────────────────────────────
@app.post("/auth/token", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
    user = db.execute("SELECT * FROM users WHERE email=?", (form.username,)).fetchone()
    if not user or not verify_password(form.password, user["hashed_pw"]):
        raise HTTPException(401, "Incorrect email or password")
    return Token(access_token=create_token({"sub": user["id"], "tenant": user["tenant_id"]}),
                 token_type="bearer", user_id=user["id"], tenant_id=user["tenant_id"], role=user["role"])

@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    return {k: v for k, v in user.items() if k != "hashed_pw"}

# ── USERS ─────────────────────────────────────────────────────────────────────
@app.post("/tenants/{tenant_id}/users", status_code=201)
def create_user(tenant_id: str, body: UserCreate, db=Depends(get_db), user=Depends(get_current_user)):
    if user["tenant_id"] != tenant_id or user["role"] != "admin":
        raise HTTPException(403, "Admins only")
    uid = str(uuid.uuid4())
    try:
        db.execute("INSERT INTO users(id,tenant_id,email,hashed_pw,role) VALUES(?,?,?,?,?)",
                   (uid, tenant_id, body.email, hash_password(body.password), body.role))
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Email already taken")
    return {"user_id": uid}

@app.get("/tenants/{tenant_id}/users")
def list_users(tenant_id: str, db=Depends(get_db), user=Depends(get_current_user)):
    if user["tenant_id"] != tenant_id: raise HTTPException(403, "Access denied")
    return [dict(r) for r in db.execute(
        "SELECT id,email,role,created_at FROM users WHERE tenant_id=?", (tenant_id,)).fetchall()]

# ── BOARDS ────────────────────────────────────────────────────────────────────
@app.post("/boards", status_code=201)
def create_board(body: BoardCreate, db=Depends(get_db), user=Depends(get_current_user)):
    bid = str(uuid.uuid4())
    db.execute("INSERT INTO boards(id,tenant_id,owner_id,title,is_public) VALUES(?,?,?,?,?)",
               (bid, user["tenant_id"], user["id"], body.title, int(body.is_public)))
    db.execute("INSERT INTO board_members(board_id,user_id,permission) VALUES(?,?,?)",
               (bid, user["id"], "owner"))
    db.commit()
    return {"board_id": bid}

@app.get("/boards")
def list_boards(db=Depends(get_db), user=Depends(get_current_user)):
    rows = db.execute("""
        SELECT b.id,b.title,b.is_public,b.created_at,b.updated_at,bm.permission
        FROM boards b JOIN board_members bm ON bm.board_id=b.id AND bm.user_id=?
        WHERE b.tenant_id=?
    """, (user["id"], user["tenant_id"])).fetchall()
    return [dict(r) for r in rows]

@app.get("/boards/{board_id}")
def get_board(board_id: str, db=Depends(get_db), user=Depends(get_current_user)):
    board = db.execute("SELECT * FROM boards WHERE id=?", (board_id,)).fetchone()
    if not board: raise HTTPException(404)
    board = dict(board)
    if board["tenant_id"] != user["tenant_id"] and not board["is_public"]:
        raise HTTPException(403)
    elements = db.execute("SELECT * FROM board_elements WHERE board_id=?", (board_id,)).fetchall()
    board["elements"] = [dict(e) | {"data": json.loads(e["data"])} for e in elements]
    return board

@app.delete("/boards/{board_id}", status_code=204)
def delete_board(board_id: str, db=Depends(get_db), user=Depends(get_current_user)):
    board = db.execute("SELECT * FROM boards WHERE id=?", (board_id,)).fetchone()
    if not board: raise HTTPException(404)
    if board["owner_id"] != user["id"] and user["role"] != "admin": raise HTTPException(403)
    db.execute("DELETE FROM boards WHERE id=?", (board_id,))
    db.commit()

# ── ELEMENTS ──────────────────────────────────────────────────────────────────
@app.post("/boards/{board_id}/elements", status_code=201)
def add_element(board_id: str, body: BoardElementCreate, db=Depends(get_db), user=Depends(get_current_user)):
    eid = str(uuid.uuid4())
    db.execute("INSERT INTO board_elements(id,board_id,type,data,created_by) VALUES(?,?,?,?,?)",
               (eid, board_id, body.type, json.dumps(body.data), user["id"]))
    db.execute("UPDATE boards SET updated_at=datetime('now') WHERE id=?", (board_id,))
    db.commit()
    return {"element_id": eid}

@app.put("/boards/{board_id}/elements/{element_id}")
def update_element(board_id: str, element_id: str, body: BoardElementUpdate,
                   db=Depends(get_db), user=Depends(get_current_user)):
    db.execute("UPDATE board_elements SET data=?,updated_at=datetime('now') WHERE id=? AND board_id=?",
               (json.dumps(body.data), element_id, board_id))
    db.execute("UPDATE boards SET updated_at=datetime('now') WHERE id=?", (board_id,))
    db.commit()
    return {"ok": True}

@app.delete("/boards/{board_id}/elements/{element_id}", status_code=204)
def delete_element(board_id: str, element_id: str, db=Depends(get_db), user=Depends(get_current_user)):
    db.execute("DELETE FROM board_elements WHERE id=? AND board_id=?", (element_id, board_id))
    db.commit()

# ── WEBSOCKET ─────────────────────────────────────────────────────────────────
active_connections: Dict[str, Dict[str, WebSocket]] = defaultdict(dict)
cursors: Dict[str, Dict[str, dict]]                 = defaultdict(dict)


async def broadcast(board_id: str, message: dict, exclude: Optional[str] = None):
    dead = []
    for uid, ws in active_connections[board_id].items():
        if uid == exclude: continue
        try:
            await ws.send_json(message)
        except Exception:
            dead.append(uid)
    for uid in dead:
        active_connections[board_id].pop(uid, None)


@app.websocket("/ws/{board_id}")
async def ws_endpoint(websocket: WebSocket, board_id: str, token: str):
    try:
        payload = decode_token(token)
    except HTTPException:
        await websocket.close(code=4001); return

    user_id = payload["sub"]
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        user  = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        board = conn.execute("SELECT * FROM boards WHERE id=?", (board_id,)).fetchone()

    if not user or not board:
        await websocket.close(code=4004); return

    await websocket.accept()
    active_connections[board_id][user_id] = websocket
    await broadcast(board_id, {"type":"user_joined","user_id":user_id,"email":user["email"],
                                "online_count":len(active_connections[board_id])}, exclude=user_id)
    await websocket.send_json({"type":"init_presence",
                               "users":{uid:info for uid,info in cursors[board_id].items()},
                               "online_count":len(active_connections[board_id])})
    try:
        while True:
            msg = json.loads(await websocket.receive_text())
            t   = msg.get("type")

            if t == "cursor_move":
                cursors[board_id][user_id] = {"x":msg["x"],"y":msg["y"],"email":user["email"]}
                await broadcast(board_id, {"type":"cursor_update","user_id":user_id,
                    "email":user["email"],"x":msg["x"],"y":msg["y"]}, exclude=user_id)

            elif t == "element_add":
                eid = str(uuid.uuid4())
                with sqlite3.connect(DB_PATH) as c:
                    c.execute("INSERT INTO board_elements(id,board_id,type,data,created_by) VALUES(?,?,?,?,?)",
                              (eid, board_id, msg["element_type"], json.dumps(msg["data"]), user_id))
                    c.execute("UPDATE boards SET updated_at=datetime('now') WHERE id=?", (board_id,))
                await broadcast(board_id, {"type":"element_add","element_id":eid,
                    "element_type":msg["element_type"],"data":msg["data"],"added_by":user_id})
                await websocket.send_json({"type":"element_add_ack","element_id":eid})

            elif t == "element_update":
                eid = msg["element_id"]
                with sqlite3.connect(DB_PATH) as c:
                    c.execute("UPDATE board_elements SET data=?,updated_at=datetime('now') WHERE id=?",
                              (json.dumps(msg["data"]), eid))
                await broadcast(board_id, {"type":"element_update","element_id":eid,
                    "data":msg["data"],"updated_by":user_id}, exclude=user_id)

            elif t == "element_delete":
                eid = msg["element_id"]
                with sqlite3.connect(DB_PATH) as c:
                    c.execute("DELETE FROM board_elements WHERE id=?", (eid,))
                await broadcast(board_id, {"type":"element_delete","element_id":eid,"deleted_by":user_id})

            elif t == "chat":
                await broadcast(board_id, {"type":"chat","user_id":user_id,"email":user["email"],
                    "text":msg.get("text","")[:500],"ts":datetime.utcnow().isoformat()})

    except WebSocketDisconnect:
        pass
    finally:
        active_connections[board_id].pop(user_id, None)
        cursors[board_id].pop(user_id, None)
        await broadcast(board_id, {"type":"user_left","user_id":user_id,"email":user["email"],
                                    "online_count":len(active_connections[board_id])})

# ── HEALTH ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("backend_whiteboard:app", host="0.0.0.0", port=port, reload=False)
