import aiosqlite
import os
import cpx
# ...import os, time, smtplib, hmac, hashlib, jwt, aiosqlite
from email.message import EmailMessage
from fastapi import FastAPI, HTTPException, Depends, Header
import cpx
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from passlib.hash import bcrypt
from starlette.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# ---------- Config ----------
JWT_SECRET = os.getenv('JWT_SECRET', 'change-me')
JWT_EXPIRE = 60 * 60 * 24 * 14  # 14 days
CPX_APP_ID = os.getenv('CPX_APP_ID', '28541')
CPX_SECURE_KEY = os.getenv('CPX_SECURE_KEY', 'set-me')

SMTP_HOST = os.getenv('SMTP_HOST', '')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USER = os.getenv('SMTP_USER', '')
SMTP_PASS = os.getenv('SMTP_PASS', '')
SMTP_FROM = os.getenv('SMTP_FROM', SMTP_USER or 'noreply@example.com')

DAILY_AD_LIMIT = int(os.getenv('DAILY_AD_LIMIT', '30'))
USER_SPLIT = float(os.getenv('PAYOUT_USER_SPLIT', '0.7'))
TOTAL_PAYOUT = 0.01

DB = 'db.sqlite'

app = FastAPI(title='7030 Backend')


@app.get('/api/db/debug')
def _db_debug():
    import sqlite3, json
    info = {}
    try:
        # expose DB value from this module if present
        try:
            from server import DB as _DB
        except Exception:
            _DB = None
        info['DB'] = _DB
        if _DB:
            try:
                conn = sqlite3.connect(_DB)
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                info['tables'] = [r[0] for r in cur.fetchall()]
                if 'users' in info.get('tables', []):
                    cur.execute("SELECT COUNT(1) FROM users")
                    info['users_count'] = cur.fetchone()[0]
                conn.close()
            except Exception as e:
                info['sqlite_error'] = str(e)
    except Exception as e:
        info['error'] = str(e)
    return info
app.add_middleware(
    CORSMiddleware,
        allow_origins=[
        "http://localhost:5500",
        "http://localhost",
        "http://127.0.0.1:5500"
    ],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

# ---------- Models ----------
class AuthIn(BaseModel):
    email: EmailStr
    password: str

class ResetVerifyIn(BaseModel):
    email: EmailStr
    code: str
    newPassword: str

class AdminIn(BaseModel):
    email: EmailStr
    password: str

# ---------- DB ----------
async def db_init():
    async with aiosqlite.connect(DB) as db:
        await db.execute('''
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          email TEXT UNIQUE NOT NULL,
          passhash TEXT NOT NULL,
          balance REAL NOT NULL DEFAULT 0
        )''')
        await db.execute('''
        CREATE TABLE IF NOT EXISTS adviews(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          day TEXT NOT NULL,
          count INTEGER NOT NULL DEFAULT 0,
          UNIQUE(user_id, day)
        )''')
        await db.execute('''
        CREATE TABLE IF NOT EXISTS resets(
          email TEXT PRIMARY KEY,
          code TEXT NOT NULL,
          ts INTEGER NOT NULL
        )''')
        await db.commit()

@app.on_event('startup')
async def on_start():
    await db_init()

# ---------- Helpers ----------
def now_day_key():
    return time.strftime('%Y-%m-%d', time.gmtime())

def make_token(uid, email):
    payload = {'sub': str(uid), 'email': email, 'exp': int(time.time()) + JWT_EXPIRE}
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def get_claims(authorization: str = Header(None)):
    if not authorization or not authorization.lower().startswith('bearer '):
        raise HTTPException(401, 'Missing token')
    token = authorization.split(' ', 1)[1].strip()
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except Exception:
        raise HTTPException(401, 'Invalid token')

async def get_user(claims=Depends(get_claims)):
    uid = int(claims['sub'])
    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute('SELECT id,email,balance FROM users WHERE id=?', (uid,))
        row = await cur.fetchone()
    if not row:
        raise HTTPException(401, 'User not found')
    return dict(row)

def is_admin(email, password):
    return (
        email == os.getenv('ADMIN_EMAIL', 'admin@example.com') and
        password == os.getenv('ADMIN_PASSWORD', 'change-me')
    )

# ---------- Auth ----------
@app.post('/api/auth/register')
async def register(inp: AuthIn):
    async with aiosqlite.connect(DB) as db:
        try:
            await db.execute(
                'INSERT INTO users(email, passhash) VALUES (?,?)',
                (inp.email.lower(), bcrypt.hash(inp.password))
            )
            await db.commit()
        except Exception as e:
            if 'UNIQUE' in str(e):
                raise HTTPException(409, 'Email already exists')
            raise
        cur = await db.execute('SELECT id FROM users WHERE email=?', (inp.email.lower(),))
        uid = (await cur.fetchone())[0]
    return {'token': make_token(uid, inp.email.lower())}

@app.post('/api/auth/login')
async def login(inp: AuthIn):
    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute('SELECT id, passhash FROM users WHERE email=?', (inp.email.lower(),))
        row = await cur.fetchone()
    if not row or not bcrypt.verify(inp.password, row['passhash']):
        raise HTTPException(401, 'Invalid credentials')
    return {'token': make_token(row['id'], inp.email.lower())}

@app.post('/api/auth/logout')
async def logout():
    return {'ok': True}

@app.post('/api/auth/reset/request')
async def reset_request(email: EmailStr):
    code = str(int(time.time()))[-6:]
    async with aiosqlite.connect(DB) as db:
        await db.execute(
            'INSERT OR REPLACE INTO resets(email, code, ts) VALUES (?,?,?)',
            (email.lower(), code, int(time.time()))
        )
        await db.commit()
    if SMTP_HOST and SMTP_USER:
        msg = EmailMessage()
        msg['From'] = SMTP_FROM
        msg['To'] = email
        msg['Subject'] = 'Your 70/30 reset code'
        msg.set_content(f'Your reset code is: {code}')
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    return {'ok': True}

@app.post('/api/auth/reset/verify')
async def reset_verify(payload: ResetVerifyIn):
    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute('SELECT code,ts FROM resets WHERE email=?', (payload.email.lower(),))
        row = await cur.fetchone()
        if (not row) or (row['code'] != payload.code) or (int(time.time()) - row['ts'] > 900):
            raise HTTPException(400, 'Invalid or expired code')
        await db.execute(
            'UPDATE users SET passhash=? WHERE email=?',
            (bcrypt.hash(payload.newPassword), payload.email.lower())
        )
        await db.execute('DELETE FROM resets WHERE email=?', (payload.email.lower(),))
        await db.commit()
    return {'ok': True}

# ---------- User ----------
@app.get('/api/user/me')
async def me(user=Depends(get_user)):
    return {'id': user['id'], 'email': user['email']}

@app.get('/api/user/balance')
async def balance(user=Depends(get_user)):
    return {'balance': float(user['balance'])}

# ---------- Ads ----------
@app.get('/api/ads/daily-count')
async def daily_count(user=Depends(get_user)):
    day = now_day_key()
    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute('SELECT count FROM adviews WHERE user_id=? AND day=?', (user['id'], day))
        row = await cur.fetchone()
    return {'count': row['count'] if row else 0}

@app.post('/api/ads/watch')
async def watch(user=Depends(get_user)):
    day = now_day_key()
    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute('SELECT count FROM adviews WHERE user_id=? AND day=?', (user['id'], day))
        row = await cur.fetchone()
        current = row['count'] if row else 0
        if current >= DAILY_AD_LIMIT:
            raise HTTPException(429, 'Daily limit reached')
        if row:
            await db.execute('UPDATE adviews SET count=count+1 WHERE user_id=? AND day=?', (user['id'], day))
        else:
            await db.execute('INSERT INTO adviews(user_id, day, count) VALUES (?,?,1)', (user['id'], day))
        user_credit = TOTAL_PAYOUT * USER_SPLIT
        await db.execute('UPDATE users SET balance = balance + ? WHERE id=?', (user_credit, user['id']))
        await db.commit()
    return {'message': 'Recorded', 'credit': round(user_credit, 4)}

# ---------- CPX ----------
@app.get('/api/cpx/sign')
async def cpx_sign(ext_user_id: str):
    digest = hmac.new(CPX_SECURE_KEY.encode(), ext_user_id.encode(), hashlib.sha256).hexdigest()
    return {'secure_hash': digest}

@app.get('/api/cpx/link')
async def cpx_link(user=Depends(get_user)):
    ext_user_id = user['email']  # or str(user['id'])
    digest = hmac.new(CPX_SECURE_KEY.encode(), ext_user_id.encode(), hashlib.sha256).hexdigest()
    url = f'https://offers.cpx-research.com/index.php?app_id={CPX_APP_ID}&ext_user_id={ext_user_id}&secure_hash={digest}'
    return {'url': url}

# ---------- AdGem ----------
@app.get('/api/adgem/url')
async def adgem_url(ext_user_id: str):
    url = f'https://www.adgem.com/offers?user_id={ext_user_id}'
    return {'url': url}

# ---------- Admin ----------
@app.post('/api/admin/login')
async def admin_login(inp: AdminIn):
    if not is_admin(inp.email, inp.password):
        raise HTTPException(401, 'Invalid admin credentials')
    return {'token': make_token(0, inp.email)}

@app.get('/api/admin/metrics')
async def admin_metrics(auth=Depends(get_claims)):
    async with aiosqlite.connect(DB) as db:
        cu = await db.execute('SELECT COUNT(*) FROM users')
        users = (await cu.fetchone())[0]
        cv = await db.execute('SELECT SUM(count) FROM adviews WHERE day=?', (now_day_key(),))
        views = (await cv.fetchone())[0] or 0
        cb = await db.execute('SELECT SUM(balance) FROM users')
        bal = (await cb.fetchone())[0] or 0.0
    return {'users': users, 'viewsToday': views, 'totalPaid': round(bal, 2)}

@app.get('/api/admin/user')
async def admin_user(email: EmailStr, auth=Depends(get_claims)):
    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cu = await db.execute('SELECT id,email,balance FROM users WHERE email=?', (email.lower(),))
        row = await cu.fetchone()
    if not row:
        raise HTTPException(404, 'User not found')
    return dict(row)

# ---------- Health ----------
@app.get('/')
def root():
    return {'ok': True, 'service': '7030 backend'}

from fastapi import APIRouter
router = APIRouter()
@router.get('/health', include_in_schema=False)
def _health():
    return {'ok': True}
app.include_router(router)


# Serve index.html and static web dir
try:
    app.mount('/web', StaticFiles(directory='web'), name='web')
except Exception:
    pass
@app.get('/', include_in_schema=False)
def _root():
    return FileResponse('index.html')
@app.get('/index.html', include_in_schema=False)
def _index():
    return FileResponse('index.html')


# Mount CPX/wallet routes
app.include_router(cpx.router)


import cpx_wallet
app.include_router(cpx_wallet.router)



from fastapi import APIRouter
import sqlite3
dbdebug = APIRouter()
@dbdebug.get("/api/db/debug")
def db_debug():
    info = {}
    try:
        # Your server.py uses aiosqlite.connect(DB), so expose DB
        from server import DB as _DB  # this file
        info["DB"] = _DB
        # Try opening with sqlite3 to inspect tables
        conn = sqlite3.connect(_DB)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        info["tables"] = [r[0] for r in cur.fetchall()]
        if "users" in info["tables"]:
            cur.execute("SELECT COUNT(1) FROM users")
            info["users_count"] = cur.fetchone()[0]
        conn.close()
    except Exception as e:
        info["error"] = str(e)
    return info
app.include_router(dbdebug)


# ===== force-include cpx_wallet (with visible logging) =====
try:
    import cpx_wallet
    try:
        app.include_router(cpx_wallet.router)
        print("CPX_WALLET: router mounted")
    except Exception as _merr:
        print("CPX_WALLET_INCLUDE_ERROR:", _merr)
except Exception as _imp:
    print("CPX_WALLET_IMPORT_ERROR:", _imp)
# ===== end force-include =====

@app.get("/api/_probe_wallet_import")
def _probe_wallet_import():
    try:
        import cpx_wallet  # noqa
        return {"import_ok": True}
    except Exception as e:
        return {"import_ok": False, "error": str(e)}

@app.post("/api/_mount_wallet")
def _mount_wallet():
    try:
        import cpx_wallet
        try:
            app.include_router(cpx_wallet.router)
            return {"mounted": True}
        except Exception as e2:
            return {"mounted": False, "error": f"include failed: {e2}"}
    except Exception as e:
        return {"mounted": False, "error": f"import failed: {e}"}
print("===BOOT MARKER A===")
try:
    import cpx_wallet as _cw
    try:
        app.include_router(_cw.router)
        print("===WALLET ROUTER MOUNTED===")
    except Exception as e2:
        print("===WALLET MOUNT ERROR===", e2)
except Exception as e:
    print("===WALLET IMPORT ERROR===", e)
# === INLINE WALLET (no import/mount issues) ===
import os
from datetime import datetime
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

# Reuse the same DB file as the rest of the app
_DB = globals().get("DB", "db.sqlite")
_DATABASE_URL = os.getenv("DATABASE_URL") or (_DB if str(_DB).startswith("sqlite:///") else f"sqlite:///{_DB}")
_CPX_HASH = os.getenv("CPX_SECURE_HASH", "")

_engine = create_engine(_DATABASE_URL, future=True)

with _engine.begin() as _conn:
    _conn.execute(text("""
CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  source TEXT NOT NULL,
  external_id TEXT NOT NULL,
  gross_cents INTEGER NOT NULL,
  net_cents INTEGER NOT NULL,
  status TEXT NOT NULL,
  meta TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(source, external_id)
)"""))
    _conn.execute(text("""
CREATE TABLE IF NOT EXISTS wallet_balances (
  user_id INTEGER PRIMARY KEY,
  balance_cents INTEGER NOT NULL DEFAULT 0
)"""))

def _w_get_user(conn, email):
    return conn.execute(text("SELECT id, email FROM users WHERE email=:e"), {"e": email}).first()

def _w_ensure(conn, uid):
    conn.execute(text("""
CREATE TABLE IF NOT EXISTS wallet_balances (
  user_id INTEGER PRIMARY KEY,
  balance_cents INTEGER NOT NULL DEFAULT 0
)"""))
    conn.execute(text("""
      INSERT INTO wallet_balances (user_id, balance_cents)
      VALUES (:u, 0)
      ON CONFLICT(user_id) DO NOTHING
    """), {"u": uid})

def _w_balance(conn, uid):
    row = conn.execute(text("SELECT balance_cents FROM wallet_balances WHERE user_id=:u"), {"u": uid}).first()
    return int(row[0]) if row else 0

def _w_add(conn, uid, add_cents):
    conn.execute(text("UPDATE wallet_balances SET balance_cents = balance_cents + :a WHERE user_id=:u"),
                 {"a": int(add_cents), "u": uid})

@app.get("/api/wallet_inline")
def wallet_inline(email: str):
    with _engine.begin() as conn:
        u = _w_get_user(conn, email)
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        _w_ensure(conn, u.id)
        bal = _w_balance(conn, u.id)
        rows = conn.execute(text("""
          SELECT id, source, external_id, gross_cents, net_cents, status, created_at
          FROM transactions WHERE user_id=:u ORDER BY id DESC LIMIT 50
        """), {"u": u.id}).all()
        recent = [{
          "id": r.id, "source": r.source, "external_id": r.external_id,
          "gross_cents": r.gross_cents, "net_cents": r.net_cents,
          "status": r.status, "created_at": r.created_at
        } for r in rows]
    return {"balance_cents": int(bal), "recent": recent}

@app.api_route("/api/cpx/webhook_inline", methods=["GET","POST"])
async def cpx_webhook_inline(request: Request):
    # parse input
    if request.method == "GET":
        data = dict(request.query_params)
    else:
        try:
            data = await request.json()
        except Exception:
            form = await request.form()
            data = dict(form)

    ext_user_id = (data.get("ext_user_id") or data.get("user") or data.get("subid") or "").strip()
    txid        = (data.get("txid") or data.get("clickid") or data.get("transaction_id") or "").strip()
    status      = (data.get("status") or "").lower().strip()
    amount_raw  = (data.get("amount") or "").strip()
    reward_raw  = (data.get("reward") or "").strip()
    incoming    = (data.get("secure_hash") or data.get("hash") or "").strip()

    if not ext_user_id or not txid:
        return JSONResponse({"error": "Missing ext_user_id or txid"}, status_code=400)

    # optional signature for now (we can require it later)
    if _CPX_HASH and incoming and incoming != _CPX_HASH:
        return JSONResponse({"error": "Bad signature"}, status_code=401)

    # dollars->cents or raw cents fallback
    gross_cents = 0
    try:
        if amount_raw:
            gross_cents = int(round(float(amount_raw) * 100))
        elif reward_raw:
            gross_cents = int(float(reward_raw))
    except Exception:
        gross_cents = 0

    net_cents = int(gross_cents * 0.70) if gross_cents > 0 else 0
    allowed = {"approved","confirmed","completed","paid","success"}
    will_credit = (status in allowed) and (net_cents > 0)

    created_at = datetime.utcnow().isoformat()
    import json as _json
    meta_json = _json.dumps(data)

    with _engine.begin() as conn:
        u = _w_get_user(conn, ext_user_id)
        if not u:
            # record ignored for traceability
            try:
                conn.execute(text("""
                  INSERT INTO transactions (user_id, source, external_id, gross_cents, net_cents, status, meta, created_at)
                  VALUES (:uid, 'cpx', :tx, :g, :n, :st, :m, :ts)
                """), {"uid": 0, "tx": txid, "g": gross_cents, "n": net_cents,
                       "st": "ignored", "m": meta_json, "ts": created_at})
            except Exception:
                pass
            return JSONResponse({"ok": True, "credited": False, "reason": "user_not_found"}, status_code=202)

        _w_ensure(conn, u.id)
        # dedupe
        try:
            conn.execute(text("""
              INSERT INTO transactions (user_id, source, external_id, gross_cents, net_cents, status, meta, created_at)
              VALUES (:uid, 'cpx', :tx, :g, :n, :st, :m, :ts)
            """), {"uid": u.id, "tx": txid, "g": gross_cents, "n": net_cents,
                   "st": "credited" if will_credit else "ignored",
                   "m": meta_json, "ts": created_at})
        except IntegrityError:
            return {"ok": True, "deduped": True}

        if will_credit:
            _w_add(conn, u.id, net_cents)

    return {"ok": True, "credited": will_credit, "gross_cents": gross_cents, "net_cents": net_cents}
# === END INLINE WALLET ===
# === INLINE WALLET WIRED (guaranteed mount) ===
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from datetime import datetime
import os, json as _json

try:
    _DB = DB  # from this module (used by aiosqlite.connect(DB))
except NameError:
    _DB = "db.sqlite"

_DATABASE_URL = os.getenv("DATABASE_URL") or (_DB if str(_DB).startswith("sqlite:///") else f"sqlite:///{_DB}")
_engine = create_engine(_DATABASE_URL, future=True)
_CPX_HASH = os.getenv("CPX_SECURE_HASH", "")

with _engine.begin() as _c:
    _c.execute(text("""
CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  source TEXT NOT NULL,
  external_id TEXT NOT NULL,
  gross_cents INTEGER NOT NULL,
  net_cents INTEGER NOT NULL,
  status TEXT NOT NULL,
  meta TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(source, external_id)
)"""))
    _c.execute(text("""
CREATE TABLE IF NOT EXISTS wallet_balances (
  user_id INTEGER PRIMARY KEY,
  balance_cents INTEGER NOT NULL DEFAULT 0
)"""))

def _wi_get_user(conn, email):
    return conn.execute(text("SELECT id, email FROM users WHERE email=:e"), {"e": email}).first()

def _wi_ensure(conn, uid):
    _csql = """
CREATE TABLE IF NOT EXISTS wallet_balances (
  user_id INTEGER PRIMARY KEY,
  balance_cents INTEGER NOT NULL DEFAULT 0
)"""
    conn.execute(text(_csql))
    conn.execute(text("""
      INSERT INTO wallet_balances (user_id, balance_cents)
      VALUES (:u, 0)
      ON CONFLICT(user_id) DO NOTHING
    """), {"u": uid})

def _wi_balance(conn, uid):
    row = conn.execute(text("SELECT balance_cents FROM wallet_balances WHERE user_id=:u"), {"u": uid}).first()
    return int(row[0]) if row else 0

def _wi_add(conn, uid, add_cents):
    conn.execute(text("UPDATE wallet_balances SET balance_cents = balance_cents + :a WHERE user_id=:u"),
                 {"a": int(add_cents), "u": uid})

def wallet_inline(email: str):
    with _engine.begin() as conn:
        u = _wi_get_user(conn, email)
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        _wi_ensure(conn, u.id)
        bal = _wi_balance(conn, u.id)
        rows = conn.execute(text("""
          SELECT id, source, external_id, gross_cents, net_cents, status, created_at
          FROM transactions WHERE user_id=:u ORDER BY id DESC LIMIT 50
        """), {"u": u.id}).all()
        recent = [{
          "id": r.id, "source": r.source, "external_id": r.external_id,
          "gross_cents": r.gross_cents, "net_cents": r.net_cents,
          "status": r.status, "created_at": r.created_at
        } for r in rows]
    return {"balance_cents": int(bal), "recent": recent}

async def cpx_webhook_inline(request: Request):
    # parse input
    if request.method == "GET":
        data = dict(request.query_params)
    else:
        try:
            data = await request.json()
        except Exception:
            form = await request.form()
            data = dict(form)

    ext_user_id = (data.get("ext_user_id") or data.get("user") or data.get("subid") or "").strip()
    txid        = (data.get("txid") or data.get("clickid") or data.get("transaction_id") or "").strip()
    status      = (data.get("status") or "").lower().strip()
    amount_raw  = (data.get("amount") or "").strip()
    reward_raw  = (data.get("reward") or "").strip()
    incoming    = (data.get("secure_hash") or data.get("hash") or "").strip()

    if not ext_user_id or not txid:
        return JSONResponse({"error": "Missing ext_user_id or txid"}, status_code=400)

    # optional signature for now (we can require once CPX hash is set)
    if _CPX_HASH and incoming and incoming != _CPX_HASH:
        return JSONResponse({"error": "Bad signature"}, status_code=401)

    # dollars->cents or raw cents fallback
    gross_cents = 0
    try:
        if amount_raw:
            gross_cents = int(round(float(amount_raw) * 100))
        elif reward_raw:
            gross_cents = int(float(reward_raw))
    except Exception:
        gross_cents = 0

    net_cents = int(gross_cents * 0.70) if gross_cents > 0 else 0
    allowed = {"approved","confirmed","completed","paid","success"}
    will_credit = (status in allowed) and (net_cents > 0)

    created_at = datetime.utcnow().isoformat()
    meta_json = _json.dumps(data)

    with _engine.begin() as conn:
        u = _wi_get_user(conn, ext_user_id)
        if not u:
            try:
                conn.execute(text("""
                  INSERT INTO transactions (user_id, source, external_id, gross_cents, net_cents, status, meta, created_at)
                  VALUES (:uid, 'cpx', :tx, :g, :n, :st, :m, :ts)
                """), {"uid": 0, "tx": txid, "g": gross_cents, "n": net_cents,
                       "st": "ignored", "m": meta_json, "ts": created_at})
            except Exception:
                pass
            return JSONResponse({"ok": True, "credited": False, "reason": "user_not_found"}, status_code=202)

        _wi_ensure(conn, u.id)
        try:
            conn.execute(text("""
              INSERT INTO transactions (user_id, source, external_id, gross_cents, net_cents, status, meta, created_at)
              VALUES (:uid, 'cpx', :tx, :g, :n, :st, :m, :ts)
            """), {"uid": u.id, "tx": txid, "g": gross_cents, "n": net_cents,
                   "st": "credited" if will_credit else "ignored",
                   "m": meta_json, "ts": created_at})
        except IntegrityError:
            return {"ok": True, "deduped": True}

        if will_credit:
            _wi_add(conn, u.id, net_cents)

    return {"ok": True, "credited": will_credit, "gross_cents": gross_cents, "net_cents": net_cents}

# Register routes explicitly
app.add_api_route("/api/wallet_inline", wallet_inline, methods=["GET"])
app.add_api_route("/api/cpx/webhook_inline", cpx_webhook_inline, methods=["GET","POST"])
# === END INLINE WALLET WIRED ===
