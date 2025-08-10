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



