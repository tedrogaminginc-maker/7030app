
from datetime import datetime
import os, json
from typing import List

from fastapi import APIRouter, Request, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

# --- Resolve DB to match server.py ---
DB_FILE = os.getenv("DB", "")
try:
    # server.py defines DB used by aiosqlite.connect(DB)
    from server import DB as _SERVER_DB
    if isinstance(_SERVER_DB, str) and _SERVER_DB:
        DB_FILE = _SERVER_DB
except Exception:
    pass

env_url = os.getenv("DATABASE_URL", "")
if env_url:
    DATABASE_URL = env_url
else:
    if not DB_FILE:
        DB_FILE = "db.sqlite"
    DATABASE_URL = DB_FILE if DB_FILE.startswith("sqlite:///") else f"sqlite:///{DB_FILE}"

CPX_SECURE_HASH = os.getenv("CPX_SECURE_HASH", "")  # optional for now

engine = create_engine(DATABASE_URL, future=True)
router = APIRouter(prefix="/api", tags=["wallet"])
# ---- schema: create tables explicitly ----
with engine.begin() as conn:
    conn.execute(text("""
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
)
"""))
    conn.execute(text("""
CREATE TABLE IF NOT EXISTS wallet_balances (
  user_id INTEGER PRIMARY KEY,
  balance_cents INTEGER NOT NULL DEFAULT 0
)
"""))

def _ensure_wallet(conn, user_id:int) -> None:
    conn.execute(text("""
CREATE TABLE IF NOT EXISTS wallet_balances (
  user_id INTEGER PRIMARY KEY,
  balance_cents INTEGER NOT NULL DEFAULT 0
)
"""))
    conn.execute(text("""
      INSERT INTO wallet_balances (user_id, balance_cents)
      VALUES (:u, 0)
      ON CONFLICT(user_id) DO NOTHING
    """), {"u": user_id})

def _get_user_by_email(conn, email:str):
    return conn.execute(
        text("SELECT id, email FROM users WHERE email=:e"),
        {"e": email}
    ).first()

def _get_balance(conn, user_id:int) -> int:
    row = conn.execute(
        text("SELECT balance_cents FROM wallet_balances WHERE user_id=:u"),
        {"u": user_id}
    ).first()
    return int(row[0]) if row else 0

def _add_balance(conn, user_id:int, add_cents:int) -> None:
    conn.execute(
        text("UPDATE wallet_balances SET balance_cents = balance_cents + :a WHERE user_id=:u"),
        {"a": add_cents, "u": user_id}
    )
# Plain JSON to avoid model validation surprises
@router.get("/wallet")
def wallet(email: str = Query(..., description="User email for lookup")):
    with engine.begin() as conn:
        u = _get_user_by_email(conn, email)
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        _ensure_wallet(conn, u.id)
        bal = _get_balance(conn, u.id)
        rows = conn.execute(text("""
          SELECT id, source, external_id, gross_cents, net_cents, status, created_at
          FROM transactions
          WHERE user_id=:u
          ORDER BY id DESC
          LIMIT 50
        """), {"u": u.id}).all()
        recent = [{
            "id": r.id, "source": r.source, "external_id": r.external_id,
            "gross_cents": r.gross_cents, "net_cents": r.net_cents,
            "status": r.status, "created_at": r.created_at
        } for r in rows]
    return {"balance_cents": int(bal), "recent": recent}

@router.get("/wallet/debug")
def wallet_debug():
    info = {"DATABASE_URL": DATABASE_URL}
    try:
        if DATABASE_URL.startswith("sqlite:///"):
            info["sqlite_file"] = DATABASE_URL.replace("sqlite:///","")
        with engine.begin() as conn:
            names = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")).all()
            info["tables"] = [n[0] for n in names]
            if "users" in info["tables"]:
                info["users_count"] = int(conn.execute(text("SELECT COUNT(1) FROM users")).scalar() or 0)
            if "wallet_balances" in info["tables"]:
                info["wallet_count"] = int(conn.execute(text("SELECT COUNT(1) FROM wallet_balances")).scalar() or 0)
            if "transactions" in info["tables"]:
                info["tx_count"] = int(conn.execute(text("SELECT COUNT(1) FROM transactions")).scalar() or 0)
    except Exception as e:
        info["error"] = str(e)
    return info
@router.api_route("/cpx/webhook", methods=["GET","POST"])
async def cpx_webhook(request: Request):
    # Parse input
    if request.method == "GET":
        data = dict(request.query_params)
    else:
        try:
            data = await request.json()
        except Exception:
            form = await request.form()
            data = dict(form)

    ext_user_id = (data.get("ext_user_id") or data.get("user") or data.get("subid") or "").strip()
    txid = (data.get("txid") or data.get("clickid") or data.get("transaction_id") or "").strip()
    status = (data.get("status") or "").lower().strip()
    amount_raw = (data.get("amount") or "").strip()
    reward_raw = (data.get("reward") or "").strip()
    incoming_hash = (data.get("secure_hash") or data.get("hash") or "").strip()

    if not ext_user_id or not txid:
        return JSONResponse({"error":"Missing ext_user_id or txid"}, status_code=400)

    # Optional signature for now (we can require it after you set CPX_SECURE_HASH in env)
    if CPX_SECURE_HASH and incoming_hash and incoming_hash != CPX_SECURE_HASH:
        return JSONResponse({"error":"Bad signature"}, status_code=401)

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
    meta_json = json.dumps(data)

    with engine.begin() as conn:
        u = _get_user_by_email(conn, ext_user_id)
        if not u:
            # track ignored for observability
            try:
                conn.execute(text("""
                  INSERT INTO transactions (user_id, source, external_id, gross_cents, net_cents, status, meta, created_at)
                  VALUES (:uid, 'cpx', :tx, :g, :n, :st, :m, :ts)
                """), {"uid": 0, "tx": txid, "g": gross_cents, "n": net_cents,
                       "st": "ignored", "m": meta_json, "ts": created_at})
            except Exception:
                pass
            return JSONResponse({"ok": True, "credited": False, "reason":"user_not_found"}, status_code=202)

        _ensure_wallet(conn, u.id)

        # Dedupe by (source, external_id)
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
            _add_balance(conn, u.id, net_cents)

    return {"ok": True, "credited": will_credit, "gross_cents": gross_cents, "net_cents": net_cents}
