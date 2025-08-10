from datetime import datetime
import os, json
from typing import List

from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

# ---- Config ----
CPX_SECURE_HASH = os.getenv("CPX_SECURE_HASH", "")  # optional, if set we require it on webhook
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")

engine = create_engine(DATABASE_URL, future=True)
router = APIRouter(prefix="/api", tags=["wallet"])

# Try to import your auth dependency
try:
    from auth import get_current_user
except Exception:
    def get_current_user():
        raise HTTPException(status_code=500, detail="get_current_user not wired")

# ---- Schema (idempotent) ----
DDL = """
CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  source TEXT NOT NULL,         -- 'cpx'
  external_id TEXT NOT NULL,    -- CPX txid/clickid
  gross_cents INTEGER NOT NULL,
  net_cents INTEGER NOT NULL,
  status TEXT NOT NULL,         -- credited/ignored
  meta TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(source, external_id)
);
"""
with engine.begin() as conn:
    conn.execute(text(DDL))

def _ensure_wallet_storage(conn, user_id:int):
    # Prefer users.balance_cents if present; otherwise fallback to wallet_balances table.
    try:
        conn.execute(text("SELECT balance_cents FROM users WHERE id=:u"), {"u": user_id}).first()
        return "users"
    except Exception:
        pass

    # Fallback wallet_balances table
    conn.execute(text("""
      CREATE TABLE IF NOT EXISTS wallet_balances (
        user_id INTEGER PRIMARY KEY,
        balance_cents INTEGER NOT NULL DEFAULT 0
      )
    """))
    # Ensure row
    conn.execute(text("""
      INSERT INTO wallet_balances (user_id, balance_cents) VALUES (:u, 0)
      ON CONFLICT(user_id) DO NOTHING
    """), {"u": user_id})
    return "wallet_balances"

def _get_balance(conn, user_id:int):
    # Try users.balance_cents first
    try:
        row = conn.execute(text("SELECT balance_cents FROM users WHERE id=:u"), {"u": user_id}).first()
        if row is not None and row[0] is not None:
            return int(row[0])
    except Exception:
        pass
    # Else wallet_balances
    row = conn.execute(text("SELECT balance_cents FROM wallet_balances WHERE user_id=:u"), {"u": user_id}).first()
    return int(row[0]) if row else 0

def _add_balance(conn, user_id:int, add_cents:int):
    target = _ensure_wallet_storage(conn, user_id)
    if target == "users":
        conn.execute(text("UPDATE users SET balance_cents = COALESCE(balance_cents,0) + :a WHERE id=:u"),
                     {"a": add_cents, "u": user_id})
    else:
        conn.execute(text("UPDATE wallet_balances SET balance_cents = balance_cents + :a WHERE user_id=:u"),
                     {"a": add_cents, "u": user_id})

class TxOut(BaseModel):
    id:int
    source:str
    external_id:str
    gross_cents:int
    net_cents:int
    status:str
    created_at:str

class WalletOut(BaseModel):
    balance_cents:int
    recent:List[TxOut]

@router.get("/wallet", response_model=WalletOut)
def wallet(user=Depends(get_current_user)):
    with engine.begin() as conn:
        bal = _get_balance(conn, user["id"])
        rows = conn.execute(text("""
          SELECT id, source, external_id, gross_cents, net_cents, status, created_at
          FROM transactions WHERE user_id=:u ORDER BY id DESC LIMIT 50
        """), {"u": user["id"]}).all()
    recent = [TxOut(id=r.id, source=r.source, external_id=r.external_id,
                    gross_cents=r.gross_cents, net_cents=r.net_cents,
                    status=r.status, created_at=r.created_at) for r in rows]
    return WalletOut(balance_cents=bal, recent=recent)

@router.api_route("/cpx/webhook", methods=["GET","POST"])
async def cpx_webhook(request: Request):
    """
    Minimal CPX webhook:
      - optional secure_hash check (if CPX_SECURE_HASH is set)
      - dedupe by external_id (txid/clickid)
      - status allowlist
      - 70% credit
    Accepts ext_user_id, txid/clickid, amount (USD), reward (fallback), status.
    """
    # Parse incoming
    if request.method == "GET":
        data = dict(request.query_params)
    else:
        try:
            data = await request.json()
        except Exception:
            form = await request.form()
            data = dict(form)

    # Optional hash check (defense-in-depth)
    incoming_hash = (data.get("secure_hash") or data.get("hash") or "").strip()
    if CPX_SECURE_HASH and incoming_hash and incoming_hash != CPX_SECURE_HASH:
        raise HTTPException(status_code=401, detail="Bad signature")

    ext_user_id = (data.get("ext_user_id") or data.get("user") or data.get("subid") or "").strip()
    txid = (data.get("txid") or data.get("clickid") or data.get("transaction_id") or "").strip()
    status = (data.get("status") or "").lower().strip()
    amount_raw = (data.get("amount") or "").strip()
    reward_raw = (data.get("reward") or "").strip()

    if not ext_user_id or not txid:
        raise HTTPException(status_code=400, detail="Missing ext_user_id or txid")

    # Parse cents
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

    meta_json = json.dumps(data)
    created_at = datetime.utcnow().isoformat()

    with engine.begin() as conn:
        # find user
        u = conn.execute(text("SELECT id,email FROM users WHERE email=:e"), {"e": ext_user_id}).first()
        if not u:
            # no user: store ignored entry to help debug
            try:
                conn.execute(text("""
                  INSERT INTO transactions (user_id, source, external_id, gross_cents, net_cents, status, meta, created_at)
                  VALUES (:uid, 'cpx', :tx, :g, :n, :st, :m, :ts)
                """), {"uid": 0, "tx": txid, "g": gross_cents, "n": net_cents,
                       "st": "ignored", "m": meta_json, "ts": created_at})
            except Exception:
                pass
            raise HTTPException(status_code=202, detail="User not found; stored ignored")

        user_id = int(u.id)

        # record tx (dedupe on source+external_id)
        try:
            conn.execute(text("""
              INSERT INTO transactions (user_id, source, external_id, gross_cents, net_cents, status, meta, created_at)
              VALUES (:uid, 'cpx', :tx, :g, :n, :st, :m, :ts)
            """), {"uid": user_id, "tx": txid, "g": gross_cents, "n": net_cents,
                   "st": "credited" if will_credit else "ignored",
                   "m": meta_json, "ts": created_at})
        except IntegrityError:
            return JSONResponse({"ok": True, "deduped": True})

        # credit wallet
        if will_credit:
            _add_balance(conn, user_id, net_cents)

    return {"ok": True, "credited": will_credit, "gross_cents": gross_cents, "net_cents": net_cents}
