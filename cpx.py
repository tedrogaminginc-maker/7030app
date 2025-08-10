from datetime import datetime
from typing import Optional, List, Dict, Any
import os
import json

from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.engine import Engine

# --- Config ---
CPX_APP_ID = os.getenv("CPX_APP_ID", "28541")
CPX_SECURE_HASH = os.getenv("CPX_SECURE_HASH", "qTNDcrRbH2XGbK4oT1QvWODM21PiXGMf")  # simple mode you tested
CPX_BASE = "https://offers.cpx-research.com/index.php"

# Expect your app already builds an engine; if not, fall back to sqlite db file.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
engine: Engine = create_engine(DATABASE_URL, future=True)

# Your auth dependency (import from your code). Adjust import path if needed.
try:
    from auth import get_current_user  # returns dict with at least id, email
except Exception:
    # Fallback stub for dev only
    def get_current_user():
        raise HTTPException(status_code=500, detail="get_current_user not wired")

router = APIRouter(prefix="/api", tags=["cpx"])

# --- one-time table setup (idempotent) ---
DDL = """
CREATE TABLE IF NOT EXISTS wallet_balances (
  user_id INTEGER PRIMARY KEY,
  balance_cents INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  source TEXT NOT NULL,             -- 'cpx'
  external_id TEXT NOT NULL,        -- CPX txid or clickid
  gross_cents INTEGER NOT NULL,
  net_cents INTEGER NOT NULL,
  status TEXT NOT NULL,             -- 'credited','ignored','pending'
  meta TEXT,                        -- raw payload
  created_at TEXT NOT NULL,
  UNIQUE (source, external_id)
);
"""
with engine.begin() as conn:
    # Execute multiple statements
    for stmt in DDL.strip().split(";\n\n"):
        if stmt.strip():
            conn.execute(text(stmt))

def ensure_wallet_row(user_id: int):
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO wallet_balances (user_id, balance_cents)
            VALUES (:uid, 0)
            ON CONFLICT(user_id) DO NOTHING
        """), {"uid": user_id})

class WalletTx(BaseModel):
    id: int
    source: str
    external_id: str
    gross_cents: int
    net_cents: int
    status: str
    created_at: str

class WalletOut(BaseModel):
    balance_cents: int
    recent: List[WalletTx]

@router.get("/wallet", response_model=WalletOut)
def get_wallet(user = Depends(get_current_user)):
    ensure_wallet_row(user["id"])
    with engine.begin() as conn:
        bal = conn.execute(text("SELECT balance_cents FROM wallet_balances WHERE user_id=:uid"),
                           {"uid": user["id"]}).scalar_one()
        rows = conn.execute(text("""
            SELECT id, source, external_id, gross_cents, net_cents, status, created_at
            FROM transactions
            WHERE user_id=:uid
            ORDER BY id DESC
            LIMIT 25
        """), {"uid": user["id"]}).all()
    recent = [WalletTx(
        id=r.id, source=r.source, external_id=r.external_id,
        gross_cents=r.gross_cents, net_cents=r.net_cents,
        status=r.status, created_at=r.created_at
    ) for r in rows]
    return WalletOut(balance_cents=bal, recent=recent)

@router.get("/cpx/url")
def cpx_url(user = Depends(get_current_user)):
    """
    Returns the per-user CPX URL you already tested.
    Uses your fixed secure_hash for now (CPX setting you showed worked).
    """
    ext_user_id = user["email"]
    url = f"{CPX_BASE}?app_id=28541&ext_user_id={ext_user_id}&secure_hash=qTNDcrRbH2XGbK4oT1QvWODM21PiXGMf"
    return {"url": url}

def _parse_amount_to_cents(amount_raw: Optional[str], reward_raw: Optional[str]) -> int:
    """
    CPX may send either amount (e.g. 0.40) or reward (points). We’ll favor amount.
    """
    if amount_raw:
        try:
            # Interpret dollars -> cents
            cents = int(round(float(amount_raw) * 100))
            if cents >= 0:
                return cents
        except Exception:
            pass
    if reward_raw:
        try:
            # If CPX is configured so reward is already USD cents, keep it.
            # Otherwise, treat as cents conservatively.
            cents = int(float(reward_raw))
            if cents >= 0:
                return cents
        except Exception:
            pass
    return 0

@router.api_route("/cpx/webhook", methods=["GET","POST"])
async def cpx_webhook(request: Request):
    """
    Minimal CPX webhook:
      - dedupe by external_id (txid/clickid)
      - credit 70% of gross_cents to the referenced user
      - basic status filter
    Expected fields (lenient): ext_user_id, txid or clickid, amount, reward, status
    """
    if request.method == "GET":
        data = dict(request.query_params)
    else:
        try:
            data = await request.json()
        except Exception:
            form = await request.form()
            data = dict(form)

    ext_user_id = data.get("ext_user_id") or data.get("user") or data.get("subid") or ""
    txid = data.get("txid") or data.get("clickid") or data.get("transaction_id") or ""
    status = (data.get("status") or "").lower()
    amount_raw = data.get("amount")
    reward_raw = data.get("reward")

    if not ext_user_id or not txid:
        raise HTTPException(status_code=400, detail="Missing ext_user_id or txid")

    gross_cents = _parse_amount_to_cents(amount_raw, reward_raw)
    if gross_cents <= 0:
        # Record but ignore zero/invalid amounts
        net_cents = 0
    else:
        net_cents = int(gross_cents * 0.70)

    # Basic status allowlist
    allowed = {"approved","confirmed","completed","paid","success"}
    will_credit = status in allowed and net_cents > 0

    # Lookup user by email
    with engine.begin() as conn:
        user_row = conn.execute(text("SELECT id, email FROM users WHERE email=:e"), {"e": ext_user_id}).first()
        if not user_row:
            # Could 202 Accepted and store pending; for now, log and ignore
            raise HTTPException(status_code=202, detail="User not found; stored as ignored")

        user_id = user_row.id
        ensure_wallet_row(user_id)

        # Insert transaction (dedupe on (source, external_id))
        created_at = datetime.utcnow().isoformat()
        meta_json = json.dumps(data)
        try:
            conn.execute(text("""
                INSERT INTO transactions (user_id, source, external_id, gross_cents, net_cents, status, meta, created_at)
                VALUES (:uid, 'cpx', :tx, :gross, :net, :status, :meta, :ts)
            """), {"uid": user_id, "tx": txid, "gross": gross_cents, "net": net_cents,
                   "status": "credited" if will_credit else "ignored",
                   "meta": meta_json, "ts": created_at})
        except IntegrityError:
            # duplicate — treat as success but do nothing
            return JSONResponse({"ok": True, "deduped": True})

        # Credit wallet if allowed
        if will_credit:
            conn.execute(text("""
                UPDATE wallet_balances SET balance_cents = balance_cents + :amt WHERE user_id=:uid
            """), {"amt": net_cents, "uid": user_id})

    return {"ok": True, "credited": will_credit, "gross_cents": gross_cents, "net_cents": net_cents}
