"""Demo Fintech Application with deliberate race condition vulnerability."""

import asyncio
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3

app = FastAPI(title="Demo Fintech App")

# Database setup
def init_db():
    conn = sqlite3.connect("fintech.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            account_id TEXT PRIMARY KEY,
            balance REAL NOT NULL,
            updated_at TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_account TEXT,
            to_account TEXT,
            amount REAL,
            timestamp TEXT
        )
    """)
    # Create test accounts
    cursor.execute("INSERT OR REPLACE INTO accounts VALUES (?, ?, ?)",
                   ("ACC001", 1000.0, datetime.utcnow().isoformat()))
    cursor.execute("INSERT OR REPLACE INTO accounts VALUES (?, ?, ?)",
                   ("ACC002", 500.0, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

init_db()


class TransferRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float


@app.get("/")
def root():
    return {"message": "Demo Fintech API", "vulnerable": True}


@app.get("/balance/{account_id}")
def get_balance(account_id: str):
    conn = sqlite3.connect("fintech.db")
    cursor = conn.cursor()
    cursor.execute("SELECT balance FROM accounts WHERE account_id = ?", (account_id,))
    result = cursor.fetchone()
    conn.close()
    if not result:
        raise HTTPException(status_code=404, detail="Account not found")
    return {"account_id": account_id, "balance": result[0]}


@app.post("/transfer")
async def transfer_funds(request: TransferRequest):
    """
    VULNERABILITY: Race condition - balance check not atomic with deduction.
    Multiple concurrent requests can bypass the balance check.
    """
    conn = sqlite3.connect("fintech.db")
    cursor = conn.cursor()
    
    # Check balance (NOT ATOMIC)
    cursor.execute("SELECT balance FROM accounts WHERE account_id = ?",
                   (request.from_account,))
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        raise HTTPException(status_code=404, detail="Account not found")
    
    balance = result[0]
    
    if balance >= request.amount:
        # VULNERABILITY: Delay allows race condition
        await asyncio.sleep(0.1)
        
        # Deduct from source (SEPARATE TRANSACTION)
        cursor.execute(
            "UPDATE accounts SET balance = balance - ?, updated_at = ? WHERE account_id = ?",
            (request.amount, datetime.utcnow().isoformat(), request.from_account)
        )
        
        # Credit to destination
        cursor.execute(
            "UPDATE accounts SET balance = balance + ?, updated_at = ? WHERE account_id = ?",
            (request.amount, datetime.utcnow().isoformat(), request.to_account)
        )
        
        # Log transaction
        cursor.execute(
            "INSERT INTO transactions (from_account, to_account, amount, timestamp) VALUES (?, ?, ?, ?)",
            (request.from_account, request.to_account, request.amount, datetime.utcnow().isoformat())
        )
        
        conn.commit()
        conn.close()
        return {"status": "success", "message": "Transfer completed"}
    else:
        conn.close()
        return {"status": "insufficient_funds", "balance": balance}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
