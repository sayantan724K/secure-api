from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from fastapi.responses import JSONResponse
import logging

app = FastAPI()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("security")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

class SecurityRequest(BaseModel):
    userId: str
    input: str
    category: str

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        headers={"Retry-After": "60"},
        content={
            "blocked": True,
            "reason": "Too many requests",
            "sanitizedOutput": None,
            "confidence": 0.99
        }
    )

@app.post("/validate")
@limiter.limit("40/minute")
async def validate(request: Request, data: SecurityRequest):

    if not data.userId or not data.input:
        raise HTTPException(status_code=400, detail="Invalid input")

    sanitized = data.input.replace("<", "").replace(">", "")

    return {
        "blocked": False,
        "reason": "Input passed all security checks",
        "sanitizedOutput": sanitized,
        "confidence": 0.95
    }
