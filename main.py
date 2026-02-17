from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from collections import defaultdict, deque
import time
import logging

app = FastAPI()

# -------------------- LOGGING --------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("security")

# -------------------- CONFIG --------------------
MAX_REQUESTS = 40
BURST_LIMIT = 11
WINDOW_SIZE = 60  # seconds

# -------------------- MEMORY STORE --------------------
request_store = defaultdict(deque)

# -------------------- REQUEST MODEL --------------------
class SecurityRequest(BaseModel):
    userId: str
    input: str
    category: str

# -------------------- RATE LIMIT FUNCTION --------------------
def is_rate_limited(identifier: str):
    current_time = time.time()
    window_start = current_time - WINDOW_SIZE

    requests = request_store[identifier]

    # Remove old timestamps
    while requests and requests[0] < window_start:
        requests.popleft()

    # Check burst (instant flood protection)
    if len(requests) >= BURST_LIMIT and (current_time - requests[-BURST_LIMIT]) < 1:
        return True, 1

    # Check 40 per minute
    if len(requests) >= MAX_REQUESTS:
        retry_after = int(WINDOW_SIZE - (current_time - requests[0]))
        return True, retry_after

    # Allow request
    requests.append(current_time)
    return False, None

# -------------------- ENDPOINT --------------------
@app.post("/validate")
async def validate(request: Request, data: SecurityRequest):

    # -------- Input Validation --------
    if not data.userId or not data.input:
        return JSONResponse(
            status_code=400,
            content={
                "blocked": True,
                "reason": "Invalid input format",
                "sanitizedOutput": None,
                "confidence": 0.98
            }
        )

    # -------- Identify User + IP --------
    client_ip = request.client.host
    identifier = f"{data.userId}:{client_ip}"

    blocked, retry_after = is_rate_limited(identifier)

    if blocked:
        logger.warning(f"Rate limit exceeded: {identifier}")

        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(retry_after)},
            content={
                "blocked": True,
                "reason": "Rate limit exceeded",
                "sanitizedOutput": None,
                "confidence": 0.99
            }
        )

    # -------- Output Sanitization --------
    sanitized = (
        data.input
        .replace("<", "")
        .replace(">", "")
        .replace("script", "")
    )

    logger.info(f"Request allowed: {identifier}")

    return {
        "blocked": False,
        "reason": "Input passed all security checks",
        "sanitizedOutput": sanitized,
        "confidence": 0.95
    }
