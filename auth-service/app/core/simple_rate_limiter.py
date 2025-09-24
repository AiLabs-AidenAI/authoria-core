"""
Simple in-memory rate limiter (for development without Redis)
"""

from datetime import datetime, timedelta
from typing import Dict, List
from fastapi import HTTPException, status

class SimpleRateLimiter:
    def __init__(self):
        self.attempts: Dict[str, List[datetime]] = {}
    
    async def check_rate_limit(self, key: str, limit: int, window_seconds: int) -> bool:
        """Check if request is within rate limit"""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=window_seconds)
        
        # Clean old attempts
        if key in self.attempts:
            self.attempts[key] = [
                attempt for attempt in self.attempts[key] 
                if attempt > window_start
            ]
        else:
            self.attempts[key] = []
        
        # Check if limit exceeded
        if len(self.attempts[key]) >= limit:
            return False
        
        # Record this attempt
        self.attempts[key].append(now)
        return True

rate_limiter = SimpleRateLimiter()

async def rate_limit(action: str, identifier: str, limit: int, window: int):
    """Rate limiting function"""
    key = f"rate_limit:{action}:{identifier}"
    
    if not await rate_limiter.check_rate_limit(key, limit, window):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {limit} requests per {window} seconds."
        )