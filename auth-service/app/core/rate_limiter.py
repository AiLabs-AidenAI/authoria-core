"""
Advanced rate limiting with Redis backend
"""

import redis
from datetime import datetime, timedelta
from typing import Optional
from fastapi import HTTPException, status

from .config import get_settings

settings = get_settings()

class RedisRateLimiter:
    def __init__(self):
        self.redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    
    async def check_rate_limit(self, key: str, limit: int, window_seconds: int) -> bool:
        """Check if request is within rate limit"""
        pipe = self.redis_client.pipeline()
        now = datetime.utcnow().timestamp()
        
        # Remove expired entries
        pipe.zremrangebyscore(key, 0, now - window_seconds)
        
        # Count current requests
        pipe.zcard(key)
        
        # Add current request
        pipe.zadd(key, {str(now): now})
        
        # Set expiration
        pipe.expire(key, window_seconds)
        
        results = pipe.execute()
        current_requests = results[1]
        
        return current_requests < limit
    
    async def get_remaining_requests(self, key: str, limit: int, window_seconds: int) -> int:
        """Get remaining requests in current window"""
        now = datetime.utcnow().timestamp()
        current_requests = self.redis_client.zcount(key, now - window_seconds, now)
        return max(0, limit - current_requests)


rate_limiter = RedisRateLimiter()

async def rate_limit(action: str, identifier: str, limit: int, window: int):
    """Rate limiting function"""
    key = f"rate_limit:{action}:{identifier}"
    
    if not await rate_limiter.check_rate_limit(key, limit, window):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {limit} requests per {window} seconds."
        )