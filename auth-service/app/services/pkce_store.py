"""
PKCE verifier storage using Database
"""
from typing import Optional
from datetime import datetime, timedelta
from sqlalchemy import Column, String, DateTime, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import AsyncSessionLocal, Base
import logging
import asyncio

logger = logging.getLogger(__name__)

class PKCEVerifier(Base):
    __tablename__ = "pkce_verifiers"
    
    state = Column(String(255), primary_key=True, index=True)
    verifier = Column(String(255), nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class PKCEStore:
    def __init__(self):
        self._cleanup_task = None
        self._start_cleanup_task()
    
    def _start_cleanup_task(self):
        """Start background cleanup task"""
        try:
            loop = asyncio.get_event_loop()
            if not loop.is_running():
                return
            self._cleanup_task = loop.create_task(self._periodic_cleanup())
        except RuntimeError:
            # No event loop running, cleanup will be manual
            pass
    
    async def _periodic_cleanup(self):
        """Periodic cleanup of expired verifiers"""
        while True:
            try:
                await asyncio.sleep(300)  # Cleanup every 5 minutes
                await self.cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Periodic cleanup error: {e}")

    async def store_verifier(self, state: str, verifier: str, ttl: int = 600):
        """Store PKCE verifier with TTL (default 10 minutes)"""
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                async with AsyncSessionLocal() as db:
                    expires_at = datetime.utcnow() + timedelta(seconds=ttl)
                    
                    # Delete any existing entry for this state
                    await db.execute(
                        delete(PKCEVerifier).where(PKCEVerifier.state == state)
                    )
                    
                    pkce_entry = PKCEVerifier(
                        state=state,
                        verifier=verifier,
                        expires_at=expires_at
                    )
                    
                    db.add(pkce_entry)
                    await db.commit()
                    
                    logger.debug(f"Stored PKCE verifier for state: {state[:8]}...")
                    return
                    
            except Exception as e:
                retry_count += 1
                logger.error(f"Failed to store PKCE verifier (attempt {retry_count}/{max_retries}): {e}")
                if retry_count >= max_retries:
                    raise
                await asyncio.sleep(0.1 * retry_count)  # Exponential backoff
    
    async def get_verifier(self, state: str) -> Optional[str]:
        """Retrieve and delete PKCE verifier"""
        if not state:
            return None
            
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                async with AsyncSessionLocal() as db:
                    # Get verifier if not expired
                    result = await db.execute(
                        delete(PKCEVerifier)
                        .where(PKCEVerifier.state == state)
                        .where(PKCEVerifier.expires_at > datetime.utcnow())
                        .returning(PKCEVerifier.verifier)
                    )
                    
                    await db.commit()
                    
                    row = result.fetchone()
                    if row:
                        logger.debug(f"Retrieved PKCE verifier for state: {state[:8]}...")
                        return row[0]
                    
                    logger.warning(f"PKCE verifier not found or expired for state: {state[:8]}...")
                    return None
                    
            except Exception as e:
                retry_count += 1
                logger.error(f"Failed to retrieve PKCE verifier (attempt {retry_count}/{max_retries}): {e}")
                if retry_count >= max_retries:
                    return None
                await asyncio.sleep(0.1 * retry_count)  # Exponential backoff
        
        return None
    
    async def cleanup_expired(self):
        """Remove expired PKCE verifiers"""
        try:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    delete(PKCEVerifier)
                    .where(PKCEVerifier.expires_at < datetime.utcnow())
                )
                await db.commit()
                
                deleted_count = result.rowcount
                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} expired PKCE verifiers")
                    
        except Exception as e:
            logger.error(f"Failed to cleanup expired PKCE verifiers: {e}")

# Singleton instance
_pkce_store = PKCEStore()

def get_pkce_store() -> PKCEStore:
    return _pkce_store
