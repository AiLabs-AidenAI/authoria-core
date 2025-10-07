"""API v1 package"""

from fastapi import APIRouter
from .routes import auth, admin, users, tenants, admin_config, roles, bulk_users

router = APIRouter()

# Include routers
router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
router.include_router(admin.router, prefix="/admin", tags=["Admin"])
router.include_router(users.router, prefix="/users", tags=["Users"])
router.include_router(tenants.router, prefix="/tenants", tags=["Tenants"])
router.include_router(admin_config.router, prefix="/admin/config", tags=["Admin Config"])
router.include_router(roles.router, prefix="/admin", tags=["Roles"])
router.include_router(bulk_users.router, prefix="/users", tags=["Bulk Users"])
