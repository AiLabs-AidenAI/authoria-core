"""
Tenants/Organizations API routes
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from typing import List, Optional
from pydantic import BaseModel, Field
import uuid
from datetime import datetime

from app.core.database import get_db
from app.core.security import get_current_admin_user

router = APIRouter(prefix="/tenants", tags=["tenants"])


class TenantCreate(BaseModel):
    name: str = Field(..., max_length=200)
    description: Optional[str] = None
    domain: Optional[str] = None
    enabled: bool = True
    auto_approve_domains: List[str] = []


class TenantResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    domain: Optional[str]
    enabled: bool
    auto_approve_domains: List[str]
    created_at: datetime
    updated_at: Optional[datetime]


# Mock data for now - in real implementation, this would be database-backed
MOCK_TENANTS = [
    {
        "id": "1",
        "name": "System Default",
        "description": "Default organization for general users",
        "domain": None,
        "enabled": True,
        "auto_approve_domains": [],
        "created_at": datetime.now(),
        "updated_at": None
    },
    {
        "id": "2", 
        "name": "Acme Corporation",
        "description": "Acme Corp main organization",
        "domain": "acme.com",
        "enabled": True,
        "auto_approve_domains": ["acme.com"],
        "created_at": datetime.now(),
        "updated_at": None
    },
    {
        "id": "3",
        "name": "TechStart Inc.",
        "description": "TechStart startup organization", 
        "domain": "techstart.io",
        "enabled": True,
        "auto_approve_domains": ["techstart.io"],
        "created_at": datetime.now(),
        "updated_at": None
    },
    {
        "id": "4",
        "name": "Global Solutions Ltd.",
        "description": "Global Solutions enterprise organization",
        "domain": "globalsolutions.com", 
        "enabled": True,
        "auto_approve_domains": ["globalsolutions.com"],
        "created_at": datetime.now(),
        "updated_at": None
    }
]


@router.get("/", response_model=List[TenantResponse])
async def get_tenants():
    """Get all available tenants/organizations"""
    return MOCK_TENANTS


@router.get("/{tenant_id}", response_model=TenantResponse)
async def get_tenant(tenant_id: str):
    """Get specific tenant by ID"""
    tenant = next((t for t in MOCK_TENANTS if t["id"] == tenant_id), None)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


@router.post("/", response_model=TenantResponse)
async def create_tenant(
    tenant_data: TenantCreate,
    current_user = Depends(get_current_admin_user)
):
    """Create a new tenant (admin only)"""
    new_tenant = {
        "id": str(len(MOCK_TENANTS) + 1),
        "name": tenant_data.name,
        "description": tenant_data.description,
        "domain": tenant_data.domain,
        "enabled": tenant_data.enabled,
        "auto_approve_domains": tenant_data.auto_approve_domains,
        "created_at": datetime.now(),
        "updated_at": None
    }
    MOCK_TENANTS.append(new_tenant)
    return new_tenant


@router.put("/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: str,
    tenant_data: TenantCreate,
    current_user = Depends(get_current_admin_user)
):
    """Update tenant (admin only)"""
    tenant_index = next((i for i, t in enumerate(MOCK_TENANTS) if t["id"] == tenant_id), None)
    if tenant_index is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    MOCK_TENANTS[tenant_index].update({
        "name": tenant_data.name,
        "description": tenant_data.description,
        "domain": tenant_data.domain,
        "enabled": tenant_data.enabled,
        "auto_approve_domains": tenant_data.auto_approve_domains,
        "updated_at": datetime.now()
    })
    
    return MOCK_TENANTS[tenant_index]


@router.delete("/{tenant_id}")
async def delete_tenant(
    tenant_id: str,
    current_user = Depends(get_current_admin_user)
):
    """Delete tenant (admin only)"""
    tenant_index = next((i for i, t in enumerate(MOCK_TENANTS) if t["id"] == tenant_id), None)
    if tenant_index is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    MOCK_TENANTS.pop(tenant_index)
    return {"message": "Tenant deleted successfully"}