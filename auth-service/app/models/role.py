"""
Role and Permission Models for User Management
"""

from sqlalchemy import Column, String, Boolean, DateTime, Text, ForeignKey, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from .user import Base

# Association table for user-role many-to-many relationship
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    Column('role_id', UUID(as_uuid=True), ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
    Column('assigned_at', DateTime, default=datetime.utcnow),
    Column('assigned_by', UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
)

class Role(Base):
    """User roles for access control"""
    __tablename__ = "roles"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(50), unique=True, nullable=False, index=True)
    display_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    is_system_role = Column(Boolean, default=False, nullable=False)  # Cannot be deleted
    is_admin_role = Column(Boolean, default=False, nullable=False)  # Grants admin access
    permissions = Column(Text, nullable=True)  # JSON string of permissions
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    users = relationship("User", secondary=user_roles, back_populates="roles")

    def __repr__(self):
        return f"<Role {self.name}>"

# Predefined system roles
SYSTEM_ROLES = [
    {
        "name": "super_admin",
        "display_name": "Super Administrator",
        "description": "Full system access with all permissions",
        "is_system_role": True,
        "is_admin_role": True,
        "permissions": ["*"]  # All permissions
    },
    {
        "name": "admin",
        "display_name": "Administrator",
        "description": "Standard admin with user management capabilities",
        "is_system_role": True,
        "is_admin_role": True,
        "permissions": [
            "user.read", "user.create", "user.update", "user.delete",
            "signup.approve", "signup.reject", "audit.read"
        ]
    },
    {
        "name": "moderator",
        "display_name": "Moderator",
        "description": "Can review and approve user signups",
        "is_system_role": True,
        "is_admin_role": False,
        "permissions": ["signup.read", "signup.approve", "signup.reject", "user.read"]
    },
    {
        "name": "user",
        "display_name": "Standard User",
        "description": "Regular user with basic access",
        "is_system_role": True,
        "is_admin_role": False,
        "permissions": ["profile.read", "profile.update"]
    }
]