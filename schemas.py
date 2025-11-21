"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal

class User(BaseModel):
    """
    Users collection schema
    Collection name: "user" (lowercase of class name)
    """
    email: EmailStr = Field(..., description="Unique email address")
    name: Optional[str] = Field(None, description="Full name")
    role: Literal["trader", "admin", "developer"] = Field("trader", description="Access role")
    password_hash: str = Field(..., description="BCrypt password hash")
    mfa_enabled: bool = Field(False, description="Is MFA enabled")
    mfa_secret: Optional[str] = Field(None, description="Base32 TOTP secret if MFA enabled")
    is_active: bool = Field(True, description="Whether user is active")
