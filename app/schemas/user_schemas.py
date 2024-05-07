from pydantic import BaseModel, EmailStr, Field, validator, root_validator
from typing import Optional, List
from datetime import datetime
from enum import Enum
import uuid
from app.models.user_model import UserRole
from app.utils.nickname_gen import generate_nickname
from validators import url as url_validator

def validate_url(url: Optional[str]) -> Optional[str]:
    if url is None:
        return url
    allowed_protocols = ['http', 'https']
    if not url_validator(url) or not any(url.startswith(f"{protocol}://") for protocol in allowed_protocols):
        raise ValueError('Invalid URL format or protocol not allowed')
    return url

class UserBase(BaseModel):
    email: EmailStr
    nickname: Optional[str] = Field(None, min_length=3, pattern=r'^[\w-]+$')
    first_name: Optional[str]
    last_name: Optional[str]
    bio: Optional[str]
    profile_picture_url: Optional[str]
    linkedin_profile_url: Optional[str]
    github_profile_url: Optional[str]
    role: UserRole

    _validate_urls = validator('profile_picture_url', 'linkedin_profile_url', 'github_profile_url', pre=True, allow_reuse=True)(validate_url)
 
class UserCreate(UserBase):
    password: str = Field(..., example="Secure*1234")

class UserUpdate(UserBase):
    email: Optional[EmailStr]
    role: Optional[UserRole]

    @root_validator(pre=True)
    def check_at_least_one_value(cls, values):
        if not any(values.values()):
            raise ValueError("At least one field must be provided for update")
        return values

class UserResponse(UserBase):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    is_professional: Optional[bool] = Field(default=False)

class LoginRequest(BaseModel):
    email: str
    password: str

class ErrorResponse(BaseModel):
    error: str
    details: Optional[str]

class UserListResponse(BaseModel):
    items: List[UserResponse]
    total: int
    page: int
    size: int
