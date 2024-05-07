from datetime import timedelta
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, require_role
from app.schemas.user_schemas import UserUpdate, UserResponse
from app.services.user_service import UserService
from app.utils.link_generation import create_user_links

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

@router.put("/profile/update", response_model=UserResponse, tags=["Profile"])
async def update_profile(
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: UUID = Depends(get_current_user)
):
    """
    Update user profile information for the currently logged-in user.
    """
    updated_user = await UserService.update_user(db, current_user, user_update.dict(exclude_unset=True))
    if not updated_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return updated_user

@router.get("/users/{user_id}", response_model=UserResponse, name="get_user", tags=["User Management"])
async def get_user(
    user_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_role(["ADMIN", "MANAGER"]))
):
    """
    Fetch a user by their UUID. Requires admin or manager role.
    Includes HATEOAS links for possible actions based on the user's role.
    """
    user = await UserService.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse(**user.dict(), links=create_user_links(user.id, request.url_for))

@router.put("/users/{user_id}", response_model=UserResponse, tags=["User Management"])
async def update_user(
    user_id: UUID,
    user_update: UserUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_role(["ADMIN", "MANAGER"]))
):
    """
    Update user details by ID. Requires admin or manager role.
    """
    updated_user = await UserService.update_user(db, user_id, user_update.dict(exclude_unset=True))
    if not updated_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse(**updated_user.dict(), links=create_user_links(updated_user.id, request.url_for))
