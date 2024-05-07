import logging
from typing import Optional, List
from uuid import UUID
from datetime import datetime, timezone
from pydantic import ValidationError
from sqlalchemy import func, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_email_service
from app.models.user_model import User, UserRole
from app.schemas.user_schemas import UserCreate, UserUpdate, UserResponse
from app.utils.nickname_gen import generate_nickname
from app.utils.security import generate_verification_token, hash_password, verify_password

logger = logging.getLogger(__name__)

class UserService:

    @classmethod
    async def _execute_query(cls, session: AsyncSession, query):
        try:
            result = await session.execute(query)
            await session.commit()
            return result
        except SQLAlchemyError as e:
            logger.error(f"Database error: {e}")
            await session.rollback()
            return None

    @classmethod
    async def _fetch_user(cls, session: AsyncSession, **filters) -> Optional[User]:
        query = select(User).filter_by(**filters)
        result = await cls._execute_query(session, query)
        return result.scalars().first() if result else None

    @classmethod
    async def create(cls, session: AsyncSession, user_data: Dict[str, str], email_service: EmailService) -> Optional[User]:
        if 'password' not in user_data or not user_data['password']:
            logger.error("Password is required and cannot be empty.")
            return 'PASSWORD_REQUIRED'
        if len(user_data['password'].strip()) < 8:  
            logger.error("Password too short.")
            return 'PASSWORD_TOO_SHORT'
        
        existing_user = await cls.get_by_email(session, user_data.get('email'))
        if existing_user:
            logger.error("User with given email already exists.")
            return None

        user_count = await cls.count(session)
        user_role = UserRole.ADMIN if user_count == 0 else UserRole.ANONYMOUS
        user_data['role'] = user_role  
        try:
            validated_data = UserCreate(**user_data).dict(exclude_unset=True)
            validated_data['hashed_password'] = hash_password(user_data['password'])
            validated_data.pop('password', None)
            validated_data['nickname'] = await cls._generate_unique_nickname(session)
            validated_data['email_verified'] = (validated_data['role'] == UserRole.ADMIN)
            validated_data['verification_token'] = None if validated_data['role'] == UserRole.ADMIN else generate_verification_token()

            new_user = User(**validated_data)
            session.add(new_user)
            await session.commit()
            if not validated_data['email_verified']:
                await email_service.send_verification_email(new_user)
            return new_user
        except ValidationError as e:
            logger.error(f"Validation error during user creation: {e}")
            return None

    @classmethod
    async def _generate_unique_nickname(cls, session: AsyncSession) -> str:
        nickname = generate_nickname()
        while await cls.get_by_nickname(session, nickname):
            nickname = generate_nickname()
        return nickname

    @classmethod
    async def update(cls, session: AsyncSession, user_id: UUID, update_data: Dict[str, str]) -> Optional[User]:
        try:
            validated_data = UserUpdate(**update_data).dict(exclude_unset=True)
            if 'password' in validated_data:
                validated_data['hashed_password'] = hash_password(validated_data.pop('password'))
            
            query = update(User).where(User.id == user_id).values(**validated_data).execution_options(synchronize_session="fetch")
            result = await cls._execute_query(session, query)
            if result is None:
                logger.error(f"Update failed for User {user_id}")
                return None

            updated_user = await cls.get_by_id(session, user_id)
            if updated_user:
                session.refresh(updated_user)
                logger.info(f"User {user_id} updated successfully.")
                return updated_user
            else:
                logger.error(f"User {user_id} not found after update attempt.")
                return None
        except Exception as e:
            logger.error(f"Error during user update: {e}")
            return None

    # Additional methods remain mostly unchanged, but ensure to use async and await properly, handle exceptions, and use logging effectively.

