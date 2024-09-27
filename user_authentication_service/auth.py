#!/usr/bin/env python3
""" Authentication module
"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import uuid


def _hash_password(password: str) -> str:
    """ Hash password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """ Generate UUID
    """
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initialize a new Auth instance.
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a user
        """
        try:
            user = self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))

    def valid_login(self, email: str, password: str) -> bool:
        """Validate a login
        """
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode('utf-8'),
                                  user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """Create a session
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> str:
        """ returns a string or None """
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        else:
            return user

    def destroy_session(self, user_id: int) -> None:
        """ destroys a session
        """
        try:
            user = self._db.find_user_by(id=user_id)
        except NoResultFound:
            return None
        else:
            self._db.update_user(user.id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """ returns a string or None """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        else:
            reset_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token

    def update_password(self, rest_token: str, password: str) -> None:
        """ updates a password
        """
        try:
            user = self._db.find_user_by(reset_token=rest_token)
        except NoResultFound:
            raise ValueError
        else:
            self._db.update_user(user.id,
                                 hashed_password=_hash_password(password),
                                 reset_token=None)
