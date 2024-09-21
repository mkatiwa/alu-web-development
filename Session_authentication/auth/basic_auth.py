#!/usr/bin/env python3
""" Auth Class
"""
import base64
from typing import TypeVar
from models.user import User
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """ Auth Class
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """ extract_base64_authorization_header
        """
        if not authorization_header or type(authorization_header) != str:
            return None
        if authorization_header[:6] != 'Basic ':
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header:
                                           str) -> str:
        """ decode_base64_authorization_header
        """
        if not base64_authorization_header:
            return None
        if type(base64_authorization_header) != str:
            return None
        try:
            return base64.b64decode(
                base64_authorization_header).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header:
                                 str) -> (str, str):
        """ extract_user_credentials
        """
        if not decoded_base64_authorization_header:
            return None, None
        if type(decoded_base64_authorization_header) != str:
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        return decoded_base64_authorization_header.split(':', 1)

    def user_object_from_credentials(self,
                                     user_email: str,
                                     user_pwd: str
                                     ) -> TypeVar('User'):
        """ user_object_from_credentials
        """
        if not user_email or type(user_email) != str:
            return None
        if not user_pwd or type(user_pwd) != str:
            return None
        try:
            user = User.search({'email': user_email})
        except Exception:
            return None
        if not user:
            return None
        if user[0].is_valid_password(user_pwd):
            return user[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ current_user
        """
        auth = self.authorization_header(request)
        if not auth:
            return None
        base64_auth = self.extract_base64_authorization_header(auth)
        if not base64_auth:
            return None
        decoded_base64_auth = self.decode_base64_authorization_header(
            base64_auth)
        if not decoded_base64_auth:
            return None
        user = self.extract_user_credentials(decoded_base64_auth)
        if not user:
            return None
        email, pwd = user
        return self.user_object_from_credentials(email, pwd)
