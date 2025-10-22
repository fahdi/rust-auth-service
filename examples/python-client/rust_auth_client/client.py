"""
Python client for the Rust Auth Service.

This module provides a comprehensive client for interacting with the Rust Auth Service API.
It handles authentication, token management, and provides a simple interface for all
authentication operations.
"""

import json
import time
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .models import (
    User, AuthResponse, LoginRequest, RegisterRequest, UpdateProfileRequest,
    ChangePasswordRequest, ForgotPasswordRequest, ResetPasswordRequest,
    VerifyEmailRequest, RefreshTokenRequest
)


class AuthError(Exception):
    """Exception raised for authentication-related errors."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, details: Optional[Dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.details = details or {}


class AuthClient:
    """
    Python client for the Rust Auth Service.
    
    This client provides a simple interface for authentication operations including
    login, registration, profile management, and token handling.
    
    Example:
        >>> client = AuthClient('https://auth.example.com/api')
        >>> auth_response = client.login('user@example.com', 'password123')
        >>> user = client.get_current_user()
        >>> print(f"Welcome, {user.full_name}!")
    """
    
    def __init__(
        self,
        base_url: str = 'https://localhost/api',
        timeout: int = 10,
        max_retries: int = 3,
        verify_ssl: bool = True
    ):
        """
        Initialize the AuthClient.
        
        Args:
            base_url: Base URL for the auth service API
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Token storage
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None
        
        # Set up session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'rust-auth-python-client/1.0.0'
        })
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        authenticated: bool = True
    ) -> requests.Response:
        """
        Make an HTTP request to the API.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (without base URL)
            data: Request body data
            params: Query parameters
            authenticated: Whether to include authentication headers
            
        Returns:
            HTTP response object
            
        Raises:
            AuthError: If the request fails
        """
        url = f"{self.base_url}{endpoint}"
        
        # Add authentication header if needed
        headers = {}
        if authenticated and self._access_token:
            # Check if token needs refresh
            if self._token_expires_at and datetime.now() >= self._token_expires_at:
                self._refresh_access_token()
            headers['Authorization'] = f'Bearer {self._access_token}'
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            # Handle specific status codes
            if response.status_code == 401 and authenticated:
                # Try to refresh token once
                if self._refresh_token:
                    try:
                        self._refresh_access_token()
                        headers['Authorization'] = f'Bearer {self._access_token}'
                        response = self.session.request(
                            method=method,
                            url=url,
                            json=data,
                            params=params,
                            headers=headers,
                            timeout=self.timeout,
                            verify=self.verify_ssl
                        )
                    except AuthError:
                        # Refresh failed, clear tokens
                        self.clear_tokens()
                        raise AuthError("Authentication failed. Please log in again.", 401)
                
                if response.status_code == 401:
                    self.clear_tokens()
                    raise AuthError("Authentication failed. Please log in again.", 401)
            
            # Check for other error status codes
            if not response.ok:
                try:
                    error_data = response.json()
                    message = error_data.get('message', error_data.get('error', 'Request failed'))
                    details = error_data.get('details', {})
                except (json.JSONDecodeError, ValueError):
                    message = f"HTTP {response.status_code}: {response.reason}"
                    details = {}
                
                raise AuthError(message, response.status_code, details)
            
            return response
            
        except requests.exceptions.RequestException as e:
            raise AuthError(f"Network error: {str(e)}")
    
    def _set_tokens(self, access_token: str, refresh_token: Optional[str] = None, expires_in: Optional[int] = None):
        """Store authentication tokens."""
        self._access_token = access_token
        if refresh_token:
            self._refresh_token = refresh_token
        
        if expires_in:
            # Set expiration time with a 5-minute buffer
            self._token_expires_at = datetime.now() + timedelta(seconds=expires_in - 300)
    
    def clear_tokens(self):
        """Clear stored authentication tokens."""
        self._access_token = None
        self._refresh_token = None
        self._token_expires_at = None
    
    def _refresh_access_token(self):
        """Refresh the access token using the refresh token."""
        if not self._refresh_token:
            raise AuthError("No refresh token available")
        
        request_data = RefreshTokenRequest(refresh_token=self._refresh_token)
        response = self._make_request('POST', '/auth/refresh', request_data.to_dict(), authenticated=False)
        
        token_data = response.json()
        self._set_tokens(
            access_token=token_data['access_token'],
            expires_in=token_data.get('expires_in')
        )
    
    def register(self, email: str, password: str, first_name: str, last_name: str) -> AuthResponse:
        """
        Register a new user account.
        
        Args:
            email: User's email address
            password: User's password
            first_name: User's first name
            last_name: User's last name
            
        Returns:
            AuthResponse containing tokens and user data
            
        Raises:
            AuthError: If registration fails
        """
        request_data = RegisterRequest(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )
        
        response = self._make_request('POST', '/auth/register', request_data.to_dict(), authenticated=False)
        auth_data = response.json()
        auth_response = AuthResponse.from_dict(auth_data)
        
        self._set_tokens(
            access_token=auth_response.access_token,
            expires_in=auth_response.expires_in
        )
        
        return auth_response
    
    def login(self, email: str, password: str) -> AuthResponse:
        """
        Authenticate a user with email and password.
        
        Args:
            email: User's email address
            password: User's password
            
        Returns:
            AuthResponse containing tokens and user data
            
        Raises:
            AuthError: If login fails
        """
        request_data = LoginRequest(email=email, password=password)
        
        response = self._make_request('POST', '/auth/login', request_data.to_dict(), authenticated=False)
        auth_data = response.json()
        auth_response = AuthResponse.from_dict(auth_data)
        
        self._set_tokens(
            access_token=auth_response.access_token,
            expires_in=auth_response.expires_in
        )
        
        return auth_response
    
    def logout(self):
        """
        Log out the current user.
        
        This will invalidate the current session and clear stored tokens.
        """
        try:
            self._make_request('POST', '/auth/logout', authenticated=True)
        except AuthError:
            # Continue with logout even if API call fails
            pass
        finally:
            self.clear_tokens()
    
    def get_current_user(self) -> User:
        """
        Get the current authenticated user's profile.
        
        Returns:
            User object with current user data
            
        Raises:
            AuthError: If not authenticated or request fails
        """
        response = self._make_request('GET', '/auth/me', authenticated=True)
        user_data = response.json()
        return User.from_dict(user_data)
    
    def update_profile(self, first_name: Optional[str] = None, last_name: Optional[str] = None, email: Optional[str] = None) -> User:
        """
        Update the current user's profile.
        
        Args:
            first_name: New first name (optional)
            last_name: New last name (optional)
            email: New email address (optional)
            
        Returns:
            Updated User object
            
        Raises:
            AuthError: If not authenticated or update fails
        """
        request_data = UpdateProfileRequest(
            first_name=first_name,
            last_name=last_name,
            email=email
        )
        
        response = self._make_request('PUT', '/auth/profile', request_data.to_dict(), authenticated=True)
        user_data = response.json()
        return User.from_dict(user_data)
    
    def change_password(self, current_password: str, new_password: str):
        """
        Change the current user's password.
        
        Args:
            current_password: Current password for verification
            new_password: New password to set
            
        Raises:
            AuthError: If not authenticated or password change fails
        """
        request_data = ChangePasswordRequest(
            current_password=current_password,
            new_password=new_password
        )
        
        self._make_request('POST', '/auth/change-password', request_data.to_dict(), authenticated=True)
    
    def forgot_password(self, email: str):
        """
        Request a password reset for the given email address.
        
        Args:
            email: Email address to send reset instructions to
            
        Raises:
            AuthError: If the request fails
        """
        request_data = ForgotPasswordRequest(email=email)
        self._make_request('POST', '/auth/forgot-password', request_data.to_dict(), authenticated=False)
    
    def reset_password(self, token: str, new_password: str):
        """
        Reset password using a reset token.
        
        Args:
            token: Password reset token from email
            new_password: New password to set
            
        Raises:
            AuthError: If the reset fails
        """
        request_data = ResetPasswordRequest(token=token, new_password=new_password)
        self._make_request('POST', '/auth/reset-password', request_data.to_dict(), authenticated=False)
    
    def verify_email(self, token: str):
        """
        Verify email address using a verification token.
        
        Args:
            token: Email verification token from email
            
        Raises:
            AuthError: If verification fails
        """
        request_data = VerifyEmailRequest(token=token)
        self._make_request('POST', '/auth/verify', request_data.to_dict(), authenticated=False)
    
    def is_authenticated(self) -> bool:
        """
        Check if the client has valid authentication tokens.
        
        Returns:
            True if authenticated, False otherwise
        """
        return self._access_token is not None
    
    def get_access_token(self) -> Optional[str]:
        """
        Get the current access token.
        
        Returns:
            Current access token or None if not authenticated
        """
        return self._access_token
    
    def health_check(self) -> Dict[str, Any]:
        """
        Check the health status of the auth service.
        
        Returns:
            Dictionary containing health status information
            
        Raises:
            AuthError: If health check fails
        """
        response = self._make_request('GET', '/health', authenticated=False)
        return response.json()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close session."""
        self.session.close()