"""
Data models for the Rust Auth Service Python client.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class User:
    """User model representing a user account."""
    
    id: str
    email: str
    first_name: str
    last_name: str
    is_active: bool
    is_verified: bool
    role: str
    created_at: datetime
    updated_at: datetime
    
    @classmethod
    def from_dict(cls, data: dict) -> 'User':
        """Create User instance from dictionary."""
        return cls(
            id=data['id'],
            email=data['email'],
            first_name=data['first_name'],
            last_name=data['last_name'],
            is_active=data['is_active'],
            is_verified=data['is_verified'],
            role=data['role'],
            created_at=datetime.fromisoformat(data['created_at'].replace('Z', '+00:00')),
            updated_at=datetime.fromisoformat(data['updated_at'].replace('Z', '+00:00')),
        )
    
    @property
    def full_name(self) -> str:
        """Get the user's full name."""
        return f"{self.first_name} {self.last_name}"


@dataclass
class AuthResponse:
    """Authentication response containing tokens and user data."""
    
    access_token: str
    token_type: str
    expires_in: int
    user: User
    
    @classmethod
    def from_dict(cls, data: dict) -> 'AuthResponse':
        """Create AuthResponse instance from dictionary."""
        return cls(
            access_token=data['access_token'],
            token_type=data['token_type'],
            expires_in=data['expires_in'],
            user=User.from_dict(data['user']),
        )


@dataclass
class LoginRequest:
    """Login request data."""
    
    email: str
    password: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API requests."""
        return {
            'email': self.email,
            'password': self.password,
        }


@dataclass
class RegisterRequest:
    """Registration request data."""
    
    email: str
    password: str
    first_name: str
    last_name: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API requests."""
        return {
            'email': self.email,
            'password': self.password,
            'first_name': self.first_name,
            'last_name': self.last_name,
        }


@dataclass
class UpdateProfileRequest:
    """Profile update request data."""
    
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API requests, excluding None values."""
        return {k: v for k, v in {
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
        }.items() if v is not None}


@dataclass
class ChangePasswordRequest:
    """Change password request data."""
    
    current_password: str
    new_password: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API requests."""
        return {
            'current_password': self.current_password,
            'new_password': self.new_password,
        }


@dataclass
class ForgotPasswordRequest:
    """Forgot password request data."""
    
    email: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API requests."""
        return {
            'email': self.email,
        }


@dataclass
class ResetPasswordRequest:
    """Reset password request data."""
    
    token: str
    new_password: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API requests."""
        return {
            'token': self.token,
            'new_password': self.new_password,
        }


@dataclass
class VerifyEmailRequest:
    """Email verification request data."""
    
    token: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API requests."""
        return {
            'token': self.token,
        }


@dataclass
class RefreshTokenRequest:
    """Refresh token request data."""
    
    refresh_token: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API requests."""
        return {
            'refresh_token': self.refresh_token,
        }