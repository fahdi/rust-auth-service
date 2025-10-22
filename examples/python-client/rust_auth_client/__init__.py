"""
Rust Auth Service Python Client

A comprehensive Python client library for integrating with the Rust Auth Service.
Provides a simple, type-safe interface for authentication operations.
"""

from .client import AuthClient, AuthError
from .models import User, AuthResponse, LoginRequest, RegisterRequest

__version__ = "1.0.0"
__all__ = [
    "AuthClient",
    "AuthError", 
    "User",
    "AuthResponse",
    "LoginRequest",
    "RegisterRequest",
]