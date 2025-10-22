# Rust Auth Service Python Client

A comprehensive Python client library for integrating with the Rust Auth Service. This client provides a simple, type-safe interface for all authentication operations including user registration, login, profile management, and token handling.

## 🎯 Features

- **Complete Authentication Flow**: Registration, login, logout, password management
- **Automatic Token Management**: Handles JWT token storage, refresh, and expiration
- **Type Safety**: Full type hints and dataclass models for all operations
- **Error Handling**: Comprehensive error handling with detailed error messages
- **Retry Logic**: Built-in retry mechanism for network resilience
- **Context Manager Support**: Clean resource management with context managers
- **Thread Safe**: Safe for use in multi-threaded applications

## 🚀 Quick Start

### Installation

```bash
# Install from PyPI (when published)
pip install rust-auth-client

# Or install from source
pip install -e .
```

### Basic Usage

```python
from rust_auth_client import AuthClient

# Initialize client
client = AuthClient('https://auth.example.com/api')

# Register a new user
auth_response = client.register(
    email='user@example.com',
    password='SecurePassword123!',
    first_name='John',
    last_name='Doe'
)

print(f"Welcome, {auth_response.user.full_name}!")

# Login with existing credentials
auth_response = client.login('user@example.com', 'SecurePassword123!')

# Get current user profile
user = client.get_current_user()
print(f"User: {user.email}, Verified: {user.is_verified}")

# Update profile
updated_user = client.update_profile(first_name='Jane')

# Change password
client.change_password('SecurePassword123!', 'NewPassword456!')

# Logout
client.logout()
```

### Context Manager Usage

```python
with AuthClient('https://auth.example.com/api') as client:
    auth_response = client.login('user@example.com', 'password')
    user = client.get_current_user()
    print(f"Logged in as: {user.full_name}")
    # Automatic cleanup when exiting context
```

## 📚 API Reference

### AuthClient

The main client class for interacting with the Rust Auth Service.

#### Constructor

```python
AuthClient(
    base_url: str = 'https://localhost/api',
    timeout: int = 10,
    max_retries: int = 3,
    verify_ssl: bool = True
)
```

**Parameters:**
- `base_url`: Base URL for the auth service API
- `timeout`: Request timeout in seconds
- `max_retries`: Maximum number of retry attempts for failed requests
- `verify_ssl`: Whether to verify SSL certificates

#### Authentication Methods

##### `register(email, password, first_name, last_name) -> AuthResponse`

Register a new user account.

```python
auth_response = client.register(
    email='user@example.com',
    password='SecurePassword123!',
    first_name='John',
    last_name='Doe'
)
```

##### `login(email, password) -> AuthResponse`

Authenticate with email and password.

```python
auth_response = client.login('user@example.com', 'password')
```

##### `logout()`

Log out the current user and clear stored tokens.

```python
client.logout()
```

#### Profile Management

##### `get_current_user() -> User`

Get the current authenticated user's profile.

```python
user = client.get_current_user()
print(f"Name: {user.full_name}")
print(f"Email: {user.email}")
print(f"Role: {user.role}")
print(f"Verified: {user.is_verified}")
```

##### `update_profile(first_name=None, last_name=None, email=None) -> User`

Update the current user's profile information.

```python
# Update first name only
updated_user = client.update_profile(first_name='Jane')

# Update multiple fields
updated_user = client.update_profile(
    first_name='Jane',
    last_name='Smith',
    email='jane.smith@example.com'
)
```

#### Password Management

##### `change_password(current_password, new_password)`

Change the current user's password.

```python
client.change_password('OldPassword123!', 'NewPassword456!')
```

##### `forgot_password(email)`

Request a password reset email.

```python
client.forgot_password('user@example.com')
```

##### `reset_password(token, new_password)`

Reset password using a token from the reset email.

```python
client.reset_password('reset-token-from-email', 'NewPassword456!')
```

#### Email Verification

##### `verify_email(token)`

Verify email address using a verification token.

```python
client.verify_email('verification-token-from-email')
```

#### Utility Methods

##### `is_authenticated() -> bool`

Check if the client has valid authentication tokens.

```python
if client.is_authenticated():
    user = client.get_current_user()
else:
    print("Please log in first")
```

##### `get_access_token() -> Optional[str]`

Get the current access token.

```python
token = client.get_access_token()
if token:
    # Use token for direct API calls
    headers = {'Authorization': f'Bearer {token}'}
```

##### `health_check() -> Dict[str, Any]`

Check the health status of the auth service.

```python
health = client.health_check()
print(f"Service status: {health['status']}")
```

### Data Models

#### User

```python
@dataclass
class User:
    id: str
    email: str
    first_name: str
    last_name: str
    is_active: bool
    is_verified: bool
    role: str
    created_at: datetime
    updated_at: datetime
    
    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"
```

#### AuthResponse

```python
@dataclass
class AuthResponse:
    access_token: str
    token_type: str
    expires_in: int
    user: User
```

### Error Handling

The client raises `AuthError` exceptions for all API-related errors:

```python
from rust_auth_client import AuthClient, AuthError

client = AuthClient('https://auth.example.com/api')

try:
    auth_response = client.login('user@example.com', 'wrong-password')
except AuthError as e:
    print(f"Authentication failed: {e}")
    print(f"Status code: {e.status_code}")
    print(f"Details: {e.details}")
```

## 🔧 Advanced Usage

### Custom Configuration

```python
# Development configuration (disable SSL verification)
client = AuthClient(
    base_url='https://localhost:8443/api',
    timeout=30,
    max_retries=5,
    verify_ssl=False  # Only for development!
)

# Production configuration
client = AuthClient(
    base_url='https://api.production.com',
    timeout=10,
    max_retries=3,
    verify_ssl=True
)
```

### Session Management

The client automatically handles token refresh, but you can also manage it manually:

```python
client = AuthClient()

# Login
auth_response = client.login('user@example.com', 'password')

# The client will automatically refresh tokens when needed
# But you can check authentication status
if client.is_authenticated():
    user = client.get_current_user()

# Manual token clearing
client.clear_tokens()
```

### Integration with Web Frameworks

#### Flask Example

```python
from flask import Flask, request, jsonify, session
from rust_auth_client import AuthClient, AuthError

app = Flask(__name__)
app.secret_key = 'your-secret-key'

client = AuthClient('https://auth.example.com/api')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    try:
        auth_response = client.login(data['email'], data['password'])
        session['access_token'] = auth_response.access_token
        return jsonify({
            'success': True,
            'user': {
                'id': auth_response.user.id,
                'email': auth_response.user.email,
                'full_name': auth_response.user.full_name
            }
        })
    except AuthError as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/profile')
def profile():
    if 'access_token' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Set token for this request
    client._access_token = session['access_token']
    
    try:
        user = client.get_current_user()
        return jsonify({
            'id': user.id,
            'email': user.email,
            'full_name': user.full_name,
            'is_verified': user.is_verified
        })
    except AuthError as e:
        return jsonify({'error': str(e)}), 401
```

#### Django Example

```python
# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rust_auth_client import AuthClient, AuthError
import json

client = AuthClient('https://auth.example.com/api')

@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        
        try:
            auth_response = client.login(data['email'], data['password'])
            request.session['user_data'] = {
                'access_token': auth_response.access_token,
                'user_id': auth_response.user.id
            }
            return JsonResponse({
                'success': True,
                'user': {
                    'email': auth_response.user.email,
                    'full_name': auth_response.user.full_name
                }
            })
        except AuthError as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
```

#### FastAPI Example

```python
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from rust_auth_client import AuthClient, AuthError

app = FastAPI()
client = AuthClient('https://auth.example.com/api')

class LoginRequest(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    is_verified: bool

@app.post("/login")
async def login(request: LoginRequest):
    try:
        auth_response = client.login(request.email, request.password)
        return {
            "access_token": auth_response.access_token,
            "user": UserResponse(
                id=auth_response.user.id,
                email=auth_response.user.email,
                full_name=auth_response.user.full_name,
                is_verified=auth_response.user.is_verified
            )
        }
    except AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))

# Dependency for authenticated endpoints
def get_current_user(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = authorization.split(" ")[1]
    client._access_token = token
    
    try:
        return client.get_current_user()
    except AuthError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/profile", response_model=UserResponse)
async def get_profile(user: User = Depends(get_current_user)):
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_verified=user.is_verified
    )
```

### Async Support

For async applications, you can wrap the client calls:

```python
import asyncio
from concurrent.futures import ThreadPoolExecutor
from rust_auth_client import AuthClient

class AsyncAuthClient:
    def __init__(self, base_url: str):
        self.client = AuthClient(base_url)
        self.executor = ThreadPoolExecutor(max_workers=10)
    
    async def login(self, email: str, password: str):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.executor, 
            self.client.login, 
            email, 
            password
        )
    
    async def get_current_user(self):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.executor,
            self.client.get_current_user
        )

# Usage
async def main():
    client = AsyncAuthClient('https://auth.example.com/api')
    auth_response = await client.login('user@example.com', 'password')
    user = await client.get_current_user()
    print(f"Welcome, {user.full_name}!")
```

## 🧪 Testing

### Unit Tests

```python
import pytest
from unittest.mock import Mock, patch
from rust_auth_client import AuthClient, AuthError

def test_login_success():
    with patch('requests.Session.request') as mock_request:
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            'access_token': 'test-token',
            'token_type': 'Bearer',
            'expires_in': 3600,
            'user': {
                'id': '123',
                'email': 'test@example.com',
                'first_name': 'Test',
                'last_name': 'User',
                'is_active': True,
                'is_verified': True,
                'role': 'user',
                'created_at': '2023-01-01T00:00:00Z',
                'updated_at': '2023-01-01T00:00:00Z'
            }
        }
        mock_request.return_value = mock_response
        
        client = AuthClient()
        auth_response = client.login('test@example.com', 'password')
        
        assert auth_response.access_token == 'test-token'
        assert auth_response.user.email == 'test@example.com'
        assert client.is_authenticated()

def test_login_failure():
    with patch('requests.Session.request') as mock_request:
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 401
        mock_response.json.return_value = {
            'error': 'Invalid credentials',
            'message': 'Email or password is incorrect'
        }
        mock_request.return_value = mock_response
        
        client = AuthClient()
        
        with pytest.raises(AuthError) as exc_info:
            client.login('test@example.com', 'wrong-password')
        
        assert exc_info.value.status_code == 401
        assert 'Invalid credentials' in str(exc_info.value)
```

### Integration Tests

```python
import pytest
from rust_auth_client import AuthClient, AuthError

# These tests require a running Rust Auth Service instance
@pytest.fixture
def client():
    return AuthClient('https://localhost/api', verify_ssl=False)

@pytest.fixture
def test_user():
    return {
        'email': 'test@example.com',
        'password': 'TestPassword123!',
        'first_name': 'Test',
        'last_name': 'User'
    }

def test_full_auth_flow(client, test_user):
    # Register
    auth_response = client.register(**test_user)
    assert auth_response.user.email == test_user['email']
    assert client.is_authenticated()
    
    # Get profile
    user = client.get_current_user()
    assert user.email == test_user['email']
    
    # Update profile
    updated_user = client.update_profile(first_name='Updated')
    assert updated_user.first_name == 'Updated'
    
    # Logout
    client.logout()
    assert not client.is_authenticated()
    
    # Login again
    auth_response = client.login(test_user['email'], test_user['password'])
    assert client.is_authenticated()
```

## 🚀 Production Deployment

### Requirements

```txt
# requirements.txt
rust-auth-client==1.0.0
requests>=2.25.0
urllib3>=1.26.0
```

### Environment Configuration

```python
import os
from rust_auth_client import AuthClient

# Configure client from environment
client = AuthClient(
    base_url=os.getenv('AUTH_SERVICE_URL', 'https://auth.example.com/api'),
    timeout=int(os.getenv('AUTH_TIMEOUT', '10')),
    verify_ssl=os.getenv('AUTH_VERIFY_SSL', 'true').lower() == 'true'
)
```

### Docker Example

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

ENV AUTH_SERVICE_URL=https://auth.example.com/api
ENV AUTH_VERIFY_SSL=true

CMD ["python", "app.py"]
```

### Logging Configuration

```python
import logging
from rust_auth_client import AuthClient

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

client = AuthClient('https://auth.example.com/api')

try:
    auth_response = client.login('user@example.com', 'password')
    logger.info(f"User {auth_response.user.email} logged in successfully")
except AuthError as e:
    logger.error(f"Login failed: {e}")
```

## 🐛 Troubleshooting

### Common Issues

#### SSL Certificate Errors

```python
# For development environments with self-signed certificates
client = AuthClient(
    base_url='https://localhost/api',
    verify_ssl=False  # Only for development!
)
```

#### Connection Timeouts

```python
# Increase timeout for slow networks
client = AuthClient(
    base_url='https://auth.example.com/api',
    timeout=30,  # 30 seconds
    max_retries=5
)
```

#### Token Expiration

```python
from rust_auth_client import AuthError

try:
    user = client.get_current_user()
except AuthError as e:
    if e.status_code == 401:
        # Token expired, need to re-authenticate
        auth_response = client.login(email, password)
        user = client.get_current_user()
```

### Debug Mode

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("requests").setLevel(logging.DEBUG)
logging.getLogger("urllib3").setLevel(logging.DEBUG)

client = AuthClient('https://auth.example.com/api')
# All HTTP requests will now be logged
```

## 📝 Examples

See the `examples/` directory for complete example applications:

- `flask_app.py` - Flask web application
- `django_app/` - Django project
- `fastapi_app.py` - FastAPI application
- `cli_tool.py` - Command-line interface
- `async_example.py` - Async/await usage

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Run the test suite: `pytest`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Ready to build secure authentication in Python! 🐍🔐**