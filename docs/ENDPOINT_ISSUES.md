# Endpoint Implementation Issues

## Overview
This document outlines critical issues with the current endpoint implementation that need to be addressed for the authentication service to function properly.

## Critical Issues

### 1. Missing OAuth2 Routes in main.rs
**Priority: HIGH**

The OAuth2 handlers have been implemented in `src/handlers/oauth2.rs` but are not registered in the main router in `src/main.rs`. This means all OAuth2 endpoints are inaccessible.

**Missing OAuth2 Routes:**
- `GET /oauth2/authorize` - OAuth2 authorization endpoint
- `POST /oauth2/authorize` - OAuth2 consent form submission
- `POST /oauth2/token` - OAuth2 token endpoint
- `POST /oauth2/device` - Device authorization endpoint
- `GET /oauth2/device` - Device verification page
- `POST /oauth2/device/verify` - Device verification submission
- `POST /oauth2/introspect` - Token introspection (RFC 7662)
- `POST /oauth2/revoke` - Token revocation (RFC 7009)
- `GET /.well-known/oauth-authorization-server` - OAuth2 metadata (RFC 8414)
- `GET /.well-known/jwks.json` - JWKS endpoint
- `POST /oauth2/clients` - Client registration
- `GET /oauth2/clients/:id` - Get client info
- `PUT /oauth2/clients/:id` - Update client
- `DELETE /oauth2/clients/:id` - Delete client
- `GET /oauth2/clients` - List clients

### 2. OAuth2Server Method Implementation Issues
**Priority: HIGH**

The OAuth2 handlers are calling methods on `OAuth2Server` that don't exist or have incorrect signatures:

**Missing Methods:**
- `handle_authorization_request()` - Called in authorize and authorize_consent_post handlers
- `get_client()` - Called in authorize_consent handler
- `handle_token_request()` - Called in token handler
- `authorize_device_code()` - Called in device_verify_post handler
- `introspect_token()` - Called in introspect handler
- `revoke_token()` - Called in revoke handler
- `get_metadata()` - Called in metadata handler
- `get_jwks()` - Called in jwks handler

**Method Signature Issues:**
- `handle_device_authorization()` is called with 2 arguments but takes 1

### 3. Duplicate Auth Handler Files
**Priority: MEDIUM**

There are two auth handler files:
- `src/handlers/auth.rs` - Full implementation (630+ lines)
- `src/handlers/auth_simple.rs` - Simplified stubs (117 lines)

Currently `mod.rs` imports from `auth.rs`, but `auth_simple.rs` exists and may cause confusion.

### 4. AppState Integration Issues
**Priority: HIGH**

The OAuth2 handlers expect OAuth2-related state (OAuth2Server, OAuth2ClientManager) but the current `AppState` in `main.rs` only contains:
```rust
pub struct AppState {
    pub config: Arc<Config>,
    pub database: Arc<dyn AuthDatabase>,
    pub cache: Arc<CacheService>,
}
```

**Missing OAuth2 State:**
- `OAuth2Server` instance
- `OAuth2ClientManager` instance
- `TokenManager` instance
- `MfaManager` instance (for future MFA integration)

### 5. Missing MFA Routes
**Priority: MEDIUM**

MFA module has been started but no routes are defined. Will need:
- `POST /mfa/setup` - Setup MFA method
- `POST /mfa/challenge` - Create MFA challenge
- `POST /mfa/verify` - Verify MFA challenge
- `GET /mfa/methods` - List user's MFA methods
- `DELETE /mfa/methods/:id` - Remove MFA method
- `POST /mfa/backup-codes` - Generate backup codes

### 6. Handler Function Naming Conflicts
**Priority: LOW**

Some handler functions have generic names that might conflict:
- Multiple `register` functions
- Multiple `login` functions

## Impact

**Current Status: NON-FUNCTIONAL**
- OAuth2 functionality is completely inaccessible (0% working)
- Authentication works but no OAuth2 provider capabilities
- No MFA capabilities
- Client management impossible

## Resolution Plan

### Phase 1: Fix OAuth2Server Implementation (Critical)
1. Implement missing methods in `OAuth2Server`:
   - Bridge to existing `OAuth2FlowHandler` methods
   - Add proper method signatures
   - Ensure all handler calls work

### Phase 2: Add OAuth2 Routes to main.rs (Critical)
1. Create OAuth2 router with all endpoints
2. Add OAuth2 state to `AppState`
3. Initialize OAuth2 components in main()
4. Merge OAuth2 routes into main router

### Phase 3: Clean Up Handler Files (Medium)
1. Remove `auth_simple.rs` or clarify its purpose
2. Resolve any naming conflicts
3. Ensure consistent error handling

### Phase 4: Add MFA Integration (Medium)
1. Complete MFA module implementation
2. Add MFA routes
3. Integrate MFA with auth flows

## Testing Requirements

After fixes:
1. All OAuth2 flows must be testable
2. Authorization code flow with PKCE
3. Client credentials flow
4. Device code flow
5. Token introspection and revocation
6. Client registration and management

## Security Implications

- OAuth2 provider functionality is core security feature
- Missing endpoints mean no third-party app integration possible
- Client management issues could lead to security vulnerabilities
- Proper testing required before production use

## Estimated Effort

- **Phase 1**: 4-6 hours (OAuth2Server fixes)
- **Phase 2**: 2-3 hours (Route integration)
- **Phase 3**: 1-2 hours (Cleanup)
- **Phase 4**: 6-8 hours (MFA completion)

**Total**: 13-19 hours to fully resolve all endpoint issues.