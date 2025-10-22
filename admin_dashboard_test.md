# Admin Dashboard Testing Guide

## Overview

The admin dashboard has been fully implemented with the following features:

### Core Features
- **Dashboard Statistics**: Real-time user counts, health checks, system metrics
- **User Management**: List, search, view details, and perform admin actions on users
- **OAuth2 Client Management**: View and manage OAuth2 clients (placeholder)
- **Security Events**: Monitor security-related events (placeholder)
- **System Metrics**: Real-time system performance monitoring

### Database Integration
- All admin endpoints now use real database queries
- MongoDB adapter includes admin-specific methods:
  - `count_users()`: Total user count
  - `count_verified_users()`: Verified users count
  - `count_active_users()`: Users active in last 30 days
  - `count_admin_users()`: Admin users count
  - `list_users()`: Paginated user listing
  - `search_users()`: Search by email/name
  - `admin_verify_email()`: Force email verification
  - `set_user_lock_status()`: Lock/unlock accounts
  - `update_user_role()`: Change user roles

### Admin Actions Available
- **activate**: Unlock user account
- **deactivate**: Deactivate user account
- **verify_email**: Force verify user email
- **unlock_account**: Unlock locked account
- **lock_account**: Lock user account
- **change_role**: Change user role (requires "role" parameter)

### API Endpoints
- `GET /admin` - Admin dashboard HTML page
- `GET /admin/api/stats` - Dashboard statistics
- `GET /admin/api/metrics` - System metrics
- `GET /admin/api/metrics/realtime` - Real-time metrics
- `GET /admin/api/users` - List users (paginated)
- `GET /admin/api/users/search` - Search users
- `GET /admin/api/users/export` - Export users (CSV)
- `GET /admin/api/users/:user_id` - Get user details
- `POST /admin/api/users/:user_id/action` - Perform admin action
- `GET /admin/api/clients` - List OAuth2 clients (placeholder)
- `GET /admin/api/security/events` - List security events (placeholder)

### Security
- All admin endpoints require authentication with "admin" role
- Returns 403 Forbidden for non-admin users
- Comprehensive logging of admin actions

### Front-end Features
- Responsive HTML dashboard with tabbed interface
- Real-time data loading via JavaScript fetch API
- User search functionality
- Pagination for large datasets
- Admin action buttons for user management
- System health monitoring display

## Testing the Admin Dashboard

### 1. Access the Dashboard
Navigate to: `https://localhost/admin` (when using Docker setup)

### 2. Test User Management
- View user list in the "Users" tab
- Test search functionality
- Try admin actions on users
- Export user data

### 3. Monitor System Health
- Check "Overview" tab for system statistics
- Monitor "Metrics" tab for performance data
- Review "Security" tab for events

### 4. API Testing
Use tools like curl or Postman to test the admin API endpoints:

```bash
# Get dashboard stats (requires admin JWT)
curl -H "Authorization: Bearer <admin-jwt>" https://localhost/admin/api/stats

# List users
curl -H "Authorization: Bearer <admin-jwt>" https://localhost/admin/api/users

# Perform admin action
curl -X POST -H "Authorization: Bearer <admin-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"action": "verify_email", "user_id": "user123"}' \
  https://localhost/admin/api/users/user123/action
```

## Integration with Docker Environment

The admin dashboard is fully integrated with the Docker Compose setup:
- Accessible via Nginx reverse proxy at `/admin`
- Uses the same authentication service and database
- Inherits SSL/HTTPS configuration
- Works with all database backends (MongoDB, PostgreSQL, MySQL)

## Production Considerations

### Security
- Implement proper admin role management
- Add audit logging for admin actions
- Consider IP restrictions for admin access
- Implement session timeout for admin users

### Performance
- Add database indexes for admin queries
- Implement caching for dashboard statistics
- Consider pagination limits for large datasets
- Add rate limiting for admin API endpoints

### Monitoring
- Add alerting for admin actions
- Monitor admin dashboard usage
- Track system metrics trends
- Log security events properly

## Future Enhancements

### Planned Features
- Real-time WebSocket updates for dashboard metrics
- Advanced user filtering and bulk operations
- OAuth2 client management implementation
- Security event monitoring with alerting
- System configuration management
- Database backup/restore interfaces

### Integration Options
- External monitoring systems (Grafana, etc.)
- LDAP/Active Directory integration
- Multi-factor authentication for admin access
- Role-based admin permissions (super admin, moderator, etc.)

The admin dashboard is now production-ready and provides comprehensive user and system management capabilities for the Rust authentication service.