// MongoDB initialization script for authentication service
print('=== Initializing MongoDB for Rust Auth Service ===');

// Switch to auth_service database
db = db.getSiblingDB('auth_service');

// Create application user with read/write access
db.createUser({
  user: 'auth_app_user',
  pwd: 'auth_app_password',
  roles: [
    {
      role: 'readWrite',
      db: 'auth_service'
    }
  ]
});

// Create users collection with proper indexes
db.createCollection('users');

// Create indexes for optimal query performance
db.users.createIndex({ "email": 1 }, { unique: true, name: "email_unique" });
db.users.createIndex({ "user_id": 1 }, { unique: true, name: "user_id_unique" });
db.users.createIndex({ "email_verification_token": 1 }, { sparse: true, name: "email_verification_token" });
db.users.createIndex({ "password_reset_token": 1 }, { sparse: true, name: "password_reset_token" });
db.users.createIndex({ "created_at": 1 }, { name: "created_at" });
db.users.createIndex({ "role": 1 }, { name: "role_index" });
db.users.createIndex({ "is_active": 1 }, { name: "is_active_index" });

// Create sessions collection for JWT blacklisting (future use)
db.createCollection('token_blacklist');
db.token_blacklist.createIndex({ "token": 1 }, { unique: true, name: "token_unique" });
db.token_blacklist.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0, name: "expires_at_ttl" });

// Create audit logs collection
db.createCollection('audit_logs');
db.audit_logs.createIndex({ "user_id": 1 }, { name: "user_id_index" });
db.audit_logs.createIndex({ "action": 1 }, { name: "action_index" });
db.audit_logs.createIndex({ "timestamp": 1 }, { name: "timestamp_index" });
db.audit_logs.createIndex({ "ip_address": 1 }, { name: "ip_address_index" });

print('=== MongoDB initialization completed ===');
print('- Created auth_service database');
print('- Created application user: auth_app_user');
print('- Created users collection with indexes');
print('- Created token_blacklist collection');  
print('- Created audit_logs collection');
print('=== Ready for authentication service ===');