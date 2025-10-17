// MongoDB initialization script for development
// This script creates the auth_service database and collections

// Switch to the auth_service database
db = db.getSiblingDB('auth_service');

// Create collections with initial indexes
db.createCollection('users');
db.createCollection('tokens');
db.createCollection('sessions');

// Create indexes for better performance
db.users.createIndex({ "email": 1 }, { unique: true });
db.users.createIndex({ "user_id": 1 }, { unique: true });
db.tokens.createIndex({ "jti": 1 }, { unique: true });
db.tokens.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 });
db.sessions.createIndex({ "session_id": 1 }, { unique: true });
db.sessions.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 });

print('Auth service database initialized successfully!');