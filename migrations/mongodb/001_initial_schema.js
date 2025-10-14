// MongoDB Initial Schema Migration
// Creates the core users collection with comprehensive authentication features

// Create users collection
db.createCollection("users", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["user_id", "email", "password_hash", "first_name", "last_name", "role", "is_active", "email_verified", "created_at", "updated_at"],
            properties: {
                user_id: {
                    bsonType: "string",
                    description: "Unique user identifier"
                },
                email: {
                    bsonType: "string",
                    pattern: "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
                    description: "Valid email address"
                },
                password_hash: {
                    bsonType: "string",
                    description: "Hashed password"
                },
                first_name: {
                    bsonType: "string",
                    description: "User's first name"
                },
                last_name: {
                    bsonType: "string",
                    description: "User's last name"  
                },
                role: {
                    bsonType: "string",
                    enum: ["user", "admin", "moderator", "guest"],
                    description: "User role"
                },
                is_active: {
                    bsonType: "bool",
                    description: "Whether user account is active"
                },
                email_verified: {
                    bsonType: "bool", 
                    description: "Whether email is verified"
                },
                email_verification_token: {
                    bsonType: ["string", "null"],
                    description: "Email verification token"
                },
                email_verification_expires: {
                    bsonType: ["date", "null"],
                    description: "Email verification expiry"
                },
                password_reset_token: {
                    bsonType: ["string", "null"],
                    description: "Password reset token"
                },
                password_reset_expires: {
                    bsonType: ["date", "null"],
                    description: "Password reset expiry"
                },
                last_login: {
                    bsonType: ["date", "null"],
                    description: "Last login timestamp"
                },
                login_attempts: {
                    bsonType: "int",
                    minimum: 0,
                    maximum: 100,
                    description: "Failed login attempts"
                },
                locked_until: {
                    bsonType: ["date", "null"],
                    description: "Account lock expiry"
                },
                created_at: {
                    bsonType: "date",
                    description: "Record creation timestamp"
                },
                updated_at: {
                    bsonType: "date", 
                    description: "Record update timestamp"
                },
                metadata: {
                    bsonType: ["object", "null"],
                    description: "Additional user metadata"
                }
            }
        }
    }
});

// Create indexes for performance
db.users.createIndex({ "user_id": 1 }, { unique: true });
db.users.createIndex({ "email": 1 }, { unique: true });
db.users.createIndex({ "email_verification_token": 1 });
db.users.createIndex({ "password_reset_token": 1 });
db.users.createIndex({ "created_at": 1 });
db.users.createIndex({ "last_login": 1 });
db.users.createIndex({ "role": 1 });
db.users.createIndex({ "is_active": 1 });
db.users.createIndex({ "locked_until": 1 });

// Composite indexes for common query patterns
db.users.createIndex({ "email": 1, "is_active": 1 });
db.users.createIndex({ "role": 1, "is_active": 1 });
db.users.createIndex({ "email_verification_token": 1, "email_verification_expires": 1 });
db.users.createIndex({ "password_reset_token": 1, "password_reset_expires": 1 });

print("MongoDB users collection and indexes created successfully");

// DOWN
db.users.drop();
print("MongoDB users collection dropped");