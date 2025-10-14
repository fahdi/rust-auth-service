-- MySQL Initial Schema Migration
-- Creates the core users table with comprehensive authentication features

-- Users table with comprehensive authentication features
CREATE TABLE users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(36) UNIQUE NOT NULL DEFAULT (UUID()),
    email VARCHAR(320) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role ENUM('user', 'admin', 'moderator', 'guest') NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    email_verification_token VARCHAR(255) NULL,
    email_verification_expires TIMESTAMP NULL,
    password_reset_token VARCHAR(255) NULL,
    password_reset_expires TIMESTAMP NULL,
    last_login TIMESTAMP NULL,
    login_attempts INT UNSIGNED NOT NULL DEFAULT 0,
    locked_until TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    metadata JSON NOT NULL DEFAULT '{}',
    
    -- Constraints
    CONSTRAINT chk_users_email CHECK (email REGEXP '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT chk_users_login_attempts CHECK (login_attempts <= 100)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_user_id ON users(user_id);
CREATE INDEX idx_users_email_verification_token ON users(email_verification_token);
CREATE INDEX idx_users_password_reset_token ON users(password_reset_token);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_last_login ON users(last_login);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_active ON users(is_active);
CREATE INDEX idx_users_locked ON users(locked_until);

-- Composite indexes for common query patterns
CREATE INDEX idx_users_email_active ON users(email, is_active);
CREATE INDEX idx_users_role_active ON users(role, is_active);
CREATE INDEX idx_users_verification_token_expires ON users(email_verification_token, email_verification_expires);
CREATE INDEX idx_users_reset_token_expires ON users(password_reset_token, password_reset_expires);

-- Function to cleanup expired tokens (MySQL 8.0+)
DELIMITER //
CREATE EVENT IF NOT EXISTS cleanup_expired_tokens
ON SCHEDULE EVERY 6 HOUR
STARTS CURRENT_TIMESTAMP
DO
BEGIN
    -- Cleanup expired email verification tokens
    UPDATE users 
    SET 
        email_verification_token = NULL,
        email_verification_expires = NULL
    WHERE email_verification_expires IS NOT NULL 
    AND email_verification_expires < NOW();
    
    -- Cleanup expired password reset tokens
    UPDATE users 
    SET 
        password_reset_token = NULL,
        password_reset_expires = NULL
    WHERE password_reset_expires IS NOT NULL 
    AND password_reset_expires < NOW();
    
    -- Unlock accounts with expired lockouts
    UPDATE users 
    SET locked_until = NULL
    WHERE locked_until IS NOT NULL 
    AND locked_until < NOW();
END//
DELIMITER ;

-- Enable the event scheduler (requires SUPER privilege)
-- SET GLOBAL event_scheduler = ON;

-- DOWN
-- Drop all objects created by this migration in reverse order
DROP EVENT IF EXISTS cleanup_expired_tokens;
DROP INDEX IF EXISTS idx_users_reset_token_expires ON users;
DROP INDEX IF EXISTS idx_users_verification_token_expires ON users;
DROP INDEX IF EXISTS idx_users_role_active ON users;
DROP INDEX IF EXISTS idx_users_email_active ON users;
DROP INDEX IF EXISTS idx_users_locked ON users;
DROP INDEX IF EXISTS idx_users_active ON users;
DROP INDEX IF EXISTS idx_users_role ON users;
DROP INDEX IF EXISTS idx_users_last_login ON users;
DROP INDEX IF EXISTS idx_users_created_at ON users;
DROP INDEX IF EXISTS idx_users_password_reset_token ON users;
DROP INDEX IF EXISTS idx_users_email_verification_token ON users;
DROP INDEX IF EXISTS idx_users_user_id ON users;
DROP INDEX IF EXISTS idx_users_email ON users;
DROP TABLE IF EXISTS users;